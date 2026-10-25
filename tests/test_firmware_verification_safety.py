from __future__ import annotations

import json
import sys
import types
import time

import pytest

if sys.platform.startswith("win"):
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *args, **kwargs: None
    _fcntl.LOCK_EX = 2
    _fcntl.LOCK_NB = 4
    sys.modules.setdefault("fcntl", _fcntl)

from repair_tool.config import RepairError
from repair_tool.firmware.http import parse_response, response_complete
from repair_tool.firmware.rehost import FIRMWARE_DEADLINE_MESSAGE
from repair_tool.firmware.tests import _observe_exits, delivery_complete
from repair_tool.firmware.tests import run_one_test
from repair_tool.firmware.tests import validate_tests
from repair_tool.firmware.verify import (
    replay_plan, run_fixed_checks, verify_candidate)


HTTP_OK = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nhome"


class ObservationControl:
    def __init__(self, *, receive: str = "eof", delayed_exit: float | None = None):
        self.receive = receive
        self.delayed_exit = delayed_exit
        self.delivered_at: float | None = None
        self.target = {"pid": 41, "sha256": "a" * 64,
                       "program": "/sbin/httpd"}

    def current_target(self):
        return dict(self.target)

    def target_sha(self):
        return self.target["sha256"]

    def target_exits(self):
        if (self.delayed_exit is not None and self.delivered_at is not None
                and time.monotonic() - self.delivered_at >= self.delayed_exit):
            return [{"pid": self.target["pid"],
                     "sha256": self.target["sha256"],
                     "signal_name": "SIGSEGV", "intentional": False}]
        return []

    def deliver(self, request, timeout=6.0):
        self.delivered_at = time.monotonic()
        return {"receive": self.receive, "response_hex": HTTP_OK.hex(),
                "bytes": 20, "sha256": "b" * 64}

    def restart(self, transaction=None):
        self.delayed_exit = None
        self.delivered_at = None
        self.target["pid"] += 1
        return {"target": dict(self.target)}


class ImmediateCrashControl(ObservationControl):
    def __init__(self):
        super().__init__(delayed_exit=0.0)
        self.identity_calls = 0

    def current_target(self):
        self.identity_calls += 1
        if self.delivered_at is not None:
            raise RepairError("infrastructure_failed", "no live target")
        return dict(self.target)

    def target_exits(self):
        if self.delivered_at is None:
            return []
        return [{"pid": self.target["pid"],
                 "sha256": self.target["sha256"],
                 "signal_name": "SIGSEGV", "intentional": False}]


PASS_TEST = {
    "id": "survival", "kind": "regression", "expect": "pass",
    "request": {"method": "GET", "path": "/"},
    "response": {"statuses": [200], "contains": "home"},
}


def test_candidate_waits_for_delayed_exit():
    control = ObservationControl(delayed_exit=0.03)
    result = run_one_test(control, PASS_TEST, phase="candidate",
                          exit_timeout=0.12)
    assert result["passed"] is False
    assert result["reason"] == "service exited while survival was expected"
    assert result["exit_record"]["signal_name"] == "SIGSEGV"


def test_http_prefix_followed_by_timeout_is_not_a_response(tmp_path):
    control = ObservationControl(receive="TimeoutError")
    result = run_one_test(control, PASS_TEST, phase="candidate",
                          exit_timeout=0)
    assert result["passed"] is False
    assert result["reason"] == "HTTP response did not complete"

    checks = [{"request": {"path": "/"}, "statuses": [200],
               "contains": "home"}]
    with pytest.raises(RepairError, match="Fixed functional checks failed"):
        run_fixed_checks(control, checks, tmp_path / "checks", exit_timeout=0)

    plan = {"requests": [{"id": "control", "path": "/",
                           "expect": "response"}]}
    with pytest.raises(RepairError, match="incomplete_response"):
        replay_plan(control, plan, tmp_path / "replay", exit_timeout=0)


def test_contains_matches_decoded_body_not_headers(tmp_path):
    class HeaderOnlyControl(ObservationControl):
        def deliver(self, request, timeout=6.0):
            self.delivered_at = time.monotonic()
            response = (b"HTTP/1.1 200 OK\r\nX-Page: home\r\n"
                        b"Content-Length: 0\r\n\r\n")
            return {"receive": "eof", "response_hex": response.hex(),
                    "bytes": len(response), "sha256": "b" * 64}

    control = HeaderOnlyControl()
    result = run_one_test(control, PASS_TEST, phase="candidate",
                          exit_timeout=0)
    assert result["passed"] is False
    assert result["reason"] == "HTTP response assertion failed"
    with pytest.raises(RepairError, match="Fixed functional checks failed"):
        run_fixed_checks(
            control,
            [{"request": {"path": "/"}, "statuses": [200],
              "contains": "home"}],
            tmp_path / "header-only", exit_timeout=0)


def test_chunked_body_is_decoded_for_content_assertions():
    response = (b"HTTP/1.1 100 Continue\r\n\r\n"
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"2\r\nho\r\n2\r\nme\r\n0\r\n\r\n")
    parsed = parse_response(response)
    assert parsed is not None
    assert parsed.status == 200
    assert parsed.body == b"home"
    assert response_complete(response, "GET", "eof") is True


def test_timeout_is_complete_only_for_self_delimiting_http_framing():
    complete = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    truncated = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbod"
    close_delimited = b"HTTP/1.0 200 OK\r\n\r\nbody"
    header_only = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"

    assert response_complete(complete, "GET", "timeout") is True
    assert response_complete(truncated, "GET", "timeout") is False
    assert response_complete(close_delimited, "GET", "timeout") is False
    assert response_complete(b"HTTP/1.0 200 OK\r\n\r\n", "HEAD", "timeout") is True
    assert response_complete(header_only, "GET", "eof") is True
    assert delivery_complete({"receive": "timeout", "http_complete": True}) is True
    assert delivery_complete({"receive": "timeout", "http_complete": False}) is False


def test_fixed_check_crash_stays_functional_and_stops(tmp_path):
    control = ImmediateCrashControl()
    checks = [
        {"request": {"path": "/one"}, "statuses": [200]},
        {"request": {"path": "/two"}, "statuses": [200]},
    ]
    with pytest.raises(RepairError) as caught:
        run_fixed_checks(control, checks, tmp_path / "checks", exit_timeout=0)

    assert caught.value.status == "functional_failed"
    assert control.identity_calls == 1
    saved = json.loads((tmp_path / "checks" / "fixed-checks.json").read_text(
        encoding="utf-8"))
    assert len(saved) == 1
    assert saved[0]["exits"]


def test_candidate_verification_isolates_phases_with_same_bytes(
        tmp_path, monkeypatch):
    class PhaseControl(ObservationControl):
        def __init__(self):
            super().__init__()
            self.restarts = 0

        def restart(self, transaction=None):
            self.restarts += 1
            self.target["pid"] += 1
            return {"target": dict(self.target)}

    control = PhaseControl()
    order = []

    monkeypatch.setattr(
        "repair_tool.firmware.verify.run_fixed_checks",
        lambda *_args, **_kwargs: order.append("fixed") or {"passed": True})
    monkeypatch.setattr(
        "repair_tool.firmware.verify.replay_plan",
        lambda *_args, **_kwargs: order.append("replay") or
        {"stable_identity": True})
    monkeypatch.setattr(
        "repair_tool.firmware.verify.run_tests",
        lambda *_args, **_kwargs: order.append("tests") or [{"id": "t",
                                                              "passed": True}])

    result = verify_candidate(
        control,
        checks=[{"request": {"path": "/"}, "statuses": [200]}],
        plan={"requests": [{"id": "trigger", "path": "/trigger"}]},
        tests=[{"id": "t"}], logs=tmp_path, exit_timeout=0,
        transaction="tx-isolate")

    assert order == ["fixed", "replay", "tests"]
    assert control.restarts == 2
    assert [item["before"]["pid"] for item in result["phase_restarts"]] == [41, 42]
    assert [item["after"]["pid"] for item in result["phase_restarts"]] == [42, 43]
    assert all(item["same_sha256"] for item in result["phase_restarts"])
    saved = json.loads((tmp_path / "phase-restarts.json").read_text(
        encoding="utf-8"))
    assert [item["phase"] for item in saved] == [
        "fixed-to-replay", "replay-to-tests"]


def test_phase_restart_evidence_persists_when_replay_fails(
        tmp_path, monkeypatch):
    class PhaseControl(ObservationControl):
        def restart(self, transaction=None):
            self.target["pid"] += 1
            return {"target": dict(self.target)}

    monkeypatch.setattr(
        "repair_tool.firmware.verify.run_fixed_checks",
        lambda *_args, **_kwargs: {"passed": True})

    def replay_plan(*_args, **_kwargs):
        raise RepairError("verification_failed", "home: incomplete_response")

    monkeypatch.setattr(
        "repair_tool.firmware.verify.replay_plan", replay_plan)

    with pytest.raises(RepairError, match="home: incomplete_response"):
        verify_candidate(
            PhaseControl(), checks=[], plan={"requests": []}, tests=[],
            logs=tmp_path, exit_timeout=0)

    saved = json.loads((tmp_path / "phase-restarts.json").read_text(
        encoding="utf-8"))
    assert len(saved) == 1
    assert saved[0]["phase"] == "fixed-to-replay"
    assert saved[0]["before"]["pid"] == 41
    assert saved[0]["after"]["pid"] == 42
    assert saved[0]["same_sha256"] is True


def test_candidate_phase_restart_rejects_changed_bytes(
        tmp_path, monkeypatch):
    class SwappedAfterRestartControl(ObservationControl):
        def restart(self, transaction=None):
            self.target["sha256"] = "c" * 64
            return {"target": dict(self.target)}

    monkeypatch.setattr(
        "repair_tool.firmware.verify.run_fixed_checks",
        lambda *_args, **_kwargs: {"passed": True})
    replay_called = False

    def replay_plan(*_args, **_kwargs):
        nonlocal replay_called
        replay_called = True
        return {"stable_identity": True}

    monkeypatch.setattr(
        "repair_tool.firmware.verify.replay_plan", replay_plan)

    with pytest.raises(RepairError, match="fixed-to-replay restart"):
        verify_candidate(
            SwappedAfterRestartControl(),
            checks=[], plan={"requests": []}, tests=[], logs=tmp_path,
            exit_timeout=0)

    assert replay_called is False


def test_marker_pre_trigger_incomplete_is_not_same_fault(tmp_path,
                                                         monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/"},
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }

    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: {
            "passed": False,
            "stable_identity": True,
            "results": [
                {"id": "home", "expect": "response", "status": "failed",
                 "reason": "incomplete_response"},
            ],
        })
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda *_args, **_kwargs: False)

    with pytest.raises(RepairError) as caught:
        replay_plan(ObservationControl(), plan, tmp_path / "marker-replay")

    assert caught.value.status == "verification_failed"
    assert caught.value.verification_class == "pre_trigger_transport_failure"


def test_marker_trigger_failure_is_not_pre_trigger(tmp_path, monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/"},
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }
    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: {
            "passed": False,
            "stable_identity": True,
            "results": [
                {"id": "home", "expect": "response", "status": "ok"},
                {"id": "trigger", "expect": "marker_created",
                 "status": "failed", "reason": "incomplete_response"},
            ],
        })
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda *_args, **_kwargs: False)

    with pytest.raises(RepairError) as caught:
        replay_plan(ObservationControl(), plan,
                    tmp_path / "trigger-classification")

    assert caught.value.status == "verification_failed"
    assert caught.value.verification_class == "trigger_transport_failure"


def test_transient_marker_transport_failure_gets_one_candidate_retry(
        tmp_path, monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/"},
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }
    control = ObservationControl()
    outcomes = [
        {"passed": False, "stable_identity": True, "results": [
            {"id": "home", "status": "failed",
             "reason": "incomplete_response"},
        ]},
        {"passed": True, "stable_identity": True, "results": [
            {"id": "home", "status": "ok"},
            {"id": "trigger", "status": "ok", "marker_after": {
                "exists": False}},
        ]},
    ]
    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: outcomes.pop(0))
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda execution, **_kwargs: execution["passed"])

    replay = replay_plan(control, plan, tmp_path / "transient-retry")

    assert replay["transport_retry"]["attempted"] is True
    assert replay["transport_retry"]["restart"]["same_sha256"] is True
    restarts = json.loads(
        (tmp_path / "transient-retry" / "phase-restarts.json").read_text())
    assert restarts[0]["phase"] == "replay-transport-retry"


def test_transport_retry_failure_class_uses_first_observed_failure(
        tmp_path, monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/"},
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }
    outcomes = [
        {"passed": False, "stable_identity": True, "results": [
            {"id": "home", "status": "failed",
             "reason": "incomplete_response"},
        ]},
        {"passed": False, "stable_identity": True, "results": [
            {"id": "home", "status": "ok"},
            {"id": "trigger", "status": "failed",
             "reason": "incomplete_response"},
        ]},
    ]
    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: outcomes.pop(0))
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda *_args, **_kwargs: False)

    with pytest.raises(RepairError) as caught:
        replay_plan(ObservationControl(), plan,
                    tmp_path / "retry-first-failure")

    assert caught.value.verification_class == "pre_trigger_transport_failure"


def test_persistent_marker_transport_failure_retries_only_once(
        tmp_path, monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/"},
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }
    control = ObservationControl()
    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: {
            "passed": False, "stable_identity": True, "results": [
                {"id": "home", "status": "failed",
                 "reason": "incomplete_response"},
            ],
        })
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda *_args, **_kwargs: False)

    with pytest.raises(RepairError) as caught:
        replay_plan(control, plan, tmp_path / "persistent-retry")

    assert caught.value.verification_class == "pre_trigger_transport_failure"
    saved = json.loads(
        (tmp_path / "persistent-retry" / "replay.json").read_text())
    assert saved["transport_retry"]["attempted"] is True
    assert control.target["pid"] == 42


def test_marker_still_created_is_not_transport_retried(
        tmp_path, monkeypatch):
    plan = {
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "trigger", "method": "POST", "path": "/trigger",
             "expect": "marker_created", "form": {"q": "x"}},
        ],
    }
    control = ObservationControl()
    control.restart = lambda transaction=None: pytest.fail(
        "marker still created is decisive and must not restart/retry")
    monkeypatch.setattr(
        "repair_tool.firmware.verify.execute_steps",
        lambda *_args, **_kwargs: {
            "passed": False, "stable_identity": True, "results": [
                {"id": "trigger", "status": "failed",
                 "reason": "unexpected_marker"},
            ],
        })
    monkeypatch.setattr(
        "repair_tool.firmware.verify.marker_scenario_passed",
        lambda *_args, **_kwargs: False)

    with pytest.raises(RepairError) as caught:
        replay_plan(control, plan, tmp_path / "marker-still-created")

    assert caught.value.verification_class == "marker_still_created"


def test_framed_multi_step_path_cannot_be_collapsed_to_one_request():
    required = [{
        "steps": [{
            "id": "lan", "method": "GET", "path": "/lan.asp",
            "statuses": [200], "contains": "admin", "accept_timeout": True,
        }],
    }]
    data = {
        "tests": [
            {"id": "collapsed", "kind": "independent", "expect": "pass",
             "basis": "standalone LAN page", "request": {
                 "method": "GET", "path": "/lan.asp"},
             "response": {"statuses": [200]}},
            {"id": "trigger", "kind": "vulnerability", "expect": "marker",
             "basis": "confirmed trigger", "marker": "/Q", "steps": [{
                 "id": "lan", "method": "GET", "path": "/lan.asp",
                 "statuses": [200], "contains": "admin",
                 "accept_timeout": True, "expect": "marker_created"}],
             "protocol": "http-ascii-auth-form-multi-step-port80"},
            {"id": "home", "kind": "regression", "expect": "pass",
             "basis": "home page", "request": {"method": "GET", "path": "/"},
             "response": {"statuses": [200]}},
        ]
    }

    with pytest.raises(RepairError, match="complete step scenario"):
        validate_tests(data, required_trigger_scenarios=required)


def test_replay_crash_does_not_rewrite_firmware_deadline(tmp_path):
    control = ImmediateCrashControl()

    def restart(transaction=None):
        raise RepairError("infrastructure_failed", FIRMWARE_DEADLINE_MESSAGE)

    control.restart = restart
    plan = {"requests": [
        {"id": "crash", "path": "/crash"},
        {"id": "later", "path": "/later"},
    ]}
    with pytest.raises(RepairError) as caught:
        replay_plan(control, plan, tmp_path / "replay", exit_timeout=0)

    assert caught.value.status == "infrastructure_failed"
    assert str(caught.value) == FIRMWARE_DEADLINE_MESSAGE


def test_exit_observation_reports_firmware_deadline():
    class EmptyControl:
        def target_exits(self):
            return []

    with pytest.raises(RepairError) as caught:
        _observe_exits(EmptyControl(), 0, timeout=1,
                       deadline=time.monotonic() - 1)

    assert caught.value.status == "infrastructure_failed"
    assert str(caught.value) == FIRMWARE_DEADLINE_MESSAGE
