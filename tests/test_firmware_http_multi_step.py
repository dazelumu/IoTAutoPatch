from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

if sys.platform.startswith("win"):
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *args, **kwargs: None
    _fcntl.LOCK_EX = 2
    _fcntl.LOCK_NB = 4
    sys.modules.setdefault("fcntl", _fcntl)

from repair_tool.config import RepairError
from repair_tool.firmware.http_multi_step import observe_marker, validate_marker


HTTP_PROTOCOL = "http-ascii-auth-form-multi-step-port80"


from repair_tool.firmware.plan import validate_plan  # noqa: E402
from repair_tool.firmware.reproduce import reproduce_and_report  # noqa: E402
from repair_tool.firmware.tests import run_one_test  # noqa: E402
from repair_tool.firmware.verify import replay_plan, run_fixed_checks  # noqa: E402


class MarkerControl:
    def __init__(self, session: Path, *, vulnerable: bool = True,
                 streaming_auth: bool = False):
        self.session = session
        self.vulnerable = vulnerable
        self.streaming_auth = streaming_auth
        self.rootfs = session / "rootfs"
        self.rootfs.mkdir(parents=True)
        self.target = {"pid": 931, "sha256": "a" * 64}
        self.requests: list[dict] = []
        self.timeouts: list[float] = []

    def current_target(self):
        return dict(self.target)

    def target_exits(self):
        return []

    def _response(self, body: bytes, cookie: str | None = None) -> dict:
        headers = ["HTTP/1.0 200 OK"]
        if cookie:
            headers.append(f"Set-Cookie: {cookie}")
        raw = ("\r\n".join(headers)
               + f"\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        return {"receive": "eof", "response_hex": raw.hex(),
                "bytes": 81, "sha256": "b" * 64,
                "http_complete": True, "protocol": HTTP_PROTOCOL}

    def deliver(self, request, timeout=6.0, *, protocol=None):
        assert protocol == HTTP_PROTOCOL
        self.requests.append(request)
        self.timeouts.append(timeout)
        path = request["path"]
        if path == "/":
            body = (b'<input type="hidden" name="html_response_page" value="index.asp">'
                    b'<input type="hidden" name="graph_id" value="7">'
                    b'<input type="hidden" name="alert_id" value="0">')
            return self._response(body, cookie="uid=0123; Path=/")
        if path == "/login.cgi":
            form = request["form"]
            assert form["html_response_page"] == "index.asp"
            assert form["graph_id"] == "7"
            assert form["alert_id"] == "0"
            assert request["cookies"] == {"uid": "0123"}
            return self._response(b"ok")
        if path == "/lan.asp":
            assert request["cookies"] == {"uid": "0123"}
            if self.streaming_auth:
                raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
                      b'login_who="admin"'
                return {"receive": "timeout", "response_hex": raw.hex(),
                        "bytes": len(raw), "sha256": "c" * 64,
                        "http_complete": False, "protocol": HTTP_PROTOCOL}
            return self._response(b'login_who="admin"')
        assert path == "/apc_client_pin.cgi"
        if self.vulnerable and request["form"]["wps_pin"] == "';>/Q ;#":
            (self.rootfs / "Q").write_bytes(b"")
        return self._response(b"saved")


def marker_plan() -> dict:
    return validate_plan({
        "analysis": "bounded WPS PIN reaches an OS command",
        "protocol": HTTP_PROTOCOL,
        "outcome": "command_injection_marker",
        "marker": "/Q",
        "requests": [
            {"id": "home", "method": "GET", "path": "/",
             "capture_cookies": True,
             "capture_fields": ["html_response_page", "graph_id", "alert_id"],
             "statuses": [200]},
            {"id": "login", "method": "POST", "path": "/login.cgi",
             "form": {
                 "login_name": "YWRtaW4=", "login_n": "YWRtaW4=",
                 "login_pass": "", "log_pass": "", "graph_code": "",
                 "login": "Log In",
                 "html_response_page": {"capture": "html_response_page"},
                 "graph_id": {"capture": "graph_id"},
                 "alert_id": {"capture": "alert_id"},
             }, "statuses": [200]},
            {"id": "auth", "method": "GET", "path": "/lan.asp",
             "contains": 'login_who="admin"', "expect": "response",
             "statuses": [200], "accept_timeout": True},
            {"id": "control", "method": "POST",
             "path": "/apc_client_pin.cgi",
             "form": {"wps_pin": "12345670"},
             "expect": "marker_absent", "statuses": [200]},
            {"id": "trigger", "method": "POST",
             "path": "/apc_client_pin.cgi",
             "form": {"wps_pin": "';>/Q ;#"},
             "expect": "marker_created", "statuses": [200]},
            {"id": "post_control", "method": "POST",
             "path": "/apc_client_pin.cgi",
             "form": {"wps_pin": "12345670"},
             "expect": "response", "statuses": [200]},
        ],
        "confirmations": ["trigger"],
    })


def test_marker_plan_reproduces_and_cleans_side_effect(tmp_path):
    control = MarkerControl(tmp_path / "session")
    reproduction = reproduce_and_report(
        control, marker_plan(), tmp_path / "reproduce", exit_timeout=0)

    assert reproduction["confirmed"] is True
    assert reproduction["confirmed_ids"] == ["trigger"]
    assert not (control.rootfs / "Q").exists()
    summary = json.loads((tmp_path / "reproduce" / "fault-summary.json").read_text())
    assert summary["outcome"] == "command_injection_marker"
    assert "cookies" not in summary["request"]
    assert all("cookies" not in item["request"]
               for item in reproduction["requests"])


def test_marker_scenario_uses_configured_request_timeout(tmp_path, monkeypatch):
    import repair_tool.firmware.tests as firmware_tests

    monkeypatch.setattr(firmware_tests, "_observe_exits",
                        lambda *args, **kwargs: [])
    control = MarkerControl(tmp_path / "session")
    reproduction = reproduce_and_report(
        control, marker_plan(), tmp_path / "reproduce", exit_timeout=12.5)

    assert reproduction["confirmed"] is True
    assert control.timeouts == [12.5] * len(control.requests)


def test_declared_timeout_is_accepted_only_with_required_content(tmp_path):
    streaming_control = MarkerControl(tmp_path / "session", streaming_auth=True)
    reproduction = reproduce_and_report(
        streaming_control, marker_plan(), tmp_path / "reproduce", exit_timeout=0)
    assert reproduction["confirmed"] is True

    plan = marker_plan()
    plan["requests"][2]["contains"] = "not-in-this-response"
    with pytest.raises(RepairError, match="control requests terminated"):
        reproduce_and_report(
            MarkerControl(tmp_path / "rejected", streaming_auth=True), plan,
            tmp_path / "rejected-reproduce", exit_timeout=0)


def test_marker_candidate_replay_requires_marker_absence(tmp_path):
    control = MarkerControl(tmp_path / "session", vulnerable=False)
    (control.rootfs / "Q").write_bytes(b"")
    replay = replay_plan(control, marker_plan(), tmp_path / "replay",
                         exit_timeout=0)

    assert replay["identity_confirmed"] is True
    assert replay["violations"] == []
    assert not (control.rootfs / "Q").exists()


def test_multi_step_fixed_check_completes_authenticated_scenario(tmp_path):
    control = MarkerControl(tmp_path / "session")
    steps = marker_plan()["requests"][:3]
    checks = [{"protocol": HTTP_PROTOCOL, "steps": steps,
               "statuses": [200], "contains": 'login_who="admin"'}]

    assert run_fixed_checks(control, checks, tmp_path / "checks",
                            exit_timeout=0)["passed"] is True


def test_generated_marker_test_differs_between_baseline_and_candidate(tmp_path):
    plan = marker_plan()
    test = {
        "id": "wps-marker", "kind": "vulnerability", "expect": "marker",
        "protocol": plan["protocol"], "steps": plan["requests"],
        "marker": plan["marker"],
        "response": {"statuses": [200], "contains": ""},
    }
    baseline = run_one_test(
        MarkerControl(tmp_path / "baseline"), test,
        phase="baseline", exit_timeout=0)
    candidate = run_one_test(
        MarkerControl(tmp_path / "candidate", vulnerable=False), test,
        phase="candidate", exit_timeout=0)

    assert baseline["passed"] is True
    assert candidate["passed"] is True


def test_cve_2024_intake_example_selects_form_protocol() -> None:
    from repair_tool.config import load_intake_config

    root = Path(__file__).resolve().parents[1]
    path = (root / "cases" / "dlink" / "dir825b-2.03" /
            "cve-2024-57595" / "config" / "intake.example.yaml")
    cfg = load_intake_config(path)

    assert cfg["firmware"]["protocol"] == HTTP_PROTOCOL
    assert cfg["firmware"]["checks"][0]["protocol"] == HTTP_PROTOCOL


def test_marker_path_safety_rejects_escape_and_non_files(tmp_path):
    with pytest.raises(RepairError):
        validate_marker("/../Q")
    with pytest.raises(RepairError):
        validate_marker("Q")

    session = tmp_path / "session"
    (session / "rootfs" / "dir").mkdir(parents=True)
    with pytest.raises(RepairError, match="not a symlink or directory"):
        observe_marker(session, "/dir")
