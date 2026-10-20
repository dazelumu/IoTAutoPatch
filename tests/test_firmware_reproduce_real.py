"""M3 real-session acceptance: declarative plan execution on real DIR-825.

The plan mirrors the documented reproduction matrix (see
experiments/dir825/evidence/cve-2025-6291-reproduction.md): short .gif paths
are controls; a >=205-byte path triggers the fault. Exit attribution must
bind pid/sha256 of the registered instance.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware.plan import validate_plan
from repair_tool.firmware.rehost import SessionControl, SessionSupervisor
from repair_tool.firmware.reproduce import reproduce_and_report

ROOTFS = Path("/home/lumu/firmware-lab/dir825-b-2.03/work/rootfs-full")


@pytest.mark.slow
@pytest.mark.skipif(not ROOTFS.is_dir(), reason="DIR-825 lab rootfs not present")
def test_real_plan_reproduction_and_attribution(tmp_path):
    plan = validate_plan({
        "analysis": "long static .gif path overflows a fixed buffer",
        "requests": [
            {"id": "control_short", "method": "GET", "path": "/AAAA(30).gif",
             "expect": "response"},
            {"id": "control_home", "method": "GET", "path": "/", "expect": "response"},
            {"id": "trigger", "method": "GET", "path": "/" + "A" * 205 + ".gif",
             "expect": "fatal_exit"},
        ],
        "confirmations": ["trigger"]})
    session = tmp_path / "session"
    with SessionSupervisor(ROOTFS, session):
        control = SessionControl(session)
        try:
            reproduction = reproduce_and_report(control, plan,
                                                tmp_path / "stage",
                                                exit_timeout=15.0)
        finally:
            try:
                control.current_target()
            except RepairError:
                control.restart()
        assert reproduction["confirmed"]
        summary = (tmp_path / "stage" / "fault-summary.json").read_text()
        assert "SIGSEGV" in summary or "SIGBUS" in summary
        # Service identity is unchanged across the fault (same binary bytes).
        assert control.current_target()["sha256"] == reproduction["target_start"]["sha256"]
        assert control.current_target()["pid"] > 0


def test_length_differential_measures_first_crashing_run(tmp_path):
    """Binary length probes bound the threshold without weakening evidence."""
    class DifferentialControl:
        def __init__(self):
            self.pid = 10
            self.sha256 = "baseline-sha"
            self.exits = []

        def current_target(self):
            return {"pid": self.pid, "sha256": self.sha256}

        def target_exits(self):
            return list(self.exits)

        def deliver(self, request, timeout=6.0):
            path = request["path"]
            if len(path) > 105:
                self.exits.append({
                    "pid": self.pid,
                    "sha256": self.sha256,
                    "signal_name": "SIGSEGV",
                    "intentional": False,
                })
                return {"sent": True, "receive": "eof", "bytes": 0,
                        "response_hex": ""}
            return {"sent": True, "receive": "eof", "bytes": 37,
                    "response_hex": b"HTTP/1.0 200 OK\r\n\r\nbody".hex()}

        def restart(self, transaction=None):
            self.pid += 1
            return {"ok": True}

    plan = validate_plan({
        "analysis": "same-shape short control and long trigger",
        "requests": [
            {"id": "safe", "method": "GET",
             "path": "/" + "A" * 16 + ".gif", "expect": "response"},
            {"id": "trigger", "method": "GET",
             "path": "/" + "A" * 205 + ".gif", "expect": "fatal_exit"},
        ],
        "confirmations": ["trigger"]})
    control = DifferentialControl()
    reproduction = reproduce_and_report(
        control, plan, tmp_path / "stage", exit_timeout=0.01,
        transaction="tx", length_differential=True, length_probe_limit=8)

    differential = reproduction["length_differential"]
    assert differential["status"] == "first_crash_bounded"
    assert differential["safe_run_length"] == 16
    assert differential["first_crash_run_length"] == 101
    assert differential["first_crash_path_length"] == 106
    assert differential["probe_count"] == 8
    assert all(probe["verdict"] in {"safe", "fatal"}
               for probe in differential["probes"])
    summary = json.loads(
        (tmp_path / "stage" / "fault-summary.json").read_text(encoding="utf-8"))
    assert summary["length_differential"] == differential
    assert (tmp_path / "stage" / "length-differential.json").is_file()
    assert control.current_target()["sha256"] == "baseline-sha"


def test_length_differential_records_inconclusive_probe(tmp_path):
    """An unattributable probe remains part of the diagnostic evidence."""
    class DifferentialControl:
        def __init__(self):
            self.pid = 20
            self.sha256 = "baseline-sha"
            self.exits = []

        def current_target(self):
            return {"pid": self.pid, "sha256": self.sha256}

        def target_exits(self):
            return list(self.exits)

        def deliver(self, request, timeout=6.0):
            run_length = len(request["path"]) - len("/.gif")
            if run_length == 101:
                return {"sent": True, "receive": "timeout", "bytes": 0,
                        "response_hex": ""}
            if run_length > 100:
                self.exits.append({
                    "pid": self.pid,
                    "sha256": self.sha256,
                    "signal_name": "SIGSEGV",
                    "intentional": False,
                })
                return {"sent": True, "receive": "eof", "bytes": 0,
                        "response_hex": ""}
            return {"sent": True, "receive": "eof", "bytes": 37,
                    "response_hex": b"HTTP/1.0 200 OK\r\n\r\nbody".hex()}

        def restart(self, transaction=None):
            self.pid += 1
            return {"ok": True}

    plan = validate_plan({
        "analysis": "same-shape short control and long trigger",
        "requests": [
            {"id": "safe", "method": "GET",
             "path": "/" + "A" * 16 + ".gif", "expect": "response"},
            {"id": "trigger", "method": "GET",
             "path": "/" + "A" * 205 + ".gif", "expect": "fatal_exit"},
        ],
        "confirmations": ["trigger"]})
    control = DifferentialControl()
    reproduction = reproduce_and_report(
        control, plan, tmp_path / "stage", exit_timeout=0.01,
        transaction="tx", length_differential=True, length_probe_limit=8)

    differential = reproduction["length_differential"]
    assert differential["status"] == "inconclusive"
    assert differential["lower_bound_run_length"] == 98
    assert differential["upper_bound_run_length"] == 104
    assert differential["probe_count"] == 6
    assert differential["probes"][-1] == {
        "run_length": 101,
        "path_length": 106,
        "request": {"method": "GET", "path": "/" + "A" * 101 + ".gif"},
        "verdict": "inconclusive",
    }
    progress = json.loads(
        (tmp_path / "stage" / "length-differential-progress.json").read_text(
            encoding="utf-8"))
    assert progress["probes"] == differential["probes"]
