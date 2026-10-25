"""M3: plan contract + reproduction execution on a fake session."""
from __future__ import annotations

import json
import socket
import sys
import types
import threading
from pathlib import Path

import pytest

if sys.platform.startswith("win"):
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *args, **kwargs: None
    _fcntl.LOCK_EX = 2
    _fcntl.LOCK_NB = 4
    sys.modules.setdefault("fcntl", _fcntl)

from repair_tool.config import RepairError
from repair_tool.firmware.plan import plan_prompt, validate_plan
from repair_tool.firmware.rehost import SessionControl
from repair_tool.firmware.reproduce import execute_plan, reproduce_and_report


# --------------------------------------------------------------- plan contract

def test_plan_accepts_valid_declarative_plan():
    plan = {"analysis": "long static path overflows a fixed buffer",
            "requests": [
                {"id": "control", "method": "GET", "path": "/small.gif", "expect": "response"},
                {"id": "trigger", "method": "GET", "path": "/" + "A" * 205 + ".gif",
                 "expect": "fatal_exit"}],
            "confirmations": ["trigger"]}
    validated = validate_plan(plan)
    assert validated["confirmations"] == ["trigger"]


def test_plan_rejects_unknown_fields_and_bad_ids():
    for bad in (
            {"analysis": "x", "requests": [{"id": "a", "path": "/"}],
             "confirmations": ["a"], "extra": 1},
            {"analysis": "x", "requests": [{"id": "BAD ID", "path": "/"}],
             "confirmations": ["BAD ID"]},
            {"analysis": "x", "requests": [{"id": "a", "path": "/"}],
             "confirmations": ["missing"]},
            {"analysis": "x", "requests": [{"id": "a", "path": "/x y"}],
             "confirmations": ["a"]},
            {"analysis": "", "requests": [], "confirmations": []},
    ):
        with pytest.raises(RepairError):
            validate_plan(bad)


def test_plan_confirmations_must_reference_fatal_exit_requests():
    plan = {"analysis": "control cannot be a crash confirmation",
            "requests": [
                {"id": "control", "path": "/", "expect": "response"},
                {"id": "trigger", "path": "/fault", "expect": "fatal_exit"}],
            "confirmations": ["control"]}
    with pytest.raises(RepairError, match="fatal_exit"):
        validate_plan(plan)


def test_plan_prompt_contains_poc_and_channel_only():
    payload = plan_prompt("print('x')", "note")
    assert payload["poc_source"] == "print('x')"
    assert "declarative HTTP requests" in payload["instruction"]
    assert '"marker": "/absolute/path"' in payload["instruction"]
    assert "never marker_path" in payload["instruction"]
    assert "The list is named requests, never steps" in payload["instruction"]
    assert "A POST body is named form, never fields" in payload["instruction"]
    assert "that plan is authoritative" in payload["instruction"]
    assert "preserving every step" in payload["instruction"]
    assert "accept_timeout=true" in payload["instruction"]
    assert "stable_identity=true" in payload["instruction"]
    assert "same prefix and suffix" in payload["instruction"]
    assert "code" not in json.dumps(payload).lower() or "Only output JSON" in payload["instruction"]


# --------------------------------------------------------------- reproduction

class PlanFakeAdapter:
    """Crashes (SIGSEGV record) on /fault paths; serves / normally."""

    def __init__(self, directory: Path):
        import hashlib
        self.dir = directory
        self.dir.mkdir(parents=True)
        (self.dir / "target-exits.jsonl").write_text("")
        self.target_file = self.dir / "rootfs" / "sbin" / "httpd"
        self.target_file.parent.mkdir(parents=True)
        self.target_file.write_bytes(b"ELF")
        self.pid = 777
        self.stopped = threading.Event()
        self.sockets = []
        self.threads = []
        for name in ("admin.sock", "http.sock"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(self.dir / name))
            sock.listen(8)
            sock.settimeout(0.1)
            self.sockets.append(sock)
            thread = threading.Thread(target=self._serve, args=(sock, name), daemon=True)
            thread.start()
            self.threads.append(thread)

    def _record(self, signal_name="SIGSEGV", intentional=False):
        import hashlib
        digest = hashlib.sha256(self.target_file.read_bytes()).hexdigest()
        with (self.dir / "target-exits.jsonl").open("a") as stream:
            stream.write(json.dumps({"pid": self.pid, "sha256": digest,
                                     "signal_name": signal_name,
                                     "intentional": intentional}) + "\n")

    def _serve(self, sock, name):
        import hashlib
        import selectors
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        while not self.stopped.is_set():
            for _ in selector.select(timeout=0.1):
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                with conn:
                    conn.settimeout(3)
                    data = conn.recv(65536)
                    if name == "admin.sock":
                        request = json.loads(data)
                        digest = hashlib.sha256(self.target_file.read_bytes()).hexdigest()
                        if request.get("command") == "status":
                            reply = {"ok": True, "target": {"pid": self.pid, "sha256": digest}}
                        else:
                            reply = {"ok": False, "error": "unsupported"}
                        conn.sendall(json.dumps(reply).encode() + b"\n")
                    else:
                        if data.startswith(b"GET /fault"):
                            self._record()
                            conn.sendall(b"HTTP/1.0 404 Not Found\r\n\r\n")
                        else:
                            conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nhome")

    def close(self):
        self.stopped.set()
        for thread in self.threads:
            thread.join(timeout=1)
        for sock in self.sockets:
            sock.close()


@pytest.fixture
def plan_session(tmp_path):
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("this host has no Unix socket support")
    adapter = PlanFakeAdapter(tmp_path / "session")
    yield tmp_path / "session"
    adapter.close()


GOOD_PLAN = {"analysis": "overflow",
             "requests": [
                 {"id": "control", "path": "/index.htm", "expect": "response"},
                 {"id": "trigger", "path": "/fault", "expect": "fatal_exit"}],
             "confirmations": ["trigger"]}


def test_execute_plan_confirms_fault(plan_session, tmp_path):
    control = SessionControl(plan_session)
    result = execute_plan(control, validate_plan(GOOD_PLAN),
                          stage_dir=tmp_path / "stage")
    assert result["confirmed"] is True
    assert result["confirmed_ids"] == ["trigger"]
    assert (tmp_path / "stage" / "reproduction.json").exists()


def test_reproduce_reports_summary(plan_session, tmp_path):
    control = SessionControl(plan_session)
    reproduction = reproduce_and_report(control, validate_plan(GOOD_PLAN),
                                        tmp_path / "stage")
    assert reproduction["confirmed"]
    summary = json.loads((tmp_path / "stage" / "fault-summary.json").read_text())
    assert summary["request"]["path"] == "/fault"
    assert summary["signal"] == "SIGSEGV"


def test_execute_plan_fails_when_trigger_does_not_fault(plan_session, tmp_path):
    control = SessionControl(plan_session)
    plan = {"analysis": "x",
            "requests": [{"id": "t", "path": "/safe", "expect": "fatal_exit"}],
            "confirmations": ["t"]}
    with pytest.raises(RepairError, match="did not exit|reproduction"):
        reproduce_and_report(control, validate_plan(plan), tmp_path / "stage")


def test_execute_plan_fails_when_control_kills_service(plan_session, tmp_path):
    control = SessionControl(plan_session)
    plan = {"analysis": "x",
            "requests": [
                {"id": "c", "path": "/fault", "expect": "response"},
                {"id": "t", "path": "/fault", "expect": "fatal_exit"}],
            "confirmations": ["t"]}
    result = execute_plan(control, validate_plan(plan), stage_dir=tmp_path / "stage")
    assert result["confirmed"] is False
    assert result["control_failures"] == ["c"]
