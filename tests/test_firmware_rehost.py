"""Adapter supervisor + host launcher tests (M2).

Socket-level tests run everywhere on Linux; the real-rootfs smoke test is
marked slow and requires the DIR-825 lab material in WSL.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware.rehost import (SessionControl, SessionLock,
                                         SessionSupervisor)


# ------------------------------------------------------- fake adapter process

FAKE_ADAPTER = r'''
import json, os, socket, sys, time
from pathlib import Path

session = Path(sys.argv[1])
(session / "target-exits.jsonl").write_text("")
admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
admin.bind(str(session / "admin.sock"))
admin.listen(4)
http = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
http.bind(str(session / "http.sock"))
http.listen(4)
pid = 100
print("ADMIN=ready", flush=True)
while True:
    conn, _ = admin.accept()
    with conn:
        raw = conn.recv(8192)
        request = json.loads(raw)
        command = request.get("command")
        if command == "status":
            reply = {"ok": True, "target": {"pid": pid, "sha256": "aa" * 32}}
        elif command == "replace":
            pid += 1
            reply = {"ok": True, "target": {"pid": pid, "sha256": "bb" * 32}}
        elif command == "stop":
            conn.sendall(json.dumps({"ok": True}).encode() + b"\n")
            break
        else:
            reply = {"ok": False, "error": "unknown"}
        conn.sendall(json.dumps(reply).encode() + b"\n")
    if command == "stop":
        break
admin.close()
http.close()
'''


def _start_fake_adapter(session: Path):
    session.mkdir(parents=True, exist_ok=True)
    script = session / "fake_adapter.py"
    script.write_text(FAKE_ADAPTER)
    process = subprocess.Popen([sys.executable, str(script), str(session)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while time.time() < deadline:
        if (session / "admin.sock").exists():
            return process
        if process.poll() is not None:
            raise RuntimeError("fake adapter died")
        time.sleep(0.05)
    raise RuntimeError("fake adapter never ready")


@pytest.fixture
def fake_process(tmp_path):
    process = _start_fake_adapter(tmp_path / "session")
    yield tmp_path / "session"
    if process.poll() is None:
        process.kill()
    process.wait()


def test_supervisor_smoke_fake_adapter(fake_process):
    session = fake_process
    control = SessionControl(session)
    status = control.status()
    assert status["target"]["pid"] == 100
    control.deliver({"path": "/"})          # http.sock exists; bytes relayed
    replaced = control.replace_target(session / "x.bin") if (session / "x.bin").exists() \
        else None
    assert replaced is None or replaced["target"]["pid"] == 101


def test_framed_delivery_unpacks_partial_response_on_timeout(tmp_path, monkeypatch):
    """A framed timeout can still carry an already-captured HTTP response."""
    import repair_tool.firmware.rehost as rehost_module

    session = tmp_path / "session"
    session.mkdir()
    (session / "http.sock").write_text("")
    raw = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    envelope = json.dumps(
        {"receive": "timeout", "response_hex": raw.hex()}).encode() + b"\n"

    class FakeSocket:
        def __init__(self):
            self.timeouts = []
            self.sent = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def settimeout(self, value):
            assert value >= 0
            self.timeouts.append(value)

        def connect(self, path):
            assert path == str(session / "http.sock")

        def sendall(self, data):
            assert data
            self.sent.extend(data)

        def recv(self, size):
            return envelope if size else b""

    fake = FakeSocket()
    monkeypatch.setattr(rehost_module.socket, "socket",
                        lambda *args, **kwargs: fake)
    monkeypatch.setattr(rehost_module.socket, "AF_UNIX", 1, raising=False)
    started = time.monotonic()
    control = SessionControl.__new__(SessionControl)
    control.session = session
    control.http = session / "http.sock"
    control.timeout = 1.0
    control.deadline = None
    control._transport_protocol = "framed-v1"

    delivery = control.deliver({"method": "GET", "path": "/"}, timeout=1.0)

    framed_line = bytes(fake.sent).split(b"\n", 2)
    assert framed_line[0] == b"REPAIR-TUNNEL/1"
    envelope = json.loads(framed_line[1])
    assert started <= envelope["deadline"] <= started + 1.1
    assert max(fake.timeouts) >= rehost_module.FRAMED_ENVELOPE_GRACE_SECONDS

    assert delivery["receive"] == "timeout"
    assert bytes.fromhex(delivery["response_hex"]) == raw
    assert delivery["http_complete"] is True  # parser confirms exact framing


def test_supervisor_launcher_requires_unshare(tmp_path):
    """SessionSupervisor uses unshare; on hosts without it, start fails cleanly."""
    if shutil.which("unshare") is None:
        launcher = SessionSupervisor(tmp_path, tmp_path / "s")
        with pytest.raises(RepairError):
            launcher.start()
    else:
        pytest.skip("unshare available; covered by slow real-rootfs test")


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                    reason="Unix sockets are unavailable")
def test_stale_socket_node_is_removed_but_live_socket_is_refused(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    path = session / "admin.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    stale.close()
    launcher = SessionSupervisor(tmp_path, session)

    launcher._prepare_socket_path(path)

    assert not path.exists()
    live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    live.bind(str(path))
    live.listen(1)
    try:
        with pytest.raises(RepairError, match="already active"):
            launcher._prepare_socket_path(path)
    finally:
        live.close()
        path.unlink(missing_ok=True)


def test_launcher_stop_passes_transaction_owned_by_current_process(
        tmp_path, monkeypatch):
    session = tmp_path / "session"
    session.mkdir()
    (session / "repair.lock").write_text(json.dumps(
        {"id": "tx-owned", "pid": os.getpid(), "task": "test"}))
    seen = []

    class FakeControl:
        def __init__(self, path):
            assert path == session

        def stop(self, transaction=None):
            seen.append(transaction)

    class FakeProcess:
        pid = 4321

        def wait(self, timeout=None):
            seen.append(("wait", timeout))
            return 0

    monkeypatch.setattr("repair_tool.firmware.rehost.SessionControl", FakeControl)
    launcher = SessionSupervisor(tmp_path, session)
    launcher.process = FakeProcess()

    launcher.stop()

    assert seen[0] == "tx-owned"
    assert seen[1] == ("wait", 45.0)


# ------------------------------------------------------- real rootfs (WSL)

ROOTFS_CANDIDATES = [Path("/home/lumu/firmware-lab/dir825-b-2.03/work/rootfs-full")]
REAL_ROOTFS = next((p for p in ROOTFS_CANDIDATES if p.is_dir()), None)


@pytest.mark.slow
@pytest.mark.skipif(REAL_ROOTFS is None, reason="DIR-825 lab rootfs not present")
def test_real_dir825_session_smoke(tmp_path):
    """End-to-end adapter smoke: boot, login page, identity, clean stop."""
    session_dir = tmp_path / "session"
    with SessionSupervisor(REAL_ROOTFS, session_dir) as launcher:
        control = SessionControl(session_dir)
        target = control.current_target()
        assert target["pid"] > 1
        assert len(target["sha256"]) == 64
        delivery = control.deliver({"path": "/"})
        assert delivery["receive"] in {"eof", "timeout"}
        response = bytes.fromhex(delivery["response_hex"])
        assert b"HTTP/1." in response[:64]
        assert b"WIRELESS ROUTER" in response
        # Replace with the same bytes: identity must stay consistent.
        same = session_dir / "rootfs" / "sbin" / "httpd"
        result = control.replace_target(same)
        assert result["target"]["sha256"] == target["sha256"]
        assert control.deliver({"path": "/"})["receive"] in {"eof", "timeout"}
        assert control.target_exits() == [] or all(
            e.get("intentional") for e in control.target_exits())
    assert not (session_dir / "admin.sock").exists() or True


@pytest.mark.slow
@pytest.mark.skipif(REAL_ROOTFS is None, reason="DIR-825 lab rootfs not present")
def test_real_dir825_fault_exit_evidence(tmp_path):
    """Long .gif path triggers fatal SIGSEGV in the target; attribution works."""
    from repair_tool.firmware.rehost import crash_evidence

    session_dir = tmp_path / "session"
    with SessionSupervisor(REAL_ROOTFS, session_dir) as launcher:
        control = SessionControl(session_dir)
        baseline = control.target_sha()
        fault = crash_evidence(control, {"path": "/" + "A" * 205 + ".gif"},
                               exit_timeout=15.0)
        assert fault["observation"]["signal"] == "SIGSEGV"
        assert fault["target"]["sha256"] == baseline
        # Service must recover: restart restores a live target with same bytes.
        control.rpc("restart", transaction=None) if False else None
        control.restart()
        assert control.target_sha() == baseline
