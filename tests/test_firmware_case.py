"""Firmware-mode configuration and session-control unit tests (M1/M2 core)."""
from __future__ import annotations

import json
import socket
import sys
import types
import threading
from pathlib import Path

import pytest
import yaml

if sys.platform.startswith("win"):
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *args, **kwargs: None
    _fcntl.LOCK_EX = 2
    _fcntl.LOCK_NB = 4
    sys.modules.setdefault("fcntl", _fcntl)

from repair_tool.config import DEFAULTS, RepairError, load_config
from repair_tool.firmware.case import firmware_doctor
from repair_tool.firmware.rehost import (SessionControl, SessionLock,
                                         crash_evidence, request_bytes, wait_target_exit)


def base_case(tmp_path: Path, **firmware) -> tuple[Path, Path]:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True, exist_ok=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"\x7fELF-mips32be-placeholder")
    (tmp_path / "poc.py").write_text("print('poc')\n")
    cfg = {"firmware": {"mode": True, "rootfs": str(rootfs),
                        "target": "sbin/httpd", **firmware},
           "poc": {"path": str(tmp_path / "poc.py")},
           "model": {"base_url": "https://example.test/v1", "name": "m",
                     "api_key": "k"}}
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path, rootfs


# ---------------------------------------------------------------- config

def test_firmware_mode_loads_and_resolves_paths(tmp_path):
    path, rootfs = base_case(tmp_path)
    cfg = load_config(path)
    assert cfg["firmware"]["mode"] is True
    assert cfg["firmware"]["rootfs"] == str(rootfs.resolve())
    assert cfg["project"]["path"] is None


@pytest.mark.parametrize("key,value", [
    ("provider", "unsupported"), ("base_url", "http://remote.test/v1"),
    ("base_url", "https://user:password@example.test/v1"),
    ("base_url", None), ("name", None), ("api_key_env", None),
    ("api_key", 123), ("api_key", ""), ("reasoning_effort", "invalid"),
])
def test_firmware_model_uses_source_validation(tmp_path, monkeypatch, key, value):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["model"][key] = value
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError) as caught:
        load_config(path)
    assert caught.value.status == "preparation_failed"


def test_firmware_model_can_inherit_global_layer(tmp_path, monkeypatch):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    model = data.pop("model")
    path.write_text(yaml.safe_dump(data))
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(yaml.safe_dump({"model": model}))
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    assert load_config(path)["model"]["name"] == "m"


def test_firmware_mode_requires_rootfs(tmp_path):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["firmware"]["rootfs"] = str(tmp_path / "missing")
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="rootfs"):
        load_config(path)


def test_firmware_mode_rejects_target_escape(tmp_path):
    path, _ = base_case(tmp_path, target="../../etc/passwd")
    with pytest.raises(RepairError, match="rootfs-relative"):
        load_config(path)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX symlink")
def test_firmware_mode_rejects_target_symlink(tmp_path):
    path, rootfs = base_case(tmp_path)
    target = rootfs / "sbin" / "httpd"
    outside = tmp_path / "outside-httpd"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(RepairError, match="not a symbolic link"):
        load_config(path)


@pytest.mark.parametrize("directory", [
    "rootfs/repair-results",
    ".",
])
def test_firmware_mode_rejects_output_rootfs_overlap(tmp_path, directory):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["output"] = {"directory": str(tmp_path / directory)}
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="must not contain"):
        load_config(path)


def test_firmware_mode_rejects_project(tmp_path):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["project"] = {"path": str(tmp_path)}
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="excludes project"):
        load_config(path)


def test_firmware_mode_requires_poc(tmp_path):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["poc"] = {"path": None}
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="poc.path"):
        load_config(path)


def test_firmware_mode_requires_existing_poc_file(tmp_path):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["poc"]["path"] = str(tmp_path / "missing-poc.py")
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="existing file"):
        load_config(path)


def test_firmware_checks_validated(tmp_path):
    bad = {"checks": [{"request": {"path": "/x\r\n"}, "statuses": [200]}]}
    path, _ = base_case(tmp_path, **bad)
    with pytest.raises(RepairError, match="ASCII|request"):
        load_config(path)
    good = {"checks": [{"request": {"path": "/"}, "statuses": [200],
                        "contains": "LOGIN"}]}
    path, _ = base_case(tmp_path, **good)
    assert load_config(path)["firmware"]["checks"][0]["contains"] == "LOGIN"


def test_firmware_accepts_new_protocol_with_declared_steps(tmp_path):
    path, _ = base_case(tmp_path)
    data = yaml.safe_load(path.read_text())
    data["firmware"]["protocol"] = "http-ascii-auth-form-multi-step-port80"
    data["firmware"]["checks"] = [{
        "steps": [
            {"id": "home", "method": "GET", "path": "/",
             "capture_cookies": True, "statuses": [200]},
            {"id": "login", "method": "POST", "path": "/login.cgi",
             "form": {"login_name": "YWRtaW4="}, "statuses": [200]},
        ],
        "statuses": [200],
    }]
    path.write_text(yaml.safe_dump(data))
    cfg = load_config(path)

    assert cfg["firmware"]["protocol"] == "http-ascii-auth-form-multi-step-port80"
    assert "protocol" not in cfg["firmware"]["checks"][0]


def test_request_bytes_rejects_ambiguity():
    for mutation in ({"method": "POST"}, {"path": "no-slash"}, {"path": "/x\r\nX: y"},
                     {"path": "/has space"}, {"host": "router\r\nX: y"},
                     {"host": "bad host"}, {"port": True}, {"port": 0},
                     {"port": 8080}):
        with pytest.raises(RepairError):
            request_bytes({"path": "/", **mutation})
    assert request_bytes({"path": "/", "port": 80}) == \
        request_bytes({"path": "/"})


def test_firmware_doctor_reports_missing_ip_and_invalid_elf(tmp_path,
                                                            monkeypatch):
    import shutil
    import subprocess
    from types import SimpleNamespace

    path, _ = base_case(tmp_path)
    cfg = load_config(path)
    monkeypatch.setattr(
        shutil, "which",
        lambda name: None if name == "ip" else f"/usr/bin/{name}")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="mips\n", stderr=""))

    result = firmware_doctor(cfg)

    assert "ip" in result["missing_tools"]
    assert result["firmware"]["target_elf_valid"] is False
    assert result["status"] == "not_ready"


# ---------------------------------------------------------------- fake session

class FakeAdapter:
    """Wire-level fake: admin.sock + http.sock + target-exits.jsonl."""

    def __init__(self, directory: Path, target_bytes: bytes):
        self.directory = directory
        self.target_file = directory / "rootfs" / "sbin" / "httpd"
        self.target_file.parent.mkdir(parents=True)
        self.target_file.write_bytes(target_bytes)
        self.pid = 4242
        (directory / "target-exits.jsonl").write_text("")
        self.exits_lock = threading.Lock()
        self.listeners = []
        self.threads = []
        self.stopped = threading.Event()
        for name in ("admin.sock", "http.sock"):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(directory / name))
            listener.listen(8)
            listener.settimeout(0.1)
            self.listeners.append(listener)
            thread = threading.Thread(target=self._serve, args=(listener, name), daemon=True)
            thread.start()
            self.threads.append(thread)

    def record_exit(self, signal_name="SIGSEGV", intentional=False):
        with self.exits_lock:
            with (self.directory / "target-exits.jsonl").open("a") as stream:
                stream.write(json.dumps({
                    "pid": self.pid, "program": "/sbin/httpd",
                    "sha256": _sha_bytes(self.target_file.read_bytes()),
                    "signal_name": signal_name, "intentional": intentional}) + "\n")

    def _serve(self, listener, name):
        import hashlib
        import selectors
        selector = selectors.DefaultSelector()
        selector.register(listener, selectors.EVENT_READ)
        while not self.stopped.is_set():
            for key, _ in selector.select(timeout=0.1):
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                with conn:
                    conn.settimeout(3)
                    data = conn.recv(65536)
                    if name == "admin.sock":
                        reply = self._admin(json.loads(data))
                    else:
                        # Session-bound HTTP: crash on /fault while baseline runs.
                        if data.startswith(b"GET /fault "):
                            self.record_exit()
                        reply = b"HTTP/1.0 200 OK\r\n\r\nWIRELESS ROUTER | LOGIN"
                    conn.sendall(reply)

    def _admin(self, request):
        import hashlib
        command = request.get("command")
        digest = hashlib.sha256(self.target_file.read_bytes()).hexdigest()
        if command == "status":
            return json.dumps({"ok": True, "target": {"pid": self.pid, "sha256": digest}}).encode() + b"\n"
        if command == "replace":
            self.target_file.write_bytes(Path(request["source"]).read_bytes())
            self.pid += 1
            return json.dumps({"ok": True, "target": {"pid": self.pid, "sha256": digest}}).encode() + b"\n"
        return json.dumps({"ok": False, "error": "unknown"}).encode() + b"\n"

    def close(self):
        self.stopped.set()
        for thread in self.threads:
            thread.join(timeout=1)
        for listener in self.listeners:
            listener.close()


def _sha_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def fake_session(tmp_path):
    adapter = FakeAdapter(tmp_path / "session", b"\x7fELF-test-target")
    yield tmp_path / "session", adapter
    adapter.close()


def test_session_control_status_and_delivery(fake_session):
    session, adapter = fake_session
    control = SessionControl(session)
    assert control.current_target()["pid"] == 4242
    delivery = control.deliver({"path": "/"})
    assert delivery["receive"] in {"eof", "response"}
    assert delivery["transport"].endswith("http.sock")


def test_crash_evidence_attributes_fatal_exit(fake_session):
    session, adapter = fake_session
    control = SessionControl(session)
    fault = crash_evidence(control, {"path": "/fault"}, exit_timeout=3.0)
    assert fault["observation"]["signal"] == "SIGSEGV"
    assert fault["exit_record"]["intentional"] is False
    assert fault["target"]["pid"] == 4242


def test_crash_evidence_rejects_no_exit(fake_session):
    session, _ = fake_session
    control = SessionControl(session)
    with pytest.raises(RepairError, match="did not exit"):
        crash_evidence(control, {"path": "/ok"}, exit_timeout=0.5)


def test_crash_evidence_rejects_intentional_stop(fake_session):
    session, adapter = fake_session
    control = SessionControl(session)
    timer = threading.Timer(0.2, adapter.record_exit,
                            kwargs={"signal_name": "SIGTERM", "intentional": True})
    timer.start()
    try:
        with pytest.raises(RepairError, match="attributable fault"):
            crash_evidence(control, {"path": "/ok"}, exit_timeout=2.0)
    finally:
        timer.join()


# ---------------------------------------------------------------- lock

def test_session_lock_exclusive_and_recoverable(fake_session, tmp_path):
    import os
    session, _ = fake_session
    lock = SessionLock(session)
    lock.acquire("task-a")
    second = SessionLock(session)
    with pytest.raises(RepairError, match="locked"):
        second.acquire("task-b")
    # Simulate holder death: kernel releases flock on close of the OTHER fd.
    os.close(lock._fd)
    lock._fd = None
    second.acquire("task-b")            # no takeover code needed
    assert second._fd is not None
    second.release()
    lock.release()                      # releasing a closed fd is a no-op


def test_session_lock_stale_content_is_diagnostic_only(fake_session):
    session, _ = fake_session
    lock_file = session / "repair.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_file.write_text(json.dumps({"pid": 999999, "task": "ghost"}))
    lock = SessionLock(session)
    lock.acquire("task-new")            # content ignored; kernel lock decides
    assert lock_file.exists()           # never unlinked
    lock.release()
    assert lock_file.exists()
