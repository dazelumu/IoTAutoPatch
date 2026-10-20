"""Regression coverage for DIR-825 target restart after a fault."""
from __future__ import annotations

from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import urllib.request

from repair_tool.firmware.profiles.dlink.dir825b_2_03 import (
    device_supervisor as supervisor_module,
)
from repair_tool.firmware.profiles.dlink.dir825b_2_03.device_supervisor import (
    Dir825Supervisor,
    TargetCleanupError,
    TargetStartError,
)


class FakeProcess:
    def __init__(self, returncode=None):
        self.pid = 101
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return 0


def test_start_target_requires_registration_not_stale_readiness(
        tmp_path: Path, monkeypatch):
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    instance.runtime = tmp_path / "runtime"
    instance.root = tmp_path / "rootfs"
    target = instance.root / "sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"candidate")
    instance.processes = []
    instance.target = None
    instance.pending_target = None
    instance._launch_sequence = 0
    calls = []

    def fake_launch(args, label):
        instance.processes.append({"label": label, "process": FakeProcess()})
        calls.append(label)
        return FakeProcess()
    monkeypatch.setattr(instance, "launch", fake_launch)
    monkeypatch.setattr(instance, "ready", lambda attempt: 777)
    monkeypatch.setattr(instance, "register_target",
                        lambda pid, label, attempt: (_ for _ in ()).throw(RuntimeError(
                            "Cannot register a live target")))
    monkeypatch.setattr(Dir825Supervisor, "_cleanup_httpd_processes",
                        lambda self: calls.append("cleanup"))
    monkeypatch.setattr(supervisor_module, "_httpd_pids", lambda: set())

    try:
        instance.start_target()
    except TargetStartError as exc:
        assert "bound target" in str(exc)
        assert all("Cannot register" in failure["error"]
                   for failure in exc.failure["attempts"])
    else:
        raise AssertionError("start_target accepted stale readiness")
    assert calls == ["cleanup", "httpd-0", "cleanup", "httpd-1"]


def test_stop_target_reaps_all_httpd_groups(tmp_path: Path, monkeypatch):
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.root = tmp_path / "rootfs"
    instance.root.mkdir()
    instance.processes = [
        {"label": "rc", "process": FakeProcess()},
        {"label": "httpd-1", "process": FakeProcess()},
    ]
    reaped = []
    monkeypatch.setattr(instance, "observe_exits", lambda: None)
    monkeypatch.setattr(instance, "guest_pid", lambda name: None)
    monkeypatch.setattr(Dir825Supervisor, "event",
                        lambda self, name, **fields: None)
    monkeypatch.setattr(Dir825Supervisor, "_cleanup_httpd_processes",
                        lambda self: reaped.append(True))

    instance.stop_target()

    assert reaped == [True]


def test_stop_target_also_stops_escaped_httpd_pidfile_owner(
        tmp_path: Path, monkeypatch):
    """A fault-forked pidfile owner must not retain the candidate's port."""
    from repair_tool.firmware.profiles.dlink.dir825b_2_03 import device_supervisor as supervisor

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.runtime = tmp_path / "runtime"
    (instance.runtime / "run").mkdir(parents=True)
    instance.processes = []
    instance.target = None
    instance.pending_target = None
    stopped = []

    monkeypatch.setattr(instance, "guest_pid", lambda name: 314)
    monkeypatch.setattr(instance, "listener_pids", lambda: set())
    monkeypatch.setattr(
        supervisor, "_is_httpd_process",
        lambda pid: pid == 314)
    monkeypatch.setattr(
        supervisor, "alive",
        lambda pid: pid != 314)
    monkeypatch.setattr(supervisor.os, "kill",
                        lambda pid, sig: stopped.append((pid, sig)))
    events = []
    monkeypatch.setattr(instance, "event",
                        lambda name, **fields: events.append((name, fields)))
    monkeypatch.setattr(instance, "_reap_httpd_groups",
                        lambda: stopped.append("reap"))

    instance._cleanup_httpd_processes()

    assert stopped == [(314, signal.SIGTERM), "reap"]
    assert events == []


def test_cleanup_terminates_listener_owner_even_without_httpd_cmdline(
        tmp_path: Path, monkeypatch):
    """A socket inherited by a helper is still a private-session asset."""
    from repair_tool.firmware.profiles.dlink.dir825b_2_03 import device_supervisor as supervisor

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.runtime = tmp_path / "runtime"
    (instance.runtime / "run").mkdir(parents=True)
    instance.processes = []
    instance.target = None
    instance.pending_target = None
    stopped = []
    listener_owners = iter(({777}, set()))

    monkeypatch.setattr(instance, "guest_pid", lambda name: None)
    def fake_listener_pids():
        try:
            return next(listener_owners)
        except StopIteration:
            return set()
    monkeypatch.setattr(instance, "listener_pids", fake_listener_pids)
    monkeypatch.setattr(supervisor, "_is_httpd_process", lambda pid: False)
    monkeypatch.setattr(supervisor, "alive", lambda pid: False)
    monkeypatch.setattr(
        supervisor.os, "getpgid",
        lambda pid: (_ for _ in ()).throw(OSError("no process group")),
        raising=False)
    monkeypatch.setattr(
        supervisor.os, "kill",
        lambda pid, sig: stopped.append((pid, sig)))
    monkeypatch.setattr(supervisor.time, "sleep", lambda _: None)
    monkeypatch.setattr(instance, "_reap_httpd_groups", lambda: None)

    instance._cleanup_httpd_processes()

    assert stopped == [(777, signal.SIGTERM)]


def test_cleanup_failure_keeps_listener_owner_diagnostics(
        tmp_path: Path, monkeypatch):
    """A persistent owner is reported with bounded /proc identity evidence."""
    from repair_tool.firmware.profiles.dlink.dir825b_2_03 import device_supervisor as supervisor

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.runtime = tmp_path / "runtime"
    (instance.runtime / "run").mkdir(parents=True)
    instance.processes = []
    instance.target = None
    instance.pending_target = None
    clock = {"now": 0.0}
    stopped = []
    events = []

    monkeypatch.setattr(instance, "guest_pid", lambda name: None)
    monkeypatch.setattr(instance, "listener_pids", lambda: {1338})
    monkeypatch.setattr(supervisor, "alive", lambda pid: False)
    monkeypatch.setattr(
        supervisor.time, "monotonic",
        lambda: (clock.__setitem__("now", clock["now"] + 1.0)
                 or clock["now"]))
    monkeypatch.setattr(
        supervisor.os, "getpgid",
        lambda pid: (_ for _ in ()).throw(OSError("no process group")),
        raising=False)
    monkeypatch.setattr(
        supervisor.os, "kill",
        lambda pid, sig: stopped.append((pid, sig)))
    monkeypatch.setattr(supervisor.time, "sleep", lambda _: None)
    monkeypatch.setattr(instance, "_reap_httpd_groups", lambda: None)
    monkeypatch.setattr(
        instance, "event", lambda name, **fields: events.append((name, fields)))

    try:
        instance._cleanup_httpd_processes()
    except TargetCleanupError as exc:
        assert exc.failure["kind"] == "target_cleanup_failed"
        assert exc.failure["listener_owners"] == [
            {"pid": 1338, "cmdline": None}]
        assert 1338 in exc.failure["attempted_pids"]
    else:
        raise AssertionError("cleanup accepted a persistent listener owner")
    assert (1338, signal.SIGTERM) in stopped
    assert events[-1][0] == "target_cleanup_failed"


def test_surviving_owner_gets_bounded_process_group_kill(
        tmp_path: Path, monkeypatch):
    """Direct PID evidence is preserved, then an unkillable owner's group dies."""
    from repair_tool.firmware.profiles.dlink.dir825b_2_03 import device_supervisor as supervisor

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.processes = []
    instance.target = None
    clock = {"now": 0.0}
    pid_signals = []
    group_signals = []
    monkeypatch.setattr(signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(supervisor, "alive", lambda pid: True)
    monkeypatch.setattr(
        supervisor.time, "monotonic",
        lambda: (clock.__setitem__("now", clock["now"] + 1.0)
                 or clock["now"]))
    monkeypatch.setattr(supervisor.os, "getpgid",
                        lambda pid: 777 if pid else 1,
                        raising=False)
    monkeypatch.setattr(
        supervisor.os, "kill",
        lambda pid, sig: pid_signals.append((pid, sig)))
    monkeypatch.setattr(
        supervisor.os, "killpg",
        lambda group, sig: group_signals.append((group, sig)),
        raising=False)
    monkeypatch.setattr(supervisor.time, "sleep", lambda _: None)
    instance._terminate_session_pid(777)

    assert pid_signals == [
        (777, signal.SIGTERM), (777, signal.SIGKILL)]
    assert group_signals == [(777, signal.SIGKILL)]


def test_ready_polls_stale_listener_until_timeout(tmp_path: Path, monkeypatch):
    """A stale page is observed but cannot satisfy the new launch."""

    class Response:
        code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"WIRELESS ROUTER | LOGIN"

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.processes = [{"label": "httpd-1", "process": FakeProcess()}]
    instance.pending_target = None
    instance.runtime = tmp_path / "runtime"
    (instance.runtime / "run").mkdir(parents=True)
    instance.observe_exits = lambda: None
    instance.listener_pids = lambda: {88}
    attempt = {"launch_id": "launch-1", "label": "httpd-1",
               "expected_sha256": "a" * 64,
               "preexisting_httpd_pids": [88], "pid": None,
               "exit_recorded": False}
    calls = []

    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: calls.append(True) or Response())
    monkeypatch.setattr(instance, "guest_pid", lambda name: None)

    try:
        instance.ready(attempt, timeout=0.01)
    except TargetStartError as exc:
        assert exc.failure["stale_listener_pids"] == [88]
        assert exc.failure["listener_pids"] == [88]
    else:
        raise AssertionError("ready accepted a stale listener")
    assert calls


def test_ready_accepts_delayed_pid_only_after_listener_is_bound(
        tmp_path: Path, monkeypatch):
    """A valid delayed pidfile replaces, rather than races, a stale page."""

    class Response:
        code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"WIRELESS ROUTER | LOGIN"

    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    process = FakeProcess()
    attempt = {"launch_id": "launch-2", "label": "httpd-2",
               "expected_sha256": "b" * 64,
               "preexisting_httpd_pids": [88], "pid": None,
               "exit_recorded": False}
    instance.pending_target = attempt
    instance.processes = [{"label": "httpd-2", "process": process,
                           "target_attempt": attempt}]
    instance.observe_exits = lambda: None
    pids = iter((None, 222))
    owners = iter(({88}, {222}))
    instance.guest_pid = lambda name: next(pids)
    instance.listener_pids = lambda: next(owners)

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Response())
    monkeypatch.setattr(supervisor_module, "_is_httpd_process",
                        lambda pid: pid == 222)
    monkeypatch.setattr(supervisor_module, "_process_start_id",
                        lambda pid: "start-222")
    monkeypatch.setattr(supervisor_module.time, "sleep", lambda _: None)

    assert instance.ready(attempt, timeout=1) == 222
    assert attempt["pid"] == 222
    assert attempt["process_start_id"] == "start-222"


def test_pre_ready_fatal_exit_is_preserved_as_launch_failure(tmp_path: Path):
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    process_log = tmp_path / "httpd-1.log"
    process_log.write_text("pid 4321: terminated with signal 11\n")
    fault_log = tmp_path / "httpd-1.qemu.log"
    fault_log.write_text("pc=0x00400000\n")
    attempt = {"launch_id": "launch-3", "label": "httpd-1",
               "expected_sha256": "c" * 64,
               "preexisting_httpd_pids": [], "pid": 4321,
               "exit_recorded": False}
    instance.pending_target = attempt
    instance.target = None
    instance.processes = [{"label": "httpd-1", "process": FakeProcess(1),
                           "log": process_log, "fault_log": fault_log,
                           "offset": 0, "partial": b"",
                           "target_attempt": attempt}]
    instance.event = lambda *args, **kwargs: None
    instance.parse_fault_context = lambda path: {"pc": 0x00400000}

    instance.observe_exits()

    failure = attempt["failure"]
    assert failure["phase"] == "starting"
    assert failure["identity_confirmed"] is False
    assert failure["sha256"] == "c" * 64
    assert failure["signal_name"] == "SIGSEGV"
    assert failure["debug_context"] == {"pc": 0x00400000}
    assert (tmp_path / "target-launch-failures.jsonl").is_file()


def test_register_target_requires_pid_to_own_listener(tmp_path: Path,
                                                       monkeypatch):
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    instance.root = tmp_path / "rootfs"
    target = instance.root / "sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"candidate-bytes")
    instance.pending_target = None
    instance.event = lambda *args, **kwargs: None
    instance.listener_pids = lambda: {99}
    attempt = {"launch_id": "launch-4", "expected_sha256":
               supervisor_module.sha(target), "preexisting_httpd_pids": [],
               "process_start_id": "start-42"}

    monkeypatch.setattr(supervisor_module, "alive", lambda pid: pid == 42)
    original_read_bytes = Path.read_bytes

    def read_bytes(path):
        if str(path).replace("\\", "/").endswith("/proc/42/cmdline"):
            return b"qemu-mips\0/sbin/httpd\0"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(supervisor_module, "_process_start_id",
                        lambda pid: "start-42")

    try:
        instance.register_target(42, "httpd-4", attempt)
    except RuntimeError as exc:
        assert "owner" in str(exc)
    else:
        raise AssertionError("registered a PID that did not own port 80")


def test_unlocked_stale_lock_record_does_not_block_stop(tmp_path: Path,
                                                        monkeypatch):
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    (tmp_path / "repair.lock").write_text(
        '{"id":"old-transaction","pid":123,"task":"old"}')
    calls = []

    fake_fcntl = SimpleNamespace(
        LOCK_EX=1,
        LOCK_NB=2,
        flock=lambda descriptor, operation: calls.append((descriptor, operation)),
    )
    monkeypatch.setitem(sys.modules, "fcntl", fake_fcntl)

    descriptor = instance.authorize_mutation(None)
    try:
        assert isinstance(descriptor, int)
        assert calls
    finally:
        supervisor_module.os.close(descriptor)
