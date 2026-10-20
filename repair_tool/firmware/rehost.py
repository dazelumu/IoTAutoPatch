"""Rehosted-session control: adapter RPC, session-bound delivery, exit
evidence, flock session lock, baseline capture and transactional rollback.

All requests travel through the session's own channels (admin.sock for
control, http.sock for HTTP bytes); the tool never touches arbitrary host
TCP ports, so every observation is bound to one session instance.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from ..config import RepairError
from ..storage import sha
from .protocol import protocol_driver

FATAL_SIGNALS = {"SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"}
MUTATION_RPC_TIMEOUT_SECONDS = 180.0
FIRMWARE_DEADLINE_MESSAGE = "firmware.total_timeout_seconds exceeded"
FRAMED_ENVELOPE_GRACE_SECONDS = 1.0
HTTP_DRIVER = protocol_driver("http-ascii-get-head-port80")
DEFAULT_HTTP_PROTOCOL = HTTP_DRIVER.name


def firmware_deadline_exceeded(exc: Exception) -> bool:
    """Whether an exception is the controller-wide firmware deadline."""
    return (getattr(exc, "status", None) == "infrastructure_failed"
            and str(exc) == FIRMWARE_DEADLINE_MESSAGE)


def request_bytes(request: dict, protocol: str | None = None) -> bytes:
    """Single wire representation for reproduction AND verification requests.

    ``protocol=None`` deliberately retains the original GET/HEAD driver.  The
    newer form/auth protocol must be selected explicitly.
    """
    selected = protocol or DEFAULT_HTTP_PROTOCOL
    return protocol_driver(selected).encode_request(request)


class SessionLock:
    """Permanent lock file + flock. Ownership IS the kernel lock; the file
    content (pid/task/id) is diagnostic only. Never unlink, never take over by
    dead-PID guesswork: the kernel releases flock when a holder dies."""

    def __init__(self, session_dir: Path):
        self.path = session_dir / "repair.lock"
        self.id = f"tx-{os.getpid()}-{int(time.time())}"
        self._fd: int | None = None

    def acquire(self, task: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise RepairError("infrastructure_failed",
                              f"Session is locked by another task: {self.path}")
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({"id": self.id, "pid": os.getpid(), "task": task,
                                 "started": time.time()}).encode())
        os.fsync(fd)
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)            # kernel drops the flock; file stays
            self._fd = None


class SessionControl:
    """Client for one adapter session: admin.sock RPC + http.sock delivery."""

    def __init__(self, session_dir: str | Path, timeout: float = 35.0):
        self.session = Path(session_dir)
        self.admin = self.session / "admin.sock"
        self.http = self.session / "http.sock"
        self.timeout = timeout
        self.deadline: float | None = None
        self._transport_protocol: str | None = None
        if not self.admin.exists():
            raise RepairError("infrastructure_failed",
                              f"Session admin socket missing: {self.admin}")

    # -- control channel ---------------------------------------------------
    # Mutating RPCs drive a full service restart inside the adapter (stop,
    # replace bytes, boot, readiness poll, one crash-recovery retry); the
    # default short timeout would cut them off mid-flight.
    SLOW_COMMANDS = {"replace", "restart", "stop"}

    def rpc(self, command: str, **fields) -> dict:
        timeout = max(self.timeout, MUTATION_RPC_TIMEOUT_SECONDS) \
            if command in self.SLOW_COMMANDS \
            else self.timeout
        timeout = self._bounded_timeout(timeout)
        operation_deadline = time.monotonic() + timeout
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self._remaining(operation_deadline))
                client.connect(str(self.admin))
                client.settimeout(self._remaining(operation_deadline))
                client.sendall(json.dumps({"command": command, **fields}).encode() + b"\n")
                data = bytearray()
                while b"\n" not in data:
                    client.settimeout(self._remaining(operation_deadline))
                    block = client.recv(8192)
                    if not block:
                        break
                    data.extend(block)
                    if len(data) > 1024 * 1024:
                        raise ValueError("oversized admin reply")
        except (OSError, ValueError) as exc:
            raise RepairError("infrastructure_failed",
                              f"Admin RPC {command} failed: {exc}") from exc
        if not data:
            raise RepairError("infrastructure_failed", f"Admin RPC {command}: empty reply")
        try:
            result = json.loads(data)
        except json.JSONDecodeError as exc:
            raise RepairError("infrastructure_failed",
                              f"Admin RPC {command}: malformed reply") from exc
        if not isinstance(result, dict):
            raise RepairError("infrastructure_failed", "Admin reply must be an object")
        if not result.get("ok"):
            error = RepairError(
                "infrastructure_failed",
                f"Admin RPC {command}: {result.get('error', 'unknown error')}")
            if isinstance(result.get("failure"), dict):
                error.failure = result["failure"]
            raise error
        return result

    def status(self) -> dict:
        return self.rpc("status")

    def current_target(self) -> dict:
        """Live target instance; binds observations to pid+sha256 identity."""
        status = self.status()
        instance = status.get("target")
        if not isinstance(instance, dict) or type(instance.get("pid")) is not int \
                or instance["pid"] <= 0 or not isinstance(instance.get("sha256"), str):
            raise RepairError("infrastructure_failed",
                              "Adapter reports no live target instance")
        return instance

    def target_sha(self) -> str:
        return self.current_target()["sha256"]

    def replace_target(self, source: Path, transaction: str | None = None) -> dict:
        return self.rpc("replace", source=str(Path(source).resolve()),
                        **({"transaction": transaction} if transaction else {}))

    def restart(self, transaction: str | None = None) -> dict:
        return self.rpc("restart",
                        **({"transaction": transaction} if transaction else {}))

    def check(self) -> dict:
        return self.rpc("check")

    def stop(self, transaction: str | None = None) -> dict:
        return self.rpc("stop",
                        **({"transaction": transaction} if transaction else {}))

    # -- data channel ------------------------------------------------------
    def deliver(self, request: dict, timeout: float = 6.0,
                *, protocol: str | None = None) -> dict:
        """Deliver raw HTTP bytes through THIS session's private tunnel."""
        selected_protocol = protocol or DEFAULT_HTTP_PROTOCOL
        raw = request_bytes(request, selected_protocol)
        if self._transport_protocol is None:
            self._transport_protocol = self.status().get("transport_protocol", "raw")
        framed = self._transport_protocol == "framed-v1"
        upstream_deadline = time.monotonic() + self._bounded_timeout(timeout)
        operation_deadline = upstream_deadline
        if framed:
            operation_deadline = upstream_deadline + FRAMED_ENVELOPE_GRACE_SECONDS
            if self.deadline is not None:
                operation_deadline = min(operation_deadline, self.deadline)
        if not self.http.exists():
            raise RepairError("infrastructure_failed",
                              f"Session HTTP tunnel missing: {self.http}")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(self._remaining(operation_deadline))
            client.connect(str(self.http))
            client.settimeout(self._remaining(operation_deadline))
            if framed:
                client.sendall(b"REPAIR-TUNNEL/1\n" + json.dumps({
                    "request_hex": raw.hex(), "deadline": upstream_deadline}).encode() + b"\n")
            else:
                client.sendall(raw)
            response = bytearray()
            receive = "eof"
            try:
                limit = 256 * 1024 if framed else 65536
                while len(response) <= limit:
                    client.settimeout(self._remaining(operation_deadline))
                    block = client.recv(4096)
                    if not block:
                        break
                    response.extend(block)
                    if framed and b"\n" in response:
                        break
                if len(response) > limit:
                    receive = "size_limit"
            except OSError as exc:
                receive = type(exc).__name__
            if framed and b"\n" in response:
                try:
                    envelope = json.loads(response)
                    receive = envelope["receive"]
                    response = bytearray.fromhex(envelope["response_hex"])
                except (ValueError, KeyError, TypeError):
                    receive, response = "transport_error", bytearray()
        from .http import response_complete
        return {"sent": True, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "receive": receive, "response_hex": bytes(response).hex(),
                "protocol": selected_protocol,
                "http_complete": response_complete(
                    bytes(response), request.get("method", "GET"), receive),
                "transport": str(self.http)}

    def _remaining(self, operation_deadline: float) -> float:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise RepairError("infrastructure_failed", FIRMWARE_DEADLINE_MESSAGE)
        remaining = operation_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Session operation deadline exceeded")
        return remaining

    # -- exit evidence -----------------------------------------------------
    def target_exits(self) -> list[dict]:
        path = self.session / "target-exits.jsonl"
        if not path.is_file():
            return []
        exits = []
        for line in path.read_text(errors="replace").splitlines():
            try:
                exits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return exits

    def _bounded_timeout(self, timeout: float) -> float:
        """Clamp a transport wait to an optional absolute workflow deadline."""
        timeout = max(0.0, float(timeout))
        if self.deadline is None:
            return timeout
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RepairError("infrastructure_failed", FIRMWARE_DEADLINE_MESSAGE)
        return min(timeout, remaining)


class SessionSupervisor:
    """Host-side launcher/monitor for a device-profile session subprocess.

    Starts the PID-1 adapter inside isolated user/net/pid/mount namespaces
    (unshare), waits for admin.sock readiness, exposes stop()/alive checks.
    The repair.lock flock guards transactional mutations; the adapter
    refuses replace/restart/stop without the matching transaction id.
    """

    def __init__(self, rootfs: Path, session_dir: Path, adapter: str = "dir825",
                 trace: bool = False, activity_timeout: float = 900.0):
        import sys
        from .profiles.registry import resolve_profile
        self.rootfs = rootfs
        self.session = session_dir
        self.adapter = adapter
        self.profile = resolve_profile(adapter)
        self.trace = trace
        self.activity_timeout = activity_timeout
        self.module = self.profile.supervisor_module
        self.package_parent = Path(sys.modules["repair_tool"].__file__).resolve().parent.parent
        self.process: subprocess.Popen | None = None
        self._log_handle = None
        self.started = time.time()
        self.last_active = time.time()

    def _prepare_socket_path(self, path: Path) -> None:
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(mode):
            raise RepairError("infrastructure_failed",
                              f"Session path is not a Unix socket: {path}")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(str(path))
        except OSError:
            path.unlink(missing_ok=True)
        else:
            raise RepairError("infrastructure_failed",
                              f"Session socket is already active: {path}")
        finally:
            probe.close()

    def start(self, deadline: float | None = None) -> "SessionSupervisor":
        self.session.mkdir(parents=True, exist_ok=True)
        # A killed adapter can leave pathname sockets behind. Refuse live
        # endpoints and remove only disconnected socket nodes before launch.
        self._prepare_socket_path(self.session / "admin.sock")
        self._prepare_socket_path(self.session / "http.sock")
        argv = ["unshare", "--user", "--map-root-user", "--net", "--pid",
                "--fork", "--mount-proc",
                sys.executable, "-m", self.module,
                "--rootfs", str(self.rootfs), "--session", str(self.session)]
        if self.trace:
            argv.append("--trace")
        self._log_handle = (self.session / "supervisor.log").open("wb")
        try:
            self.process = subprocess.Popen(argv, stdout=self._log_handle,
                                            stderr=subprocess.STDOUT,
                                            start_new_session=True,
                                            cwd=str(self.package_parent))
        except OSError as exc:
            self._log_handle.close()
            self._log_handle = None
            raise RepairError("infrastructure_failed",
                              f"Cannot launch adapter session: {exc}") from exc
        readiness_deadline = time.monotonic() + 120
        deadline_exceeded = False
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RepairError("infrastructure_failed",
                                  FIRMWARE_DEADLINE_MESSAGE)
            readiness_deadline = min(readiness_deadline,
                                     time.monotonic() + remaining)
        while time.monotonic() < readiness_deadline:
            if (self.session / "admin.sock").exists():
                try:
                    probe_timeout = 2.0
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            deadline_exceeded = True
                            break
                        probe_timeout = max(0.01, min(probe_timeout, remaining))
                    SessionControl(self.session, timeout=probe_timeout).current_target()
                    if (deadline is not None
                            and time.monotonic() >= deadline):
                        deadline_exceeded = True
                        break
                    return self
                except RepairError:
                    pass
            if self.process.poll() is not None:
                break
            time.sleep(min(0.2, max(0.0, readiness_deadline - time.monotonic())))
            if deadline is not None and time.monotonic() >= deadline:
                deadline_exceeded = True
                break
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if deadline_exceeded:
            raise RepairError("infrastructure_failed", FIRMWARE_DEADLINE_MESSAGE)
        raise RepairError("infrastructure_failed",
                          "Adapter session did not become ready with a live target; "
                          "see supervisor.log")

    def keepalive(self):
        self.last_active = time.time()

    def alive(self) -> bool:
        if self.process is None:
            return False
        # Two independent facts: outer process alive AND activity within bounds.
        if self.process.poll() is not None:
            return False
        return (time.time() - self.last_active) <= self.activity_timeout

    def _owned_transaction(self) -> str | None:
        try:
            owner = json.loads((self.session / "repair.lock").read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(owner, dict) and owner.get("pid") == os.getpid() \
                and isinstance(owner.get("id"), str):
            return owner["id"]
        return None

    def stop(self, timeout: float = 45.0) -> None:
        if self.process is None:
            return
        try:
            SessionControl(self.session).stop(
                transaction=self._owned_transaction())
        except RepairError:
            pass
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        finally:
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None
            for path in (self.session / "admin.sock", self.session / "http.sock"):
                try:
                    if stat.S_ISSOCK(path.lstat().st_mode):
                        path.unlink()
                except FileNotFoundError:
                    pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


def wait_target_exit(control: SessionControl, baseline_count: int,
                     *, timeout: float = 10.0,
                     deadline: float | None = None) -> dict | None:
    """Wait for one NEW target exit record after baseline_count."""
    wait_deadline = time.monotonic() + timeout
    while time.monotonic() < wait_deadline:
        if deadline is not None and time.monotonic() >= deadline:
            raise RepairError("infrastructure_failed", FIRMWARE_DEADLINE_MESSAGE)
        exits = control.target_exits()
        if len(exits) > baseline_count:
            return exits[-1]
        time.sleep(0.2)
    return None


def crash_evidence(control: SessionControl, request: dict, *,
                   exit_timeout: float = 10.0,
                   deadline: float | None = None) -> dict:
    """Deliver one request and require a PoC-attributable fatal exit.

    Attribution: unintentional AND fatal signal AND matching pid/sha256 of
    the live target. Service-management stops (intentional SIGTERM/SIGKILL)
    and clean exits are never fault evidence.
    """
    target = control.current_target()
    before = len(control.target_exits())
    delivery = control.deliver(request)
    record = wait_target_exit(control, before, timeout=exit_timeout,
                              deadline=deadline)
    if record is None:
        raise RepairError("reproduction_failed",
                          "Request delivered but target did not exit; no fault evidence")
    signal_name = record.get("signal_name")
    if record.get("pid") != target["pid"] or record.get("sha256") != target["sha256"]:
        raise RepairError("reproduction_failed",
                          "Exit evidence does not match the live target pid/sha256")
    if record.get("intentional") or signal_name not in FATAL_SIGNALS:
        raise RepairError("reproduction_failed",
                          f"Target exited without an attributable fault "
                          f"(signal={signal_name}, intentional={record.get('intentional')})")
    return {"target": {"pid": target["pid"], "sha256": target["sha256"]},
            "input": {k: request.get(k, "GET" if k == "method" else "/")
                      for k in ("method", "path")},
            "delivery": delivery,
            "observation": {"signal": signal_name,
                            "debug_context": record.get("debug_context")},
            "exit_record": record}


def restore(control: SessionControl, baseline: Path, target_rel: str,
            transaction: str | None = None) -> dict:
    """Rollback: replace with baseline bytes, verify hashes and health."""
    control.replace_target(baseline, transaction=transaction)
    rootfs_file = control.session / "rootfs" / target_rel
    if control.target_sha() != sha(baseline) or sha(rootfs_file) != sha(baseline):
        raise RepairError("integrity_failed", "Rollback hash mismatch")
    return {"restored": True, "sha256": sha(baseline)}
