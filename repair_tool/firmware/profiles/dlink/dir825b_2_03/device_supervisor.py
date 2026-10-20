"""DIR-825 PID-1 supervisor: rehost rc+httpd under PRoot+qemu-mips.

Runs as PID 1 inside an isolated user/net/pid/mount namespace created by
the launcher (see firmware/rehost.py `SessionSupervisor`). Responsibilities:
copy the firmware to a private rootfs, start the lab wireless control
backend the CGI path depends on, launch the original rc then the target
service, register the live target instance (pid/sha256 identity), stream
PRoot kernel-backed waitpid exit events for the target, and serve
admin.sock RPC (status/replace/restart/check/stop) plus the http.sock
session tunnel. The original rootfs stays untouched; all writes hit the
session copy.

Exit-evidence protocol: PRoot -v 1 prints "pid <pid>: terminated with
signal <n>" lines from its waitpid handling of each tracee. The supervisor
correlates them with the registered live instance; only pid+sha256 matches
are recorded to target-exits.jsonl.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from .wireless import WirelessControlBackend
from repair_tool.firmware.session.http_tunnel import isolated_http_tunnel
from repair_tool.firmware.session.processes import (
    alive as session_alive,
    copy_tree,
    listener_pids as generic_listener_pids,
    matching_pids,
    process_identity as generic_process_identity,
    process_matches,
    process_start_id as generic_process_start_id,
    remove_socket_path,
    sha as session_sha,
)
from repair_tool.firmware.runtimes.native_proot_mips32be.loader import (
    executable_mappings as runtime_executable_mappings,
    executable_mappings_from_bytes as runtime_executable_mappings_from_bytes,
    remove_guest_qemu_logs,
)

TARGET_REL = "sbin/httpd"                       # inside the image
GUEST_RUN = "/tmp"                              # PRoot bind: session runtime
SERVICE = ["/sbin/rc", "init"]
READY_MARK = "WIRELESS ROUTER | LOGIN"
EXIT_PATTERN = re.compile(r"pid (\d+): (exited with status|terminated with signal) (\d+)")
FATAL = {"SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"}
QEMU_PC_PATTERN = re.compile(r"\bpc=0x([0-9a-fA-F]{8})\b", re.IGNORECASE)
QEMU_GPR_LINE_PATTERN = re.compile(r"^\s*GPR(?:04|28):\s*(.*)$", re.IGNORECASE)
QEMU_REGISTER_PATTERN = re.compile(
    r"\b(a[0-3]|gp|sp|ra)\s+(?:0x)?([0-9a-fA-F]{8})\b", re.IGNORECASE)
READY_TIMEOUT_SECONDS = 30.0
READY_HTTP_TIMEOUT_SECONDS = 0.75
READY_POLL_SECONDS = 0.2
CLEANUP_TERM_SECONDS = 2.0
CLEANUP_KILL_SECONDS = 1.0


class TargetStartError(RuntimeError):
    """A bounded target launch failed, with evidence safe for RPC transport."""

    def __init__(self, message: str, failure: dict):
        super().__init__(message)
        self.failure = failure


class TargetCleanupError(RuntimeError):
    """Target cleanup failed, with local process diagnostics for evidence."""

    def __init__(self, message: str, failure: dict):
        super().__init__(message)
        self.failure = failure


def sha(path) -> str:
    return session_sha(path)


def alive(pid) -> bool:
    return session_alive(pid)


def _is_httpd_process(pid) -> bool:
    return process_matches(pid, b"httpd")


def _process_start_id(pid: int) -> str | None:
    return generic_process_start_id(pid)


def _process_identity(pid: int) -> dict:
    return generic_process_identity(pid)


def _listener_pids(port: int) -> set[int]:
    return generic_listener_pids(port)


def _httpd_pids() -> set[int]:
    return matching_pids(b"httpd")


def _executable_mappings_from_bytes(data: bytes) -> tuple[list[dict], dict]:
    return runtime_executable_mappings_from_bytes(data)


def executable_mappings(target: Path) -> tuple[list[dict], dict]:
    return runtime_executable_mappings(target)


def copy_firmware(source: Path, target: Path) -> None:
    copy_tree(source, target)

class Dir825Supervisor:
    """Device session. One instance per rehosted firmware copy."""

    def __init__(self, rootfs: Path, session: Path | None = None, trace: bool = False):
        if os.getpid() != 1:
            raise RuntimeError("Supervisor must be PID 1 inside an isolated namespace")
        os.umask(0o077)
        self.trace = trace
        self.out = session or Path(tempfile.mkdtemp(prefix="dir825-"))
        self.out.mkdir(parents=True, exist_ok=True)
        self.root = self.out / "rootfs"
        self.runtime = self.out / "runtime"
        self.evidence = self.out / "wireless"
        copy_firmware(rootfs, self.root)
        (self.runtime / "run").mkdir(parents=True, exist_ok=True)
        (self.runtime / "tmp").mkdir(parents=True, exist_ok=True)
        (self.runtime / "log").mkdir(parents=True, exist_ok=True)
        if not (self.root / "etc/nvram.conf").exists():
            # Runtime nvram lives in the bind-mounted runtime tree.
            default = self.root / "etc/nvram.default"
            source = default.read_bytes() if default.exists() else b"hostname=DIR-825\n"
            (self.runtime / "etc").mkdir(parents=True, exist_ok=True)
            (self.runtime / "etc/nvram.conf").write_bytes(source)
        self.original_sha = {rel: sha(self.root / rel) for rel in (TARGET_REL,)}
        self._mappings, self._elf_header = executable_mappings(
            self.root / TARGET_REL)
        self.processes = []                     # outer PRoot processes
        self.target = None                      # registered live instance
        self.pending_target = None              # launch attempt before readiness
        self._launch_sequence = 0
        self.backend = None
        self.tunnel = None
        proot = shutil.which("proot") or "proot"
        qemu_mips = shutil.which("qemu-mips") or "qemu-mips"
        self.prefix = [proot, "-v", "1", "-r", str(self.root),
                       "-q", qemu_mips,
                       "-b", str(self.runtime) + ":/tmp",
                       "-b", "/proc:/proc",
                       "-b", "/dev/null:/dev/null",
                       "-b", "/dev/random:/dev/random",
                       "-b", "/dev/urandom:/dev/urandom",
                       "-w", "/"]
        self.env = dict(os.environ,
                        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        self.report = {"session": str(self.out), "adapter": "dir825",
                       "target_rel": TARGET_REL, "events": []}
        for name in ("rc.pid", "httpd.pid"):
            (self.runtime / "run" / name).unlink(missing_ok=True)

    # -- lifecycle ---------------------------------------------------------
    def event(self, name, **details):
        self.report["events"].append({"event": name, "time": time.time(), **details})
        (self.out / "report.json").write_text(json.dumps(self.report, indent=2))
        print(name + ": " + json.dumps(details), flush=True)

    def launch(self, args, label):
        log_path = self.out / (label + ".log")
        handle = log_path.open("wb")
        prefix = list(self.prefix)
        qemu_index = prefix.index("-q") + 1
        qemu_options = ""
        if self.trace:
            qemu_options += " -strace"
        fault_log = None
        if args == ["/" + TARGET_REL]:
            descriptor, name = tempfile.mkstemp(
                prefix=label + "-", suffix=".qemu.log", dir=self.runtime / "log")
            os.close(descriptor)
            fault_log = Path(name)
            # This is a guest POSIX path even when offline tests run on Windows.
            guest_fault_log = f"{GUEST_RUN.rstrip('/')}/log/{fault_log.name}"
            ranges = ",".join(
                f"0x{mapping['guest_vaddr']:x}.."
                f"0x{mapping['guest_vaddr'] + mapping['filesz'] - 1:x}"
                for mapping in self._mappings
                if mapping["filesz"] and mapping["flags"] & 1)
            qemu_options += f" -d cpu -dfilter {ranges} -D {guest_fault_log}"
        prefix[qemu_index] += qemu_options
        try:
            process = subprocess.Popen(
                prefix + args, stdout=handle, stderr=subprocess.STDOUT,
                start_new_session=True, env=self.env)
        finally:
            handle.close()
        attempt = (getattr(self, "pending_target", None)
                   if args == ["/" + TARGET_REL] else None)
        if attempt is not None:
            attempt["outer_pid"] = process.pid
        self.processes.append({"label": label, "process": process, "log": log_path,
                               "fault_log": fault_log, "offset": 0, "partial": b"",
                               "target_attempt": attempt})
        self.event("launch", label=label, pid=process.pid, args=args,
                   **({"launch_id": attempt["launch_id"],
                       "expected_sha256": attempt["expected_sha256"]}
                      if attempt is not None else {}))
        return process

    def guest_pid(self, name):
        try:
            pid = int((self.runtime / "run" / (name + ".pid")).read_text().strip())
            return pid if alive(pid) else None
        except (OSError, ValueError):
            return None

    def listener_pids(self) -> set[int]:
        return _listener_pids(80)

    def register_target(self, pid, label, attempt=None):
        if not pid or not alive(pid):
            raise RuntimeError("Cannot register a live target")
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError as exc:
            raise RuntimeError("Cannot read target process identity") from exc
        if b"httpd" not in cmdline:
            raise RuntimeError("Target PID does not identify httpd")
        owners = self.listener_pids()
        if owners != {pid}:
            raise RuntimeError(
                "Target PID is not the exclusive owner of the HTTP listener")
        program_sha = sha(self.root / TARGET_REL)
        expected_sha = attempt.get("expected_sha256") if attempt else program_sha
        if program_sha != expected_sha:
            raise RuntimeError("Target program changed during launch")
        start_id = _process_start_id(pid)
        if start_id is None:
            raise RuntimeError("Cannot bind target PID to a process start identity")
        if attempt:
            if pid in attempt.get("preexisting_httpd_pids", ()):
                raise RuntimeError("Target PID predates the current launch attempt")
            observed_start = attempt.get("process_start_id")
            if observed_start is not None and observed_start != start_id:
                raise RuntimeError("Target PID was reused during launch")
        self.target = {"pid": pid, "label": label, "program": "/" + TARGET_REL,
                       "sha256": expected_sha, "process_start_id": start_id,
                       "launch_id": attempt.get("launch_id") if attempt else None,
                       "intentional_stop": False, "exit_recorded": False,
                       "cmdline": cmdline.replace(b"\0", b" ").decode(errors="replace")}
        if attempt:
            attempt["pid"] = pid
            attempt["process_start_id"] = start_id
            attempt["identity_confirmed"] = True
        self.pending_target = None
        self.event("target_registered", pid=pid, label=label,
                   sha256=self.target["sha256"],
                   launch_id=self.target["launch_id"], listener_pids=sorted(owners))

    def observe_exits(self):
        """Parse wait statuses for a registered target or current launch attempt."""
        for item in self.processes:
            with item["log"].open("rb") as stream:
                stream.seek(item["offset"])
                data = item["partial"] + stream.read()
                item["offset"] = stream.tell()
            lines = data.split(b"\n")
            item["partial"] = lines.pop()
            for raw in lines:
                line = raw.decode(errors="replace")
                for match in EXIT_PATTERN.finditer(line):
                    pid, kind, value = int(match[1]), match[2], int(match[3])
                    registered = bool(self.target is not None
                                      and pid == self.target["pid"]
                                      and not self.target["exit_recorded"])
                    attempt = item.get("target_attempt")
                    pending = bool(attempt and not attempt.get("exit_recorded")
                                   and (attempt.get("pid") == pid
                                        or attempt.get("pid") is None))
                    if not registered and not pending:
                        continue
                    signum = value if kind == "terminated with signal" else None
                    try:
                        signal_name = signal.Signals(signum).name if signum else None
                    except ValueError:
                        signal_name = f"SIG{signum}" if signum else None
                    # An unbound child status is useful launch evidence only when
                    # the target invocation has ended or the status is fatal.
                    process_poll = getattr(item["process"], "poll", lambda: None)()
                    if pending and attempt.get("pid") is None \
                            and process_poll is None and signal_name not in FATAL:
                        continue
                    subject = self.target if registered else attempt
                    subject["exit_recorded"] = True
                    if registered and attempt \
                            and attempt.get("launch_id") == self.target.get("launch_id"):
                        attempt["exit_recorded"] = True
                    fault_log = item.get("fault_log")
                    debug_context = (
                        self.parse_fault_context(fault_log)
                        if signal_name in FATAL and fault_log is not None else None)
                    record = {"pid": pid, "label": subject["label"],
                              "program": "/" + TARGET_REL,
                              "sha256": subject.get("sha256",
                                                    subject.get("expected_sha256")),
                              "exit_code": value if signum is None else None,
                              "signal": signum,
                              "signal_name": signal_name,
                              "intentional": subject.get("intentional_stop", False),
                              "phase": "running" if registered else "starting",
                              "identity_confirmed": registered,
                              "launch_id": subject.get("launch_id"),
                              "source": "PRoot tracee kernel waitpid status",
                              "log_path": str(item["log"]), "raw_log_line": line,
                              "fault_log_path": str(fault_log) if fault_log else None,
                              "debug_context": debug_context,
                              "observed_at": time.time()}
                    evidence_path = (self.out / "target-exits.jsonl" if registered
                                     else self.out / "target-launch-failures.jsonl")
                    with evidence_path.open("a") as stream:
                        stream.write(json.dumps(record) + "\n")
                    if not registered:
                        attempt["failure"] = record
                    self.event("target_exit" if registered else "target_launch_exit",
                               pid=pid, signal=record["signal_name"],
                               intentional=record["intentional"],
                               launch_id=record["launch_id"],
                               identity_confirmed=registered)

    def parse_fault_context(self, fault_log: Path) -> dict | None:
        """Extract a minimal, neutral QEMU fault snapshot from its tail log."""
        try:
            size = fault_log.stat().st_size
            with fault_log.open("rb") as stream:
                if size > 2 * 1024 * 1024:
                    stream.seek(size - 2 * 1024 * 1024)
                    stream.readline()
                text = stream.read().decode(errors="replace")
        except OSError:
            return None

        snapshots = []
        registers = None
        for line in text.splitlines():
            pc_match = QEMU_PC_PATTERN.search(line)
            if pc_match:
                registers = {"pc": int(pc_match.group(1), 16)}
                snapshots.append(registers)
                continue
            gpr_match = QEMU_GPR_LINE_PATTERN.match(line)
            if registers is None or gpr_match is None:
                continue
            for match in QEMU_REGISTER_PATTERN.finditer(gpr_match.group(1)):
                registers[match.group(1).lower()] = int(match.group(2), 16)
        if not snapshots:
            return None
        registers = snapshots[-1]
        context = {"source": "qemu execution log tail",
                   "log_path": str(fault_log),
                   **{name: registers[name]
                      for name in ("pc", "ra", "sp", "gp", "a0", "a1",
                                   "a2", "a3") if name in registers}}
        code_words = []
        try:
            with (self.root / TARGET_REL).open("rb") as target_file:
                for register in ("pc", "ra"):
                    address = registers.get(register)
                    if not isinstance(address, int):
                        continue
                    value = self.read_guest_word(target_file, address)
                    if value is not None:
                        code_words.append({"register": register, "vaddr": address,
                                           "bytes_hex": value})
        except OSError:
            pass
        if code_words:
            context["static_code_words"] = code_words
        return context

    def read_guest_word(self, stream, address: int) -> str | None:
        for segment in self._mappings:
            start = segment["guest_vaddr"]
            end = start + segment["filesz"]
            if start <= address and address + 4 <= end:
                stream.seek(segment["file_offset"] + address - start)
                data = stream.read(4)
                if len(data) == 4:
                    return data.hex()
        return None

    def wait_exit(self, pid, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.observe_exits()
            path = self.out / "target-exits.jsonl"
            if path.is_file():
                for line in path.read_text(errors="replace").splitlines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("pid") == pid:
                        return record
            time.sleep(0.05)
        return None

    # -- service management ------------------------------------------------
    @staticmethod
    def _start_failure(attempt: dict, reason: str, **details) -> dict:
        failure = {"kind": "target_start_failed", "reason": reason,
                   "launch_id": attempt["launch_id"],
                   "label": attempt["label"],
                   "expected_sha256": attempt["expected_sha256"], **details}
        if attempt.get("failure"):
            failure["exit"] = attempt["failure"]
        return failure

    def ready(self, attempt=None, timeout=READY_TIMEOUT_SECONDS):
        """Wait for one pid-bound HTTP listener; stale pages never satisfy it."""
        import urllib.error
        import urllib.request

        attempt = attempt or self.pending_target
        current = next((item for item in reversed(self.processes)
                        if item.get("target_attempt") is attempt), None)
        if current is None:
            current = next((item for item in reversed(self.processes)
                            if item["label"].startswith("httpd-")), None)
        deadline = time.monotonic() + timeout
        stale_listener_pids: set[int] = set()
        last_pid = None
        while time.monotonic() < deadline:
            self.observe_exits()
            if attempt and attempt.get("failure"):
                failure = self._start_failure(
                    attempt, "target exited before readiness")
                raise TargetStartError("Target exited before readiness", failure)

            pid = self.guest_pid("httpd")
            owners = self.listener_pids()
            if owners and owners != ({pid} if pid else set()):
                stale_listener_pids.update(owners)
            if pid and _is_httpd_process(pid):
                last_pid = pid
                if attempt and pid not in attempt["preexisting_httpd_pids"]:
                    start_id = _process_start_id(pid)
                    if start_id:
                        attempt["pid"] = pid
                        attempt["process_start_id"] = start_id

            page_ready = False
            try:
                with urllib.request.urlopen(
                        "http://127.0.0.1/",
                        timeout=READY_HTTP_TIMEOUT_SECONDS) as response:
                    page_ready = (response.code == 200
                                  and READY_MARK in response.read().decode(
                                      errors="replace"))
            except (OSError, urllib.error.URLError):
                pass
            if page_ready and pid and owners == {pid} \
                    and (not attempt
                         or pid not in attempt["preexisting_httpd_pids"]):
                return pid

            if current is not None \
                    and getattr(current["process"], "poll", lambda: None)() is not None:
                self.observe_exits()
                failure = (self._start_failure(
                    attempt, "target process exited before readiness",
                    pid=last_pid, listener_pids=sorted(owners)) if attempt else
                    {"kind": "target_start_failed",
                     "reason": "target process exited before readiness"})
                raise TargetStartError("Target exited before readiness", failure)
            time.sleep(min(READY_POLL_SECONDS,
                           max(0, deadline - time.monotonic())))

        failure = (self._start_failure(
            attempt, "target service did not establish a bound listener",
            pid=last_pid, listener_pids=sorted(self.listener_pids()),
            stale_listener_pids=sorted(stale_listener_pids)) if attempt else
            {"kind": "target_start_failed",
             "reason": "target service did not establish a bound listener"})
        raise TargetStartError("Target service not ready", failure)

    def start_target(self):
        self._cleanup_httpd_processes()
        self.target = None                    # fresh instance; old exit state cleared
        failures = []
        for attempt_index in range(2):
            label = "httpd-" + str(len(self.processes))
            self._launch_sequence += 1
            attempt = {
                "launch_id": f"launch-{self._launch_sequence}",
                "label": label,
                "expected_sha256": sha(self.root / TARGET_REL),
                "preexisting_httpd_pids": sorted(_httpd_pids()),
                "pid": None,
                "process_start_id": None,
                "identity_confirmed": False,
                "intentional_stop": False,
                "exit_recorded": False,
                "started_at": time.time(),
            }
            self.pending_target = attempt
            process = self.launch(["/" + TARGET_REL], label)
            try:
                pid = self.ready(attempt)
                self.register_target(pid, label, attempt)
                return process
            except TargetStartError as exc:
                failures.append(exc.failure)
                # A kernel-backed exit from this invocation is candidate
                # behavior, not a stale-listener condition. Preserve it for
                # fault feedback instead of erasing it with another attempt.
                if exc.failure.get("exit") or "process exited" in exc.failure["reason"]:
                    self.pending_target = None
                    raise
            except RuntimeError as exc:
                failures.append(self._start_failure(
                    attempt, "target identity could not be registered",
                    error=str(exc), pid=attempt.get("pid"),
                    listener_pids=sorted(self.listener_pids())))
            if attempt_index == 0:
                self._cleanup_httpd_processes()
        self.pending_target = None
        failure = {"kind": "target_start_failed",
                   "reason": "target failed both bounded launch attempts",
                   "expected_sha256": sha(self.root / TARGET_REL),
                   "attempts": failures}
        raise TargetStartError("Unable to start a bound target instance", failure)

    @staticmethod
    def _cleanup_target_allowed(pid: int) -> bool:
        """Never signal PID 1 or the supervisor itself during target cleanup."""
        return pid > 1 and pid != os.getpid()

    @staticmethod
    def _reap_orphan_pid(pid: int) -> None:
        """Opportunistically reap a re-parented zombie left in PID namespace."""
        if not hasattr(os, "waitpid") or not hasattr(os, "WNOHANG"):
            return
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass

    @classmethod
    def _signal_cleanup_target(cls, pid: int, sig: int, *,
                               use_process_group: bool = False) -> None:
        if not cls._cleanup_target_allowed(pid):
            return
        getpgid = getattr(os, "getpgid", None)
        if use_process_group:
            try:
                if getpgid is not None:
                    process_group = getpgid(pid)
                    own_group = getpgid(0)
                    if process_group > 1 and process_group != own_group:
                        os.killpg(process_group, sig)
                        return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            return

    def _terminate_session_pid(self, pid: int) -> None:
        """Terminate one session-owned PID and its isolated process group."""
        if not self._cleanup_target_allowed(pid):
            return
        self._signal_cleanup_target(pid, signal.SIGTERM)
        deadline = time.monotonic() + CLEANUP_TERM_SECONDS
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not alive(pid):
            self._reap_orphan_pid(pid)
            return

        self._signal_cleanup_target(pid, signal.SIGKILL)
        deadline = time.monotonic() + CLEANUP_KILL_SECONDS
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if alive(pid):
            self._signal_cleanup_target(
                pid, signal.SIGKILL, use_process_group=True)
        self._reap_orphan_pid(pid)

    def _terminate_httpd_pid(self, pid: int, *, intentional: bool) -> None:
        if not self._cleanup_target_allowed(pid):
            return
        if self.target and pid == self.target["pid"] and intentional:
            self.target["intentional_stop"] = True
        self._terminate_session_pid(pid)
        if self.target and pid == self.target["pid"]:
            if self.wait_exit(pid) is None:
                self.event("target_exit_unobserved", pid=pid, intentional=intentional)

    def _cleanup_httpd_processes(self) -> None:
        """Stop every private-namespace port owner, then prove port 80 is free."""
        if getattr(self, "pending_target", None):
            self.pending_target["intentional_stop"] = True
        pidfile = self.runtime / "run/httpd.pid"
        pid = self.guest_pid("httpd")
        candidates = set(self.listener_pids())
        if pid:
            candidates.add(pid)
        terminated = set(candidates)
        for candidate in sorted(candidates):
            self._terminate_httpd_pid(candidate, intentional=True)
        self._reap_httpd_groups()
        pidfile.unlink(missing_ok=True)
        owners = self.listener_pids()
        for owner in sorted(owners - terminated):
            self._terminate_session_pid(owner)
        if owners - terminated:
            self._reap_httpd_groups()
        deadline = time.monotonic() + 5
        owners = self.listener_pids()
        while owners and time.monotonic() < deadline:
            for owner in sorted(owners):
                self._terminate_session_pid(owner)
            time.sleep(0.1)
            owners = self.listener_pids()
        if owners:
            diagnostics = [_process_identity(owner) for owner in sorted(owners)]
            failure = {
                "kind": "target_cleanup_failed",
                "reason": "HTTP listener remained after target cleanup",
                "listener_owners": diagnostics,
                "attempted_pids": sorted(terminated),
                "runtime": str(self.runtime),
            }
            self.event("target_cleanup_failed", **failure)
            raise TargetCleanupError(
                "HTTP listener remained after target cleanup: "
                + ",".join(str(owner) for owner in sorted(owners)), failure)

    def _reap_httpd_groups(self):
        """Force-stop every launched httpd process group; flush exit state."""
        import subprocess as _sub
        for item in self.processes:
            if not item["label"].startswith("httpd-"):
                continue
            if getattr(item["process"], "poll", lambda: None)() is None:
                try:
                    os.killpg(item["process"].pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                item["process"].wait(timeout=5)
            except _sub.TimeoutExpired:
                pass
        self.observe_exits()
        remove_guest_qemu_logs(self.runtime)

    def stop_target(self):
        self.observe_exits()
        pid = self.guest_pid("httpd")
        escaped = bool(pid and (not self.target or pid != self.target["pid"]))
        self._cleanup_httpd_processes()
        if escaped:
            self.event("escaped_httpd_stopped", pid=pid)
        self.target = None
        self.pending_target = None
        self.event("target_stopped", pid=pid)

    def restart(self):
        self.stop_target()
        self.start_target()
        self.event("restart", httpd_pid=self.guest_pid("httpd"))

    def replace(self, source):
        source = Path(source)
        data = source.read_bytes()
        try:
            mappings, elf_header = _executable_mappings_from_bytes(data)
        except RuntimeError as exc:
            raise ValueError("Replacement must be a valid ELF32 big-endian MIPS image") from exc
        program = self.root / TARGET_REL
        before = sha(program)
        self.stop_target()
        temporary = program.with_suffix(".replacement")
        temporary.write_bytes(data)
        temporary.chmod(0o755)
        os.replace(temporary, program)
        self._mappings, self._elf_header = mappings, elf_header
        self.start_target()
        self.event("replace", before_sha256=before, after_sha256=sha(program))

    # -- entry -------------------------------------------------------------
    def start(self):
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        self.backend = WirelessControlBackend(self.runtime / "run/hostapd/ath0", self.evidence)
        self.backend.start()
        self.launch(SERVICE, "rc")
        time.sleep(4)
        if self.guest_pid("httpd") or self.listener_pids():
            self.stop_target()
        self.start_target()
        remove_socket_path(self.out / "http.sock")
        self.tunnel = isolated_http_tunnel(self.out / "http.sock")
        self.event("session_ready", target_pid=self.target["pid"])

    def authorize_mutation(self, transaction: str | None):
        """Authorize against the live flock, holding it when currently free."""
        import fcntl

        lock = self.out / "repair.lock"
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            os.close(descriptor)
        try:
            owner = json.loads(lock.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Session lock is held but its owner record is invalid") from exc
        if not isinstance(owner, dict) or transaction != owner.get("id"):
            raise RuntimeError(
                "Session is owned by a repair transaction; mutation refused")
        return None

    def serve(self):
        self.start()
        path = self.out / "admin.sock"
        remove_socket_path(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(4)
            server.settimeout(0.5)
            print("ADMIN=" + str(path), flush=True)
            stop = False
            while not stop:
                self.observe_exits()
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(10)
                    raw = bytearray()
                    while b"\n" not in raw and len(raw) <= 8192:
                        block = conn.recv(1024)
                        if not block:
                            break
                        raw.extend(block)
                    mutation_guard = None
                    try:
                        if len(raw) > 8192:
                            raise ValueError("oversized request")
                        request = json.loads(raw.split(b"\n", 1)[0])
                        command = request.get("command")
                        if command in {"replace", "restart", "stop"}:
                            mutation_guard = self.authorize_mutation(
                                request.get("transaction"))
                        if command == "status":
                            reply = {"ok": True, "adapter": "dir825",
                                     "transport_protocol": "framed-v1",
                                     "target": self.public_target()}
                        elif command == "restart":
                            self.restart()
                            reply = {"ok": True, "target": self.public_target()}
                        elif command == "replace":
                            self.replace(request["source"])
                            reply = {"ok": True, "target": self.public_target()}
                        elif command == "stop":
                            stop = True
                            reply = {"ok": True}
                        else:
                            raise ValueError(f"unknown command: {command}")
                    except Exception as exc:    # noqa: BLE001 - reported to caller
                        reply = {"ok": False, "error": str(exc)}
                        failure = getattr(exc, "failure", None)
                        if isinstance(failure, dict):
                            reply["failure"] = failure
                    finally:
                        if mutation_guard is not None:
                            os.close(mutation_guard)
                    try:
                        conn.sendall(json.dumps(reply).encode() + b"\n")
                    except OSError:
                        # Client timed out and closed first; its RPC already
                        # failed on its side. The session must survive.
                        pass
        self.close()

    def public_target(self):
        if self.target is None:
            return None
        pid = self.target["pid"]
        try:
            program_matches = (sha(self.root / TARGET_REL)
                               == self.target["sha256"])
        except OSError:
            program_matches = False
        if not _is_httpd_process(pid) \
                or _process_start_id(pid) != self.target.get("process_start_id") \
                or self.listener_pids() != {pid} or not program_matches:
            self.observe_exits()
            return None
        return {"pid": self.target["pid"], "sha256": self.target["sha256"],
                "program": self.target["program"], "label": self.target["label"],
                "launch_id": self.target.get("launch_id"),
                "process_start_id": self.target.get("process_start_id")}

    def close(self):
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self.observe_exits()
        if self.tunnel:
            self.tunnel.close()
        if self.backend:
            self.backend.stop()
        self.stop_target()
        for path in Path("/proc").iterdir():
            if path.name.isdigit() and int(path.name) > 1:
                try:
                    os.kill(int(path.name), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for item in self.processes:
            try:
                item["process"].wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self.report["original_unchanged"] = all(
            sha(self.root / rel) == value for rel, value in self.original_sha.items())
        (self.out / "report.json").write_text(json.dumps(self.report, indent=2))
        for socket_path in (self.out / "http.sock", self.out / "admin.sock"):
            try:
                remove_socket_path(socket_path)
            except RuntimeError as exc:
                self.event("socket_cleanup_refused", path=str(socket_path), error=str(exc))


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    supervisor = Dir825Supervisor(Path(args.rootfs), Path(args.session), trace=args.trace)
    try:
        supervisor.serve()
    finally:
        supervisor.close()


if __name__ == "__main__":
    main()
