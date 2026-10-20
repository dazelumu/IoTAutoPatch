"""FirmAE diagnostic-only execute adapter.

The adapter invokes an explicitly configured executable on a copy of the
firmware image and records its observable output.  It never installs the tool,
never invokes sudo, and never promotes FirmAE observations to authoritative
repair verification evidence.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import signal
import time
from pathlib import Path
from typing import Any

from ...config import RepairError
from ...storage import save_json, sha
from ..diagnostics_intake import FIRMAE_REPORT_SCHEMA, load_report
from ..diagnostics_ledger import DiagnosticsLedger
from ..runtime import capability_report


FIRMAE_MODES = {
    "compatibility": "-c",
    "analysis": "-a",
}
_CONFIG_KEYS = {
    "enabled", "executable", "work_root", "timeout_seconds", "required",
}
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
CAPTURE_POLL_SECONDS = 0.05
_BRAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REPORT_BEGIN = b"-----BEGIN FIRMAE REPORT-----"
_REPORT_END = b"-----END FIRMAE REPORT-----"


def _contains_or_equals(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _output_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return bytes(value)


class FirmAEAdapter:
    """Execute FirmAE as an untrusted, diagnostic-only backend."""

    backend = "firmae"

    def __init__(self, executable: Path | None, work_root: Path | None,
                 timeout_seconds: int, *, enabled: bool = True,
                 required: bool = False, expose_to_model: bool = False,
                 peer_work_roots: tuple[Path, ...] = ()) -> None:
        if type(timeout_seconds) is not int or timeout_seconds < 1:
            raise RepairError("preparation_failed",
                              "triage.firmae.timeout_seconds must be a positive integer")
        for name, value in (("enabled", enabled), ("required", required),
                            ("expose_to_model", expose_to_model)):
            if not isinstance(value, bool):
                raise RepairError("preparation_failed",
                                  f"triage.firmae.{name} must be boolean")
        if executable is not None and (
                executable.name.lower() in {"sudo", "sudo.exe"}
                or executable.resolve().name.lower() in {"sudo", "sudo.exe"}):
            raise RepairError("preparation_failed", "triage.firmae may not invoke sudo")
        self.executable = executable
        self.work_root = work_root
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.required = required
        self.expose_to_model = expose_to_model
        self.peer_work_roots = tuple(peer_work_roots)

    @classmethod
    def from_config(cls, cfg: dict) -> "FirmAEAdapter":
        triage = cfg.get("triage", {})
        if not isinstance(triage, dict):
            raise RepairError("preparation_failed", "triage must be an object")
        values = triage.get("firmae", {})
        if not isinstance(values, dict):
            raise RepairError("preparation_failed", "triage.firmae must be an object")
        if set(values) - _CONFIG_KEYS:
            unexpected = sorted(set(values) - _CONFIG_KEYS)
            raise RepairError("preparation_failed",
                              f"Unexpected triage.firmae fields: {unexpected}")
        config_path = Path(cfg.get("config_path", ".")).resolve()

        def configured_path(value: Any) -> Path | None:
            if value is None or value == "":
                return None
            if not isinstance(value, str):
                raise RepairError("preparation_failed",
                                  "triage.firmae paths must be strings")
            path = Path(value)
            return (path if path.is_absolute() else config_path.parent / path).resolve()

        peer_value = triage.get("greenhouse", {}).get("work_root") \
            if isinstance(triage.get("greenhouse"), dict) else None
        peer_work_root = configured_path(peer_value)

        diagnostics = cfg.get("firmware", {}).get("diagnostics", {})
        if not isinstance(diagnostics, dict) or not isinstance(
                diagnostics.get("expose_to_model", False), bool):
            raise RepairError("preparation_failed",
                              "firmware.diagnostics.expose_to_model must be boolean")
        return cls(
            configured_path(values.get("executable")),
            configured_path(values.get("work_root")),
            values.get("timeout_seconds"),
            enabled=values.get("enabled", False),
            required=values.get("required", False),
            expose_to_model=diagnostics.get("expose_to_model", False),
            peer_work_roots=() if peer_work_root is None else (peer_work_root,),
        )

    def configuration_status(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        if self.executable is None:
            return False, "executable_not_configured"
        if self.work_root is None:
            return False, "work_root_not_configured"
        if not self.executable.is_file():
            return False, "executable_missing"
        if os.name == "posix" and not os.access(self.executable, os.X_OK):
            return False, "executable_not_executable"
        return True, "configured"

    def validate_execution(self, firmware: Path, mode: str, brand: str) -> None:
        if mode not in FIRMAE_MODES:
            raise RepairError("preparation_failed",
                              f"Unsupported FirmAE mode: {mode}")
        if not isinstance(brand, str) or not _BRAND.fullmatch(brand):
            raise RepairError("preparation_failed",
                              "FirmAE brand must be a short ASCII identifier")
        firmware = Path(firmware)
        if not firmware.is_file():
            raise RepairError("preparation_failed",
                              f"FirmAE firmware image is missing: {firmware}")

    @staticmethod
    def _child_env() -> dict[str, str]:
        env = {"PATH": os.environ.get("PATH", "")}
        for name in ("HOME", "LANG"):
            if name in os.environ:
                env[name] = os.environ[name]
        return env

    @staticmethod
    def _extract_report(stdout: bytes) -> tuple[dict | None, str | None]:
        if not stdout.strip():
            return None, "FirmAE stdout is not a valid report: output is empty"
        payload = stdout
        begin = payload.find(_REPORT_BEGIN)
        if begin >= 0:
            end = payload.find(_REPORT_END, begin + len(_REPORT_BEGIN))
            if end < 0:
                return None, "FirmAE report marker has no end"
            payload = payload[begin + len(_REPORT_BEGIN):end].strip()
        try:
            report = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, f"FirmAE stdout is not a valid report: {exc}"
        if not isinstance(report, dict) or report.get("schema") != FIRMAE_REPORT_SCHEMA:
            return None, f"FirmAE stdout is not a valid report: expected {FIRMAE_REPORT_SCHEMA}"
        return report, None

    def _validate_work_layout(self, output: Path,
                              protected_inputs: tuple[Path, ...]) -> None:
        work_roots = [self.work_root.resolve()] + [
            root.resolve() for root in self.peer_work_roots
        ]
        protected = [path.resolve() for path in protected_inputs]
        protected.append(self.executable.resolve())
        output_root = output.parent
        for index, left in enumerate(work_roots):
            for right in work_roots[index + 1:]:
                if _contains_or_equals(left, right):
                    raise RepairError(
                        "preparation_failed",
                        "FirmAE and Greenhouse work directories must not contain each other")
            if _contains_or_equals(left, output) or \
                    _contains_or_equals(left, output_root):
                raise RepairError(
                    "preparation_failed",
                    "FirmAE/Greenhouse work and triage output directories "
                    "must not contain each other")
            if any(_contains_or_equals(left, path) or
                   _contains_or_equals(path, left) for path in protected):
                raise RepairError(
                    "preparation_failed",
                    "FirmAE work directory must not contain configured inputs "
                    "or its executable")

    @staticmethod
    def _write_capture(output: Path, stdout: bytes, stderr: bytes) -> None:
        (output / "raw" / "stdout.bin").write_bytes(stdout)
        (output / "raw" / "stderr.bin").write_bytes(stderr)
        (output / "stdout" / "stdout.txt").write_text(
            stdout.decode("utf-8", errors="replace"), encoding="utf-8")
        (output / "stderr" / "stderr.txt").write_text(
            stderr.decode("utf-8", errors="replace"), encoding="utf-8")

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen) -> None:
        """Terminate FirmAE and descendants left in its process group."""
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                return
            except (OSError, ProcessLookupError, PermissionError):
                pass
        process.kill()

    @staticmethod
    def _input_unchanged(path: Path, expected_sha256: str) -> bool:
        try:
            return sha(path) == expected_sha256
        except OSError:
            return False

    def _execute_process(self, command: list[str], cwd: Path,
                         raw_dir: Path) -> dict:
        """Capture tool output to files with a hard per-stream limit."""
        stdout_path = raw_dir / "stdout.bin"
        stderr_path = raw_dir / "stderr.bin"
        started = time.monotonic()
        returncode: int | None = None
        execution_error: str | None = None
        process: subprocess.Popen | None = None
        reason: str | None = None
        try:
            with stdout_path.open("wb") as stdout_stream, \
                    stderr_path.open("wb") as stderr_stream:
                process = subprocess.Popen(
                    command,
                    cwd=cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_stream,
                    stderr=stderr_stream,
                    env=self._child_env(),
                    start_new_session=True,
                )
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    if elapsed >= self.timeout_seconds:
                        reason = "timeout"
                    elif max(stdout_path.stat().st_size,
                             stderr_path.stat().st_size) >= MAX_CAPTURE_BYTES:
                        reason = "output_limit"
                    if reason is not None:
                        self._terminate_process_group(process)
                        break
                    time.sleep(CAPTURE_POLL_SECONDS)
                returncode = process.wait()
                if reason is None and max(stdout_path.stat().st_size,
                                          stderr_path.stat().st_size) >= MAX_CAPTURE_BYTES:
                    reason = "output_limit"
        except OSError as exc:
            execution_error = f"Cannot execute FirmAE: {exc}"
            if process is not None and process.poll() is None:
                self._terminate_process_group(process)
                returncode = process.wait()
        output_limited = reason == "output_limit"
        if output_limited:
            for path in (stdout_path, stderr_path):
                with path.open("r+b") as stream:
                    stream.truncate(MAX_CAPTURE_BYTES)

        def read_bounded(path: Path) -> bytes:
            with path.open("rb") as stream:
                return stream.read(MAX_CAPTURE_BYTES)

        return {
            "stdout": read_bounded(stdout_path),
            "stderr": read_bounded(stderr_path),
            "returncode": returncode,
            "timed_out": reason == "timeout",
            "output_limited": output_limited,
            "failure_reason": reason,
            "error": execution_error,
            "duration_seconds": round(time.monotonic() - started, 6),
            "capture_limit_bytes": MAX_CAPTURE_BYTES,
            "process_group": True,
        }

    def _base_report(self, run_id: str, mode: str, firmware: Path,
                     firmware_sha256: str) -> dict:
        return {
            "schema": "triage-report-v1",
            "kind": "firmware-triage",
            "backend": "firmae",
            "status": "firmae_execution_failed",
            "mode": mode,
            "run_id": run_id,
            "authoritative": False,
            "configuration": {
                "enabled": self.enabled,
                "required": self.required,
                "executable": str(self.executable) if self.executable else None,
                "work_root": str(self.work_root) if self.work_root else None,
                "timeout_seconds": self.timeout_seconds,
            },
            "firmware": {
                "sha256": firmware_sha256,
                "size": firmware.stat().st_size,
                "original_unchanged": True,
            },
        }

    @staticmethod
    def _finish(output: Path, report: dict) -> dict:
        capability = capability_report("firmae")
        if capability["capabilities"]["authoritative_verification"] is not False:
            raise RepairError("preparation_failed",
                              "FirmAE capability must remain diagnostic-only")
        save_json(output / "capability-report.json", capability)
        report["output"] = str(output)
        save_json(output / "report.json", report)
        return report

    def execute(self, firmware: Path, *, output: Path, run_id: str,
                mode: str = "compatibility", brand: str = "unknown") -> dict:
        firmware = Path(firmware).resolve()
        self.validate_execution(firmware, mode, brand)
        for directory in ("raw", "stdout", "stderr", "normalized"):
            (output / directory).mkdir(parents=True, exist_ok=True)

        firmware_sha256 = sha(firmware)
        report = self._base_report(run_id, mode, firmware, firmware_sha256)
        configured, reason = self.configuration_status()
        if not configured:
            report["status"] = "firmae_not_configured"
            report["not_configured_reason"] = reason
            report["execution"] = None
            return self._finish(output, report)

        work_root = self.work_root.resolve()
        output = output.resolve()
        self._validate_work_layout(output, (firmware,))
        work_run = work_root / run_id
        if work_run == output or work_run in output.parents or output in work_run.parents:
            raise RepairError("preparation_failed",
                              "FirmAE work and output directories must not contain each other")
        if work_run.exists():
            raise RepairError("preparation_failed",
                              f"FirmAE work directory already exists: {work_run}")
        work_run.mkdir(parents=True)
        firmware_copy = work_run / firmware.name
        shutil.copyfile(firmware, firmware_copy)
        copy_sha256 = sha(firmware_copy)
        report["firmware"]["copy_sha256"] = copy_sha256
        if copy_sha256 != firmware_sha256:
            report["firmware"]["copy_integrity"] = False
            report["status"] = "firmae_copy_integrity_failed"
            report["execution"] = {
                "command": None,
                "cwd": str(work_run),
                "firmware_copy": str(firmware_copy),
                "timeout_seconds": self.timeout_seconds,
                "timed_out": False,
                "returncode": None,
                "duration_seconds": 0.0,
                "error": "FirmAE firmware copy does not match the original image",
            }
            return self._finish(output, report)
        report["firmware"]["copy_integrity"] = True
        command = [str(self.executable), FIRMAE_MODES[mode], brand, str(firmware_copy)]

        captured = self._execute_process(command, cwd=work_run,
                                         raw_dir=output / "raw")
        stdout = _output_bytes(captured["stdout"])
        stderr = _output_bytes(captured["stderr"])
        self._write_capture(output, stdout, stderr)
        original_unchanged = self._input_unchanged(firmware, firmware_sha256)

        report["execution"] = {
            "command": command,
            "cwd": str(work_run),
            "firmware_copy": str(firmware_copy),
            "timeout_seconds": self.timeout_seconds,
            "timed_out": captured["timed_out"],
            "output_limited": captured["output_limited"],
            "failure_reason": captured["failure_reason"],
            "returncode": captured["returncode"],
            "duration_seconds": captured["duration_seconds"],
            "error": captured["error"],
            "capture_limit_bytes": captured["capture_limit_bytes"],
            "process_group": captured["process_group"],
        }
        report["firmware"]["original_unchanged"] = original_unchanged
        report["firmae"] = {"results": None, "interventions": [], "records": 0}

        if not original_unchanged:
            report["execution"]["error"] = "Original firmware changed during FirmAE execution"
            report["status"] = "firmae_input_changed"
            return self._finish(output, report)
        if (captured["timed_out"] or captured["output_limited"]
                or captured["error"] is not None
                or captured["returncode"] != 0):
            if captured["timed_out"]:
                report["status"] = "firmae_timeout"
            elif captured["output_limited"]:
                report["status"] = "firmae_output_limited"
            elif captured["error"] is not None:
                report["status"] = "firmae_execution_failed"
            else:
                report["status"] = "firmae_nonzero_exit"
            return self._finish(output, report)

        raw_report, extract_error = self._extract_report(stdout)
        normalization_error: str | None = extract_error
        if raw_report is not None:
            raw_path = output / "raw" / "firmae-report-v1.json"
            raw_path.write_text(
                json.dumps(raw_report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
            claimed = raw_report.get("input", {}).get("firmware_sha256") \
                if isinstance(raw_report.get("input"), dict) else None
            claimed_brand = raw_report.get("input", {}).get("brand") \
                if isinstance(raw_report.get("input"), dict) else None
            if claimed != firmware_sha256:
                normalization_error = "FirmAE report firmware identity does not match the input image"
            elif claimed_brand != brand:
                normalization_error = "FirmAE report brand does not match the executed brand"
            else:
                try:
                    _, records, metadata = load_report(raw_path, required=True)
                    save_json(output / "normalized" / "firmae-report-v1.json", records)
                    ledger = DiagnosticsLedger(output, run_id=run_id)
                    ledger.register_import({
                        "import_id": f"firmae-{run_id}",
                        "backend": "firmae",
                        "format": FIRMAE_REPORT_SCHEMA,
                        **metadata,
                    })
                    diagnostic_ids = []
                    for record in records:
                        diagnostic_ids.append(ledger.add(record))
                    for diagnostic_id in diagnostic_ids:
                        ledger.append_decision(
                            diagnostic_id,
                            "exposed" if self.expose_to_model else "filtered",
                            "FirmAE diagnostic-only execute adapter")
                    report["counts"] = ledger.document()["counts"]
                    report["firmae"] = {
                        "tool": raw_report.get("tool", {}),
                        "results": raw_report.get("results", {}),
                        "interventions": raw_report.get("interventions", []),
                        "records": len(records),
                    }
                except RepairError as exc:
                    normalization_error = str(exc)

        if normalization_error is not None:
            report["normalization_error"] = normalization_error
            if "firmware identity" in normalization_error:
                report["status"] = "firmae_report_identity_mismatch"
            elif "brand" in normalization_error:
                report["status"] = "firmae_report_brand_mismatch"
            elif "not a valid report" in normalization_error:
                report["status"] = "firmae_report_invalid"
            else:
                report["status"] = "firmae_normalization_failed"
            return self._finish(output, report)

        results = report["firmae"]["results"]
        boot = results.get("boot") if isinstance(results, dict) else None
        if boot in {"failed", "no"}:
            report["status"] = "firmae_boot_failed"
        elif boot == "partial":
            report["status"] = "firmae_partial_boot"
        else:
            report["status"] = "diagnostics_generated"
        return self._finish(output, report)
