#!/usr/bin/python3
"""Controlled root wrapper for diagnostic-only FirmAE execution.

This program is installed root-owned and invoked through a narrow sudoers rule.
It intentionally accepts only FirmAE compatibility/analysis mode, one known
brand, and a firmware copy below a controller-created Firmae work directory.
It never accepts the interactive run/debug modes or an arbitrary command.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


FIRMAE_ROOT = Path("/usr/local/lib/firmae-controller/FirmAE")
FIRMAE_RUN = FIRMAE_ROOT / "run.sh"
FIRMWARE_ROOT = Path("/home/lumu/firmware-lab")
ALLOWED_BRAND = "dlink"
ALLOWED_USER = "lumu"
ALLOWED_MODES = {"-c": "compatibility", "-a": "analysis"}
INTERNAL_TIMEOUT_SECONDS = 3000
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
CAPTURE_POLL_SECONDS = 0.2
REPORT_BEGIN = b"-----BEGIN FIRMAE REPORT-----"
REPORT_END = b"-----END FIRMAE REPORT-----"
MAX_FIRMWARE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TEXT_ARTIFACT_BYTES = 16 * 1024 * 1024
_IID = re.compile(r"^[1-9][0-9]{0,8}$")


def fail(message: str, code: int = 2) -> int:
    print(json.dumps({
        "schema": "firmae-controller-error-v1",
        "message": message,
    }, ensure_ascii=False), file=sys.stderr)
    return code


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scratch_ids() -> set[int]:
    result: set[int] = set()
    scratch = FIRMAE_ROOT / "scratch"
    if not scratch.is_dir():
        return result
    for child in scratch.iterdir():
        if child.is_dir() and _IID.fullmatch(child.name):
            result.add(int(child.name))
    return result


def firm_ae_iid(firmware: Path) -> int | None:
    """Ask FirmAE's own database helper to attribute this input copy."""
    try:
        completed = subprocess.run(
            ["/usr/bin/python3", str(FIRMAE_ROOT / "scripts" / "util.py"),
             "get_iid", str(firmware), "127.0.0.1"],
            cwd=str(FIRMAE_ROOT),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "LANG": "C.UTF-8",
            },
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    if not _IID.fullmatch(value):
        return None
    iid = int(value)
    if iid not in scratch_ids():
        return None
    return iid


def read_text(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
        return value or None
    except OSError:
        return None


def read_bool(path: Path) -> bool | None:
    value = read_text(path)
    if value is None:
        return None
    return value.lower() == "true"


def tail(path: Path, size: int = 4096) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            remaining = stream.tell()
            start = max(0, remaining - size)
            stream.seek(start)
            return stream.read(size).decode("utf-8", errors="replace")
    except OSError:
        return ""


def export_artifacts(firmware: Path, iid: int) -> tuple[dict | None, str | None]:
    """Export a read-only, verifiable FirmAE analysis snapshot.

    The export is data only.  In particular, run.sh is retained for lineage but
    is never executed by this wrapper or by controller intake.
    """
    if iid <= 0:
        return None, f"invalid FirmAE IID: {iid}"
    scratch = FIRMAE_ROOT / "scratch" / str(iid)
    destination_root = firmware.parent / "artifacts"
    try:
        destination_root.mkdir(mode=0o755)
    except OSError as exc:
        return None, f"cannot create FirmAE artifact directory: {exc}"

    names = (
        "image.raw", "fileList", "architecture", "brand", "ip",
        "kernelVersion", "run.sh",
    )
    entries: dict[str, dict] = {}
    try:
        for name in names:
            source = scratch / name
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"missing or unsafe FirmAE artifact: {name}")
            metadata = source.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"FirmAE artifact is not a regular file: {name}")
            if name != "image.raw" and metadata.st_size > MAX_TEXT_ARTIFACT_BYTES:
                raise ValueError(f"FirmAE artifact is too large: {name}")
            destination = destination_root / name
            if destination.exists() or destination.is_symlink():
                raise ValueError(f"FirmAE artifact destination already exists: {name}")
            if name == "image.raw":
                completed = subprocess.run(
                    ["/usr/bin/cp", "--reflink=auto", "--sparse=always",
                     str(source), str(destination)],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    timeout=180, check=False,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                    },
                )
                if completed.returncode != 0:
                    detail = (completed.stderr or completed.stdout).strip()[-1000:]
                    raise ValueError(f"cannot copy image.raw: {detail}")
            else:
                shutil_copy_file(source, destination)
            os.chmod(destination, 0o444)
            entries[name] = {
                "sha256": sha256(destination),
                "size": destination.stat().st_size,
                "mode": oct(stat.S_IMODE(destination.stat().st_mode)),
            }

        manifest = {
            "schema": "firmae-artifacts-v1",
            "firmware_iid": iid,
            "transformed_image": True,
            "origin": "firmae-analysis-scratch",
            "execute_policy": "data-only; artifacts are never executed",
            "artifacts": entries,
        }
        manifest_path = destination_root / "artifact-manifest.json"
        payload = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        manifest_path.write_text(payload, encoding="utf-8")
        os.chmod(manifest_path, 0o444)
        return {
            "directory": "artifacts",
            "manifest": "artifacts/artifact-manifest.json",
            "schema": manifest["schema"],
            "firmware_iid": iid,
            "transformed_image": True,
            "files": entries,
        }, None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, str(exc)


def shutil_copy_file(source: Path, destination: Path) -> None:
    """Copy without following a source symlink; caller already rejects links."""
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        while True:
            block = incoming.read(1024 * 1024)
            if not block:
                break
            outgoing.write(block)


def terminate_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (OSError, PermissionError):
        process.kill()


def validate_firmware_copy(value: str) -> Path:
    raw = Path(value)
    if raw.is_symlink() or not raw.is_file():
        raise ValueError("firmware input must be a regular controller copy")
    path = raw.resolve(strict=True)
    parts = path.parts
    if not path.is_relative_to(FIRMWARE_ROOT):
        raise ValueError("firmware copy is outside firmware-lab")
    if "triage-work" not in parts or "firmae" not in parts:
        raise ValueError("firmware copy is outside a Firmae triage work tree")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_FIRMWARE_BYTES:
        raise ValueError("firmware copy has an invalid size")
    return path


def firmae_environment() -> dict[str, str]:
    """Return the minimal environment expected by FirmAE's analysis scripts."""
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        # FirmAE's generated run_analyze.sh creates a TAP device for the
        # invoking user with ``sudo tunctl ... -u ${USER}``.  The controlled
        # sudo boundary resets environment variables, so provide the fixed
        # allowed user instead of forwarding caller-controlled values.
        "USER": ALLOWED_USER,
    }


def execute_firmae(mode: str, brand: str, firmware: Path,
                   work: Path) -> tuple[int, bytes, bytes, bool, bool, float]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="firmae-controller-") as temporary:
        stdout_path = Path(temporary) / "stdout.bin"
        stderr_path = Path(temporary) / "stderr.bin"
        process: subprocess.Popen | None = None
        timed_out = False
        output_limited = False
        returncode: int | None = None
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    [str(FIRMAE_RUN), mode, brand, str(firmware)],
                    cwd=str(FIRMAE_ROOT),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=firmae_environment(),
                    start_new_session=True,
                )
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    captured = max(stdout_path.stat().st_size,
                                   stderr_path.stat().st_size)
                    if elapsed >= INTERNAL_TIMEOUT_SECONDS:
                        timed_out = True
                    elif captured >= MAX_CAPTURE_BYTES:
                        output_limited = True
                    if timed_out or output_limited:
                        terminate_group(process)
                        break
                    time.sleep(CAPTURE_POLL_SECONDS)
                returncode = process.wait()
        except OSError:
            if process is not None and process.poll() is None:
                terminate_group(process)
                returncode = process.wait()
            return 127, b"", b"", timed_out, output_limited, \
                time.monotonic() - started

        def bounded(path: Path) -> bytes:
            with path.open("rb") as stream:
                return stream.read(MAX_CAPTURE_BYTES)

        return (returncode if returncode is not None else 1,
                bounded(stdout_path), bounded(stderr_path),
                timed_out, output_limited,
                time.monotonic() - started)


def build_report(mode_name: str, brand: str, firmware: Path,
                 before_sha256: str, unchanged: bool,
                 before_ids: set[int], execution: dict) -> dict:
    after_ids = scratch_ids()
    new_ids = sorted(after_ids - before_ids)
    iid = firm_ae_iid(firmware)
    if iid is None and new_ids:
        iid = new_ids[-1]
    scratch = FIRMAE_ROOT / "scratch" / str(iid) if iid is not None else None
    architecture = read_text(scratch / "architecture") if scratch else None
    ping = read_bool(scratch / "ping") if scratch else None
    web = read_bool(scratch / "web") if scratch else None
    result = read_bool(scratch / "result") if scratch else None
    boot = "yes" if web or result else "partial" if ping else "failed"
    compatibility = "yes" if web or result else "unknown"
    analysis_result = None
    analysis_limitations: list[str] = []
    if scratch is not None and iid is not None:
        analysis_log = FIRMAE_ROOT / "analyses" / "scratch" / str(iid) / \
            "analysis_log"
        analysis_result = read_text(analysis_log / "result")
        initializer = read_text(analysis_log / "initializer_log")
        nmap = read_text(analysis_log / "nmap_log")
        rsf = read_text(analysis_log / "rsf")
        if initializer:
            analysis_limitations.append(initializer)
        if nmap:
            analysis_limitations.append(nmap)
        if rsf:
            analysis_limitations.append(rsf)

    logs: dict[str, str] = {}
    if scratch is not None:
        for name in ("qemu.initial.serial.log", "qemu.final.serial.log",
                     "emulation.log"):
            path = scratch / name
            if path.is_file():
                logs[name] = sha256(path)

    return {
        "schema": "firmae-report-v1",
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": {
            "name": "FirmAE",
            "version": "controlled-root-wrapper-2",
            "commit": None,
            "environment": "Ubuntu-24.04-WSL2",
        },
        "input": {
            "firmware_sha256": before_sha256,
            "brand": brand,
            "filename": firmware.name,
        },
        "results": {
            "compatibility": compatibility,
            "boot": boot,
            "network": "observed" if ping or web else "none",
            "rootfs": "extracted" if scratch is not None else "unknown",
            "architecture": architecture or "unknown",
            "analysis": "finished" if mode_name == "analysis" else "not_requested",
            "analysis_result": analysis_result,
        },
        "services": [],
        "runs": {
            "controller_mode": mode_name,
            "firmware_iid": iid,
            "new_scratch_iids": new_ids,
            "analysis_limitations": analysis_limitations,
            "serial_log_sha256": logs,
        },
        "interventions": ([{
            "kind": "firmae_scratch_image",
            "iid": iid,
        }] if iid is not None else []),
        "patch_suggestions": [],
        "controller_execution": {
            **execution,
            "input_unchanged": unchanged,
            "run_mode_only": False,
            "network_isolation": "firmAE-default-user-or-tap",
        },
    }


def main(argv: list[str]) -> int:
    if not is_root():
        return fail("controlled wrapper must run as root", 2)
    if len(argv) != 3:
        return fail("expected exactly: -c|-a BRAND FIRMWARE_COPY", 2)
    mode, brand, firmware_value = argv
    if mode not in ALLOWED_MODES:
        return fail("only FirmAE -c and -a are allowed", 2)
    if brand != ALLOWED_BRAND:
        return fail("unsupported brand for controlled wrapper", 2)
    try:
        firmware = validate_firmware_copy(firmware_value)
    except (OSError, ValueError) as exc:
        return fail(str(exc), 2)
    if not FIRMAE_RUN.is_file() or not os.access(FIRMAE_RUN, os.X_OK):
        return fail("FirmAE run.sh is missing or not executable", 2)

    before_sha256 = sha256(firmware)
    before_ids = scratch_ids()
    returncode, stdout, stderr, timed_out, output_limited, duration = \
        execute_firmae(mode, brand, firmware, firmware.parent)
    try:
        unchanged = sha256(firmware) == before_sha256
    except OSError:
        unchanged = False
    execution = {
        "returncode": returncode,
        "timed_out": timed_out,
        "output_limited": output_limited,
        "duration_seconds": round(duration, 6),
        "stdout_tail": stdout[-4096:].decode("utf-8", errors="replace"),
        "stderr_tail": stderr[-4096:].decode("utf-8", errors="replace"),
    }
    report = build_report(ALLOWED_MODES[mode], brand, firmware,
                          before_sha256, unchanged, before_ids, execution)
    artifact_export_error: str | None = None
    if (ALLOWED_MODES[mode] == "analysis" and unchanged and not timed_out
            and not output_limited and returncode == 0):
        iid = report.get("runs", {}).get("firmware_iid")
        if not isinstance(iid, int):
            artifact_export_error = "FirmAE analysis did not produce a usable IID"
            report["artifacts"] = None
        else:
            report["artifacts"], artifact_export_error = export_artifacts(firmware, iid)
    if artifact_export_error is not None:
        report["artifact_export_error"] = artifact_export_error
    payload = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    sys.stdout.buffer.write(REPORT_BEGIN + b"\n" + payload + b"\n" +
                            REPORT_END + b"\n")
    if not unchanged:
        return fail("firmware copy changed during FirmAE execution", 3)
    if timed_out or output_limited or returncode != 0:
        return returncode if returncode > 0 else 1
    if artifact_export_error is not None:
        return fail("FirmAE artifact export failed", 4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
