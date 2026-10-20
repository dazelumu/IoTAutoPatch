"""Read-only inference of a generic firmware boot plan.

The result is a proposal for humans and tooling, never an authorization to run
an unknown device. A plan is promoted only after a closed profile binds it to
a verified runtime, architecture and protocol.
"""
from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ...arch.names import (MIPS32BE_E_FLAGS_ABI_MASK,
                           MIPS32BE_E_FLAGS_ABI_O32,
                           MIPS32BE_E_FLAGS_MICROMIPS)
from ...arch.registry import architecture_names
from ..protocol import protocol_names


BOOT_PLAN_SCHEMA = "candidate-boot-plan-v1"
MAX_HINTS = 16
MAX_INIT_FILES = 256
MAX_INIT_FILE_BYTES = 256 * 1024


@dataclass(frozen=True)
class TargetRule:
    path: str
    service: str
    protocol: str
    confidence: float


_TARGET_RULES = (
    TargetRule("sbin/httpd", "httpd", "http-ascii-get-head-port80", 0.72),
    TargetRule("usr/sbin/httpd", "httpd", "http-ascii-get-head-port80", 0.68),
    TargetRule("usr/sbin/lighttpd", "lighttpd", "http-ascii-get-head-port80", 0.64),
    TargetRule("usr/sbin/nginx", "nginx", "http-ascii-get-head-port80", 0.64),
    TargetRule("usr/sbin/uhttpd", "uhttpd", "http-ascii-get-head-port80", 0.64),
)
_INIT_CANDIDATES = ("sbin/rc", "etc/init.d/rcS", "etc/init.d/rc", "etc/rc.d/rcS")
_INIT_DIRECTORIES = ("etc/init.d", "etc/rc.d")


def _safe_relative(value: str) -> Path | None:
    if (not isinstance(value, str) or not value.strip() or "\\" in value
            or "\x00" in value):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(
            part in {"", ".", ".."} for part in path.parts):
        return None
    return Path(*path.parts)


def _regular_file(rootfs: Path, relative: Path) -> Path | None:
    try:
        current = rootfs
        for part in relative.parts[:-1]:
            current = current / part
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                return None
        candidate = current / relative.parts[-1]
        mode = candidate.lstat().st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        return None
    return candidate


def _owned_directory(rootfs: Path, relative: Path) -> Path | None:
    path = rootfs / relative
    try:
        mode = path.lstat().st_mode
    except OSError:
        return None
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        return None
    return path


def _elf_identity(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
    except OSError as exc:
        return {"valid": False, "reason": f"cannot read ELF header: {exc}"}
    if len(header) < 52 or header[:4] != b"\x7fELF":
        return {"valid": False, "reason": "target is not a readable ELF image"}
    elf_class = {1: "ELF32", 2: "ELF64"}.get(header[4])
    endianness = {1: "little", 2: "big"}.get(header[5])
    if elf_class is None or endianness is None:
        return {"valid": False, "reason": "target has an unsupported ELF identity encoding"}
    byte_order = "big" if endianness == "big" else "little"
    machine_code = int.from_bytes(header[18:20], byte_order)
    machine = {8: "MIPS", 40: "ARM", 183: "AArch64"}.get(machine_code, str(machine_code))
    flags_offset = 36 if elf_class == "ELF32" else 48
    e_flags = int.from_bytes(header[flags_offset:flags_offset + 4], byte_order)
    candidate = None
    abi = None
    if machine_code == 8 and elf_class == "ELF32":
        abi = "o32" if e_flags & MIPS32BE_E_FLAGS_ABI_MASK == MIPS32BE_E_FLAGS_ABI_O32 else None
        if abi == "o32" and not e_flags & MIPS32BE_E_FLAGS_MICROMIPS:
            candidate = f"mips32{'be' if endianness == 'big' else 'le'}"
    elif machine_code == 40 and elf_class == "ELF32":
        candidate = "arm32"
    elif machine_code == 183 and elf_class == "ELF64":
        candidate = "aarch64"
    result = {
        "valid": True,
        "class": elf_class,
        "endianness": endianness,
        "machine": machine,
        "machine_code": machine_code,
        "abi": abi,
        "candidate": candidate,
    }
    if machine_code == 8 and candidate is not None:
        result["e_flags"] = e_flags
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _init_evidence(rootfs: Path) -> tuple[list[dict], dict[str, list[str]]]:
    available: list[dict] = []
    references: dict[str, list[str]] = {}
    scanned = 0
    bytes_read = 0
    for relative in _INIT_CANDIDATES:
        path = _regular_file(rootfs, Path(relative))
        if path is not None:
            available.append({
                "path": relative,
                "kind": "known-init-path",
                "executable_bit": bool(path.stat().st_mode & stat.S_IXUSR),
            })
    for directory_name in _INIT_DIRECTORIES:
        directory = _owned_directory(rootfs, Path(directory_name))
        if directory is None:
            continue
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for entry in entries:
            if scanned >= MAX_INIT_FILES or bytes_read >= MAX_INIT_FILE_BYTES:
                return available, references
            relative = Path(directory_name) / entry.name
            path = _regular_file(rootfs, relative)
            if path is None or path.stat().st_size + bytes_read > MAX_INIT_FILE_BYTES:
                continue
            scanned += 1
            try:
                data = path.read_bytes()
            except OSError:
                continue
            bytes_read += len(data)
            available.append({
                "path": relative.as_posix(),
                "kind": "init-directory-entry",
                "executable_bit": bool(path.stat().st_mode & stat.S_IXUSR),
            })
            for rule in _TARGET_RULES:
                needle = rule.service.encode("ascii", "ignore")
                if needle and needle in data:
                    references.setdefault(rule.path, []).append(relative.as_posix())
    return available, references


def _target_candidate(rootfs: Path, relative: Path, source: str,
                      rule: TargetRule | None, init_refs: list[str]) -> dict | None:
    path = _regular_file(rootfs, relative)
    if path is None:
        return None
    identity = _elf_identity(path)
    if not identity["valid"]:
        return None
    reasons = [f"source: {source}"]
    confidence = 0.30 if source == "explicit-hint" else 0.22
    if rule is not None:
        reasons.append(f"common service path: {rule.path}")
        confidence = max(confidence, rule.confidence)
    if init_refs:
        reasons.append("referenced by init scripts: " + ", ".join(init_refs[:3]))
        confidence += 0.16
    if _owned_directory(rootfs, Path("www")) is not None:
        reasons.append("rootfs contains a www directory")
        confidence += 0.05
    try:
        info = path.stat()
        executable_bit = bool(info.st_mode & stat.S_IXUSR)
    except OSError:
        return None
    return {
        "path": relative.as_posix(),
        "source": source,
        "service": rule.service if rule is not None else relative.stem,
        "protocol": rule.protocol if rule is not None else None,
        "sha256": _sha256(path),
        "size": info.st_size,
        "executable_bit": executable_bit,
        "architecture": identity,
        "confidence": round(min(confidence, 0.95), 2),
        "reasons": reasons,
        "init_references": init_refs,
    }


def infer_boot_plan(rootfs: str | Path,
                    target_hints: tuple[str, ...] | list[str] = ()) -> dict:
    """Infer bounded, static boot evidence from a materialized rootfs."""
    root = Path(rootfs)
    if not root.is_dir():
        raise ValueError(f"rootfs is not a directory: {root}")
    hints = tuple(dict.fromkeys(target_hints))
    if len(hints) > MAX_HINTS:
        raise ValueError(f"at most {MAX_HINTS} target hints are allowed")
    init_candidates, init_refs = _init_evidence(root)
    registered_architectures = set(architecture_names())
    registered_protocols = set(protocol_names())

    by_path = {rule.path: rule for rule in _TARGET_RULES}
    relatives: list[tuple[Path, str, TargetRule | None]] = []
    for hint in hints:
        relative = _safe_relative(hint)
        if relative is None:
            raise ValueError(f"target hint must be a safe rootfs-relative path: {hint!r}")
        relatives.append((relative, "explicit-hint", by_path.get(relative.as_posix())))
    explicit_paths = {relative.as_posix() for relative, _, _ in relatives}
    for rule in _TARGET_RULES:
        if rule.path not in explicit_paths:
            relatives.append((Path(rule.path), "common-service-path", rule))

    targets = []
    seen: set[str] = set()
    for relative, source, rule in relatives:
        key = relative.as_posix()
        if key in seen:
            continue
        candidate = _target_candidate(
            root, relative, source, rule, init_refs.get(key, []))
        if candidate is not None:
            candidate["architecture"]["registered"] = (
                candidate["architecture"]["candidate"] in registered_architectures)
            candidate["protocol_registered"] = (
                candidate["protocol"] in registered_protocols
                if candidate["protocol"] is not None else False)
            targets.append(candidate)
            seen.add(key)
    targets.sort(key=lambda item: (-item["confidence"], item["path"]))
    status = "candidates_found" if targets else "insufficient_evidence"
    return {
        "schema": BOOT_PLAN_SCHEMA,
        "status": status,
        "rootfs": str(root.resolve()),
        "targets": targets,
        "init_candidates": init_candidates,
        "launch_modes": [
            {"mode": "direct-target", "requires_validation": True,
             "reason": "generic runtime can try the target without a vendor init script"},
            {"mode": "init-then-target", "requires_validation": True,
             "reason": "vendor init may populate runtime state before the service"},
        ],
        "authorization": "candidate-only; unknown plans cannot start authoritative repair",
        "warnings": [
            "A candidate boot plan is static evidence, not a successful boot or repair result.",
            "Private NVRAM backends, daemon wrappers or non-HTTP protocols may still need a profile.",
        ],
    }
