"""FirmAE route-A automated intake and rootfs materialization.

FirmAE remains a diagnostic and extraction backend.  This module converts a
successful analysis artifact snapshot into an independent, bounded rootfs and a
generated firmware case; it never executes content from the firmware image.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from ..arch.names import MIPS32BE
from ..config import RepairError, load_config
from ..storage import save_json
from .case import _architecture_facts
from .diagnostics_intake import FIRMAE_REPORT_SCHEMA
from .profiles.registry import resolve_profile
from .runtime import capability_report as runtime_capability_report


INTAKE_SCHEMA = "firmware-intake-v1"
ARTIFACT_SCHEMA = "firmae-artifacts-v1"
SEVEN_ZIP = Path("/usr/bin/7z")
SEVEN_ZIP_TIMEOUT_SECONDS = 900
MAX_IMAGE_BYTES = 16 * 1024 * 1024 * 1024
MAX_FILES = 100_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SYMLINKS = 4_096
MAX_PATH_LENGTH = 4_096
MAX_FILE_LIST_BYTES = 16 * 1024 * 1024
REQUIRED_ARTIFACTS = (
    "image.raw", "fileList", "architecture", "brand", "ip",
    "kernelVersion", "run.sh",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _contains_or_equals(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _read_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairError("preparation_failed",
                          f"Cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RepairError("preparation_failed", f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_archive_path(value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise RepairError("preparation_failed",
                          f"Unsafe archive path encoding: {value!r}")
    path = PurePosixPath(value)
    parts = path.parts
    if not parts or path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        if not allow_empty or parts:
            raise RepairError("preparation_failed",
                              f"Unsafe archive path: {value!r}")
    if len(value) > MAX_PATH_LENGTH:
        raise RepairError("preparation_failed", "Archive path exceeds length limit")
    return path.as_posix()


def _run_seven_zip(arguments: list[str], *, timeout: int) -> str:
    if not SEVEN_ZIP.is_file():
        raise RepairError("preparation_failed",
                          f"Route-A intake requires {SEVEN_ZIP} in Ubuntu")
    try:
        completed = subprocess.run(
            [str(SEVEN_ZIP), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepairError("preparation_failed", f"Cannot execute 7z: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-1000:].strip()
        raise RepairError("preparation_failed",
                          f"7z failed with exit {completed.returncode}: {detail}")
    return completed.stdout


def _run_seven_zip_extract(image: Path, stage: Path,
                           symlink_count: int) -> None:
    """Extract without hiding 7z's conservative symlink behavior.

    Ubuntu 23.01 refuses some in-image relative symlinks such as
    ``usr/bin/[ -> ../../bin/busybox`` even though they remain below the
    extraction root.  The only tolerated failures are those declared symlink
    records; all other diagnostics remain fatal.
    """
    if not SEVEN_ZIP.is_file():
        raise RepairError("preparation_failed",
                          f"Route-A intake requires {SEVEN_ZIP} in Ubuntu")
    try:
        completed = subprocess.run(
            [str(SEVEN_ZIP), "x", "-y", f"-o{stage}", str(image)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=SEVEN_ZIP_TIMEOUT_SECONDS,
            check=False,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepairError("preparation_failed", f"Cannot execute 7z: {exc}") from exc
    if completed.returncode == 0:
        return
    errors = [line for line in completed.stderr.splitlines() if line.strip()]
    ignored = [line for line in errors
               if line.startswith("ERROR: Dangerous symbolic link path was ignored : ")]
    if (completed.returncode != 2 or len(errors) != len(ignored)
            or not ignored or len(ignored) > symlink_count):
        detail = "\n".join(errors[-10:]).strip()
        raise RepairError("preparation_failed",
                          f"7z extraction failed with exit {completed.returncode}: {detail}")


def parse_seven_zip_listing(text: str) -> dict[str, dict]:
    """Parse `7z l -ba -slt` records without trusting paths."""
    records: dict[str, dict] = {}
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                _add_listing_record(records, current)
                current = {}
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        current[key.strip()] = value.strip()
    if current:
        _add_listing_record(records, current)
    return records


def _add_listing_record(records: dict[str, dict], values: dict[str, str]) -> None:
    if "Path" not in values:
        return
    path = _safe_archive_path(values["Path"])
    if path in records:
        raise RepairError("preparation_failed", f"Duplicate archive path: {path}")
    size_text = values.get("Size", "0") or "0"
    try:
        size = int(size_text)
    except (TypeError, ValueError) as exc:
        raise RepairError("preparation_failed",
                          f"Invalid archive size for {path}: {size_text!r}") from exc
    if size < 0:
        raise RepairError("preparation_failed", f"Negative archive size for {path}")
    records[path] = {"size": size, "attributes": values.get("Attributes", "")}
    link = values.get("Symbolic Link", "")
    if link:
        records[path]["symbolic_link"] = link


def _validate_archive_limits(records: dict[str, dict]) -> int:
    if not 1 <= len(records) <= MAX_FILES:
        raise RepairError("preparation_failed",
                          f"Archive entry count must be 1..{MAX_FILES}")
    total = sum(item["size"] for item in records.values())
    if total > MAX_TOTAL_BYTES:
        raise RepairError("preparation_failed",
                          f"Archive logical size exceeds {MAX_TOTAL_BYTES} bytes")
    return total


def _file_list_paths(path: Path) -> set[str]:
    try:
        raw = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise RepairError("preparation_failed",
                          f"Cannot read FirmAE fileList: {exc}") from exc
    if len(raw.encode("utf-8")) > MAX_FILE_LIST_BYTES:
        raise RepairError("preparation_failed", "FirmAE fileList exceeds size limit")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) > MAX_FILES:
        raise RepairError("preparation_failed", "FirmAE fileList exceeds entry limit")
    result: set[str] = set()
    for line in lines:
        if line == ".":
            continue
        result.add(_safe_archive_path(line))
    return result


def _scan_materialized(root: Path) -> dict:
    file_count = 0
    total_bytes = 0
    symlink_count = 0
    directory_count = 0

    def visit(directory: Path) -> None:
        nonlocal file_count, total_bytes, symlink_count, directory_count
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise RepairError("preparation_failed",
                              f"Cannot scan materialized rootfs: {exc}") from exc
        for entry in entries:
            relative = (Path(entry.path).relative_to(root)).as_posix()
            _safe_archive_path(relative)
            if entry.is_symlink():
                symlink_count += 1
                if symlink_count > MAX_SYMLINKS:
                    raise RepairError("preparation_failed",
                                      f"Materialized symlink count exceeds {MAX_SYMLINKS}")
                target = os.readlink(entry.path)
                target_path = Path(target)
                if target_path.is_absolute():
                    raise RepairError("preparation_failed",
                                      f"Absolute symlink is not allowed: {relative}")
                resolved = (Path(entry.path).parent / target_path).resolve(strict=False)
                if root.resolve() not in resolved.parents and resolved != root.resolve():
                    raise RepairError("preparation_failed",
                                      f"Symlink escapes materialized rootfs: {relative}")
                continue
            if entry.is_dir(follow_symlinks=False):
                directory_count += 1
                visit(Path(entry.path))
                continue
            if not entry.is_file(follow_symlinks=False):
                raise RepairError("preparation_failed",
                                  f"Unsupported non-regular archive entry: {relative}")
            metadata = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & (stat.S_ISUID | stat.S_ISGID):
                raise RepairError("preparation_failed",
                                  f"Setuid/setgid mode is not allowed: {relative}")
            if metadata.st_nlink != 1:
                raise RepairError("preparation_failed",
                                  f"Hard-linked archive entry is not allowed: {relative}")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise RepairError("preparation_failed",
                                  "Materialized rootfs exceeds file or byte limit")

    visit(root)
    return {
        "file_count": file_count,
        "directory_count": directory_count,
        "symlink_count": symlink_count,
        "total_bytes": total_bytes,
    }


def _recreate_declared_symlinks(root: Path,
                                records: dict[str, dict]) -> list[dict]:
    normalizations: list[dict] = []
    for relative, item in records.items():
        target = item.get("symbolic_link")
        if target is None:
            continue
        if not isinstance(target, str) or not target or "\x00" in target:
            raise RepairError("preparation_failed",
                              f"Unsafe symlink target for {relative}")
        original_target = target
        target_path = Path(target)
        if target_path.is_absolute():
            inside = _safe_archive_path(target.lstrip("/"))
            target = os.path.relpath(root.resolve() / inside,
                                     (root / relative).parent.resolve())
            target_path = Path(target)
            normalizations.append({
                "path": relative,
                "original": original_target,
                "materialized": target,
                "reason": "chroot-equivalent-relative-link",
            })
        link = root / relative
        resolved = (link.parent / target_path).resolve(strict=False)
        if root.resolve() not in resolved.parents and resolved != root.resolve():
            raise RepairError("preparation_failed",
                              f"Archive symlink escapes rootfs: {relative}")
        if link.is_symlink():
            existing = os.readlink(link)
            if existing == target:
                continue
            if Path(existing).is_absolute():
                resolved_existing = link.resolve(strict=False)
                if root.resolve() not in resolved_existing.parents:
                    raise RepairError("preparation_failed",
                                      f"Extracted symlink escapes rootfs: {relative}")
                link.unlink()
            else:
                if existing != original_target:
                    raise RepairError("preparation_failed",
                                      f"Unexpected extracted symlink: {relative}")
                link.unlink()
        if link.exists():
            raise RepairError("preparation_failed",
                              f"Symlink destination is not a link: {relative}")
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
    return normalizations


def _validate_target(root: Path, target: str) -> tuple[str, dict]:
    relative = _safe_archive_path(target)
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise RepairError("preparation_failed",
                          "Materialized target must be a regular file")
    facts = _architecture_facts(path)
    if facts.get("candidate") != MIPS32BE:
        reason = facts.get("reason") or "target is not registered MIPS32BE o32"
        raise RepairError("unsupported_architecture",
                          f"Materialized target is unsupported: {reason}")
    return _sha256(path), facts["elf"]


def materialize_rootfs(image: Path, file_list: Path, target: str,
                       output_root: Path) -> tuple[Path, dict]:
    output_root.mkdir(parents=True, exist_ok=False)
    stage = output_root.parent / f".{output_root.name}.stage-{os.getpid()}"
    if stage.exists():
        raise RepairError("preparation_failed", "Rootfs staging directory already exists")
    try:
        listing_text = _run_seven_zip(
            ["l", "-ba", "-slt", str(image)], timeout=120)
        records = parse_seven_zip_listing(listing_text)
        archive_bytes = _validate_archive_limits(records)
        file_paths = _file_list_paths(file_list)
        target_path = _safe_archive_path(target)
        if target_path not in records:
            raise RepairError("preparation_failed",
                              "image.raw does not contain the configured target")
        if target_path not in file_paths:
            raise RepairError("preparation_failed",
                              "FirmAE fileList does not contain the configured target")
        stage.mkdir(mode=0o700)
        symlink_count = sum(1 for item in records.values()
                            if "symbolic_link" in item)
        _run_seven_zip_extract(image, stage, symlink_count)
        normalized_symlinks = _recreate_declared_symlinks(stage, records)
        facts = _scan_materialized(stage)
        if facts["file_count"] + facts["directory_count"] + facts["symlink_count"] \
                != len(records):
            raise RepairError("preparation_failed",
                              "Materialized entry count does not match 7z listing")
        target_sha256, _ = _validate_target(stage, target_path)
        os.replace(stage, output_root)
        return output_root, {
            **facts,
            "archive_logical_bytes": archive_bytes,
            "target_sha256": target_sha256,
            "normalized_absolute_symlinks": normalized_symlinks,
        }
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        if output_root.exists() and output_root.is_dir():
            shutil.rmtree(output_root, ignore_errors=True)
        raise


def _validate_triage_run(cfg: dict, triage_run: Path) -> tuple[dict, dict, Path, Path]:
    if not triage_run.is_dir():
        raise RepairError("preparation_failed",
                          f"FirmAE triage run not found: {triage_run}")
    report = _read_json(triage_run / "report.json", "FirmAE triage report")
    if report.get("schema") != "triage-report-v1" or \
            report.get("kind") != "firmware-triage":
        raise RepairError("preparation_failed", "Unexpected FirmAE triage report schema")
    if report.get("backend") != "firmae":
        raise RepairError("preparation_failed", "Route-A intake requires backend=firmae")
    if report.get("mode") != "analysis":
        raise RepairError("preparation_failed", "Route-A intake requires mode=analysis")
    if report.get("status") != "diagnostics_generated":
        raise RepairError("preparation_failed",
                          f"FirmAE triage run is not successful: {report.get('status')!r}")
    execution = report.get("execution")
    firmware_info = report.get("firmware")
    if not isinstance(execution, dict) or execution.get("returncode") != 0:
        raise RepairError("preparation_failed", "FirmAE triage execution did not succeed")
    if not isinstance(firmware_info, dict) or firmware_info.get("original_unchanged") is not True:
        raise RepairError("preparation_failed",
                          "FirmAE input changed during triage; refuse intake")
    run_id = report.get("run_id")
    if not isinstance(run_id, str) or not run_id or Path(run_id).name != run_id:
        raise RepairError("preparation_failed", "FirmAE triage run_id is invalid")
    configured_output = Path(cfg["triage"]["output_root"]).resolve()
    if triage_run.parent != configured_output or triage_run.name != run_id:
        raise RepairError("preparation_failed",
                          "FirmAE triage run is outside triage.output_root")
    raw_path = triage_run / "raw" / "firmae-report-v1.json"
    raw = _read_json(raw_path, "FirmAE raw report")
    if raw.get("schema") != FIRMAE_REPORT_SCHEMA:
        raise RepairError("preparation_failed", "Unexpected FirmAE raw report schema")
    work_root = Path(cfg["triage"]["firmae"]["work_root"]).resolve()
    expected_work_run = work_root / run_id
    firmware_copy = execution.get("firmware_copy")
    if not isinstance(firmware_copy, str):
        raise RepairError("preparation_failed", "FirmAE execution lacks firmware_copy")
    if Path(firmware_copy).resolve().parent != expected_work_run:
        raise RepairError("preparation_failed",
                          "FirmAE artifacts are not in the configured work run")
    return report, raw, raw_path, expected_work_run / "artifacts"


def _validate_artifacts(raw: dict, artifact_root: Path) -> tuple[dict, Path]:
    manifest_path = artifact_root / "artifact-manifest.json"
    manifest = _read_json(manifest_path, "FirmAE artifact manifest")
    if manifest.get("schema") != ARTIFACT_SCHEMA:
        raise RepairError("preparation_failed", "Unexpected FirmAE artifact schema")
    if manifest.get("transformed_image") is not True or \
            not isinstance(manifest.get("firmware_iid"), int):
        raise RepairError("preparation_failed", "Invalid FirmAE artifact identity")
    entries = manifest.get("artifacts")
    if not isinstance(entries, dict) or set(entries) != set(REQUIRED_ARTIFACTS):
        raise RepairError("preparation_failed",
                          "FirmAE artifact manifest has an unexpected file set")
    expected_names = set(REQUIRED_ARTIFACTS) | {"artifact-manifest.json"}
    try:
        actual_names = {entry.name for entry in artifact_root.iterdir()}
    except OSError as exc:
        raise RepairError("preparation_failed",
                          f"Cannot inspect FirmAE artifacts: {exc}") from exc
    if actual_names != expected_names:
        raise RepairError("preparation_failed",
                          "FirmAE artifact directory contains unexpected entries")
    for name in REQUIRED_ARTIFACTS:
        item = entries[name]
        if not isinstance(item, dict):
            raise RepairError("preparation_failed", f"Invalid artifact entry: {name}")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RepairError("preparation_failed", f"Invalid artifact SHA256: {name}")
        if type(size) is not int or size < 0:
            raise RepairError("preparation_failed", f"Invalid artifact size: {name}")
        path = artifact_root / name
        if path.is_symlink() or not path.is_file():
            raise RepairError("preparation_failed", f"Unsafe artifact: {name}")
        metadata = path.stat()
        if metadata.st_size != size or _sha256(path) != digest:
            raise RepairError("preparation_failed",
                              f"FirmAE artifact identity mismatch: {name}")
    raw_artifacts = raw.get("artifacts")
    if not isinstance(raw_artifacts, dict) or \
            raw_artifacts.get("schema") != ARTIFACT_SCHEMA or \
            raw_artifacts.get("files") != entries or \
            raw_artifacts.get("firmware_iid") != manifest["firmware_iid"]:
        raise RepairError("preparation_failed",
                          "FirmAE report and artifact manifest disagree")
    image = artifact_root / "image.raw"
    if image.stat().st_size > MAX_IMAGE_BYTES:
        raise RepairError("preparation_failed", "FirmAE image.raw exceeds size limit")
    return manifest, image


def _text_artifact(artifact_root: Path, name: str) -> str:
    try:
        value = (artifact_root / name).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise RepairError("preparation_failed",
                          f"Cannot read FirmAE artifact {name}: {exc}") from exc
    if not value:
        raise RepairError("preparation_failed", f"FirmAE artifact {name} is empty")
    return value


def _validate_generated_case(path: Path) -> dict:
    try:
        return load_config(path)
    except RepairError:
        raise
    except (OSError, ValueError, KeyError) as exc:
        raise RepairError("preparation_failed",
                          f"Generated case is invalid: {exc}") from exc


def _write_generated_case(cfg: dict, output_root: Path, rootfs: Path,
                          raw_report: Path, run_id: str) -> Path:
    generated = copy.deepcopy({key: value for key, value in cfg.items()
                               if key in {"project", "poc", "tests", "firmware",
                                          "triage", "build", "model", "repair",
                                          "validation", "execution", "output"}})
    generated["firmware"]["rootfs"] = str(rootfs)
    generated["output"]["directory"] = str(output_root / "repair-results")
    # Never persist a key in the generated case.  Omitting the key (instead of
    # writing null) also lets the software-level model layer keep supplying it.
    generated["model"].pop("api_key", None)
    diagnostics = generated["firmware"].setdefault("diagnostics", {})
    imports = diagnostics.setdefault("imports", [])
    item = {
        "id": f"firmae-intake-{run_id}",
        "path": str(raw_report),
        "backend": "firmae",
        "format": FIRMAE_REPORT_SCHEMA,
        "required": True,
    }
    if not any(isinstance(existing, dict) and existing.get("path") == item["path"]
               for existing in imports):
        imports.append(item)
    case_path = output_root / "case.generated.yaml"
    case_path.write_text(yaml.safe_dump(generated, sort_keys=False, allow_unicode=True),
                         encoding="utf-8")
    _validate_generated_case(case_path)
    return case_path


def _prepare_output_root(value: Path | str, protected: tuple[Path, ...]) -> Path:
    output_root = Path(value).resolve()
    if output_root.exists():
        if not output_root.is_dir():
            raise RepairError("preparation_failed",
                              f"Intake output root is not a directory: {output_root}")
        if any(output_root.iterdir()):
            raise RepairError("preparation_failed",
                              f"Intake output root must be empty: {output_root}")
    else:
        output_root.mkdir(parents=True)
    for path in protected:
        if _contains_or_equals(output_root, path):
            raise RepairError("preparation_failed",
                              "Intake output root must not contain triage/work inputs")
    return output_root


def run_firmae_intake(cfg: dict, triage_run: Path | str,
                      output_root: Path | str) -> dict:
    """Materialize one successful FirmAE analysis run and generate a case."""
    triage_run = Path(triage_run).resolve()
    report, raw, raw_report, artifact_root = _validate_triage_run(cfg, triage_run)
    profile = resolve_profile(cfg["firmware"]["adapter"])
    manifest, image = _validate_artifacts(raw, artifact_root)
    architecture = _text_artifact(artifact_root, "architecture")
    brand = _text_artifact(artifact_root, "brand")
    results = raw.get("results")
    firmware_sha256 = raw.get("input", {}).get("firmware_sha256")
    iid = raw.get("runs", {}).get("firmware_iid")
    if architecture != "mipseb" or (isinstance(results, dict) and
                                    results.get("architecture") != "mipseb"):
        raise RepairError("unsupported_architecture",
                          "Route-A phase 1 only supports FirmAE architecture mipseb")
    if brand != "dlink":
        raise RepairError("preparation_failed",
                          "Route-A phase 1 only supports brand dlink")
    if not isinstance(firmware_sha256, str) or not _SHA256.fullmatch(firmware_sha256):
        raise RepairError("preparation_failed", "FirmAE raw report lacks firmware SHA256")
    if iid != manifest["firmware_iid"]:
        raise RepairError("preparation_failed", "FirmAE IID identity mismatch")
    if report.get("firmware", {}).get("sha256") != firmware_sha256:
        raise RepairError("preparation_failed", "FirmAE firmware SHA mismatch")

    work_root = Path(cfg["triage"]["firmae"]["work_root"]).resolve()
    output_root = _prepare_output_root(
        output_root, (triage_run, work_root, artifact_root))
    try:
        work = output_root / "work"
        work.mkdir()
        rootfs, materialized = materialize_rootfs(
            image, artifact_root / "fileList", cfg["firmware"]["target"],
            work / "rootfs-firmae")
        target_sha256, elf = _validate_target(rootfs, cfg["firmware"]["target"])
        if target_sha256 != materialized["target_sha256"]:
            raise RepairError("preparation_failed", "Target SHA changed during intake")
        case_path = _write_generated_case(
            cfg, output_root, rootfs, raw_report, report["run_id"])
        image_entry = manifest["artifacts"]["image.raw"]
        result = {
            "schema": INTAKE_SCHEMA,
            "status": "intake_ready",
            "source_firmware": {"sha256": firmware_sha256, "brand": brand},
            "firmae": {
                "triage_run": str(triage_run),
                "run_id": report["run_id"],
                "iid": iid,
                "architecture": architecture,
                "image": {
                    "sha256": image_entry["sha256"],
                    "size": image_entry["size"],
                    "origin": "firmae-transformed-image",
                },
            },
            "materialized_rootfs": {
                "path": str(rootfs),
                "origin": "firmae-transformed-image",
                "not_original_pristine_rootfs": True,
                **{key: value for key, value in materialized.items()
                   if key != "target_sha256"},
            },
            "target": {
                "path": cfg["firmware"]["target"],
                "sha256": target_sha256,
                "elf": elf,
                "architecture": MIPS32BE,
            },
            "runtime": {
                "name": profile.runtime,
                "authoritative_verification": True,
                "architecture": MIPS32BE,
                "protocol": cfg["firmware"].get(
                    "protocol", profile.protocol),
                "supported_protocols": list(profile.supported_protocols()),
                "capabilities": runtime_capability_report(
                    profile.runtime)["capabilities"],
            },
            "generated_case": str(case_path),
            "diagnostic_import": str(raw_report),
            "execution_policy": "no image scripts executed",
        }
        save_json(work / "intake-manifest.json", result)
        return result
    except Exception:
        # Keep the new output root inspectable, but remove incomplete managed
        # subtrees so reruns cannot mistake them for a complete case.
        rootfs_candidate = output_root / "work" / "rootfs-firmae"
        if rootfs_candidate.exists():
            shutil.rmtree(rootfs_candidate, ignore_errors=True)
        raise
