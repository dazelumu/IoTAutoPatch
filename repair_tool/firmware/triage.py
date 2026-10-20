"""Firmware diagnostics triage.

Import mode deliberately does not launch FirmAE/Greenhouse and does not call
the repair model.  The explicit FirmAE/Greenhouse execute entry points below
are controlled by the controller, never by the model, and remain
diagnostic-only.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from ..config import RepairError
from ..storage import sha
from .diagnostics_intake import (FIRMAE_REPORT_SCHEMA, GREENHOUSE_REPORT_SCHEMA,
                                 copy_report_snapshot, load_report)
from .diagnostics_ledger import DiagnosticsLedger


_FORMATS = {
    "firmae": FIRMAE_REPORT_SCHEMA,
    "greenhouse": GREENHOUSE_REPORT_SCHEMA,
}


def _output_root(cfg: dict, config_path: Path) -> Path:
    value = cfg.get("triage", {}).get("output_root")
    if value is None or value == "":
        return (config_path.parent / "triage-results").resolve()
    if not isinstance(value, str):
        raise RepairError("preparation_failed", "triage.output_root must be a path")
    path = Path(value)
    return (path if path.is_absolute() else config_path.parent / path).resolve()


def _contains_or_equals(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_output_layout(cfg: dict, output_root: Path) -> None:
    firmware = cfg.get("firmware", {})
    rootfs_value = firmware.get("rootfs") if isinstance(firmware, dict) else None
    writable = [output_root.resolve()]
    if isinstance(rootfs_value, str) and rootfs_value:
        rootfs = Path(rootfs_value).resolve()
        protected = [rootfs]
        for path in writable:
            if any(_contains_or_equals(path, item) for item in protected):
                raise RepairError(
                    "preparation_failed",
                    "Triage directories must not contain or be inside firmware.rootfs")
    else:
        protected = []
    triage = cfg.get("triage", {})
    if not isinstance(triage, dict):
        return
    for backend in ("firmae", "greenhouse"):
        values = triage.get(backend, {})
        if not isinstance(values, dict):
            continue
        value = values.get("work_root")
        if not isinstance(value, str) or not value:
            continue
        path = Path(value)
        work_root = (path if path.is_absolute()
                     else Path(cfg.get("config_path", ".")).resolve().parent / path).resolve()
        if any(_contains_or_equals(work_root, item) for item in protected):
            raise RepairError(
                "preparation_failed",
                "Backend work directories must not contain or be inside firmware.rootfs")
        for previous in writable:
            if _contains_or_equals(previous, work_root):
                raise RepairError(
                    "preparation_failed",
                    "Triage output and backend work directories must not contain each other")
        writable.append(work_root)


def _verified_target_sha256(cfg: dict) -> str | None:
    firmware = cfg.get("firmware", {})
    if not isinstance(firmware, dict):
        return None
    rootfs_value = firmware.get("rootfs")
    target = firmware.get("target")
    if not isinstance(rootfs_value, str) or not rootfs_value \
            or not isinstance(target, str) or not target:
        return None
    rootfs = Path(rootfs_value).resolve()
    if target.startswith("/") or ".." in Path(target).parts:
        raise RepairError("preparation_failed",
                          "firmware.target must be a rootfs-relative path")
    configured = rootfs / target
    resolved = configured.resolve()
    if (not configured.is_file() or configured.is_symlink()
            or not resolved.is_relative_to(rootfs)):
        raise RepairError("preparation_failed",
                          "firmware.target must be an existing regular file in rootfs")
    try:
        return sha(resolved)
    except OSError as exc:
        raise RepairError("preparation_failed",
                          f"Cannot hash firmware.target {resolved}: {exc}") from exc


def _redact_config(cfg: dict) -> dict:
    redacted = copy.deepcopy(cfg)
    model = redacted.get("model", {})
    if isinstance(model, dict):
        model["api_key"] = "<redacted>" if model.get("api_key") else None
        if model.get("api_key_env"):
            model["api_key_env"] = "<redacted-env-name>"
    diagnostics = redacted.get("firmware", {}).get("diagnostics", {})
    if isinstance(diagnostics, dict):
        for item in diagnostics.get("imports", []):
            if isinstance(item, dict):
                item["path"] = "<case-relative-or-absolute-path>"
    triage = redacted.get("triage", {})
    if isinstance(triage, dict):
        for backend in ("firmae", "greenhouse"):
            values = triage.get(backend, {})
            if isinstance(values, dict):
                values["executable"] = "<configured-or-null>"
                values["work_root"] = "<configured-or-null>"
        if triage.get("output_root") is not None:
            triage["output_root"] = "<configured-or-null>"
    return redacted


def _imports(cfg: dict, backend_filter: str | None) -> list[dict]:
    diagnostics = cfg.get("firmware", {}).get("diagnostics", {})
    imports = diagnostics.get("imports", [])
    if not isinstance(imports, list):
        raise RepairError("preparation_failed", "firmware.diagnostics.imports must be a list")
    result = []
    for index, item in enumerate(imports):
        label = f"firmware.diagnostics.imports[{index}]"
        required = {"id", "path", "backend", "format", "required"}
        optional = {"allow_unbound_details"}
        if not isinstance(item, dict) or set(item) - required - optional:
            raise RepairError("preparation_failed", f"Invalid {label}")
        missing = required - set(item)
        if missing:
            raise RepairError("preparation_failed",
                              f"{label} missing fields: {sorted(missing)}")
        if item["backend"] not in _FORMATS:
            raise RepairError("preparation_failed",
                              f"{label}.backend must be firmae or greenhouse")
        if item["format"] != _FORMATS[item["backend"]]:
            raise RepairError("preparation_failed",
                              f"{label}.format does not match backend")
        if not isinstance(item["required"], bool):
            raise RepairError("preparation_failed", f"{label}.required must be boolean")
        if "allow_unbound_details" in item and not isinstance(
                item["allow_unbound_details"], bool):
            raise RepairError("preparation_failed",
                              f"{label}.allow_unbound_details must be boolean")
        if backend_filter is None or item["backend"] == backend_filter:
            result.append(dict(item))
    return result


def run_import_triage(cfg: dict, *, backend: str | None = None) -> dict:
    """Import configured reports and return an in-memory triage report."""
    if backend is not None and backend not in _FORMATS:
        raise RepairError("preparation_failed",
                          "triage backend must be firmae or greenhouse")
    config_path = Path(cfg.get("config_path", ".")).resolve()
    configured = _imports(cfg, backend)
    diagnostics = cfg.get("firmware", {}).get("diagnostics", {})
    if not isinstance(diagnostics, dict) or not isinstance(
            diagnostics.get("expose_to_model", False), bool):
        raise RepairError("preparation_failed",
                          "firmware.diagnostics.expose_to_model must be boolean")
    max_page_size = diagnostics.get("max_page_size", 20)
    max_record_bytes = diagnostics.get("max_record_bytes", 32768)
    if type(max_page_size) is not int or not 1 <= max_page_size <= 100:
        raise RepairError("preparation_failed",
                          "firmware.diagnostics.max_page_size must be 1..100")
    if type(max_record_bytes) is not int or not 1 <= max_record_bytes <= 1048576:
        raise RepairError("preparation_failed",
                          "firmware.diagnostics.max_record_bytes must be 1..1048576")

    output_root = _output_root(cfg, config_path)
    _validate_output_layout(cfg, output_root)
    verified_target_sha256 = _verified_target_sha256(cfg)
    prepared: list[dict] = []
    seen_raw_names: set[str] = set()
    for item in configured:
        source = Path(item["path"])
        if not source.is_absolute():
            source = config_path.parent / source
        source = source.resolve()
        raw_name = source.name
        if raw_name in seen_raw_names:
            raise RepairError("preparation_failed",
                              f"Duplicate raw report filename: {raw_name}")
        seen_raw_names.add(raw_name)
        _, records, metadata = load_report(
            source, required=item["required"],
            verified_target_sha256=verified_target_sha256)
        prepared.append({"item": item, "source": source, "records": records,
                         "metadata": metadata})

    run_id = f"triage-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 10000:04d}"
    output = output_root / run_id
    if output.exists():
        raise RepairError("preparation_failed", f"Triage output already exists: {output}")
    output.mkdir(parents=True)
    ledger = DiagnosticsLedger(output, run_id=run_id)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    imported: list[dict] = []
    missing_optional: list[dict] = []

    for prepared_item in prepared:
        item = prepared_item["item"]
        source = prepared_item["source"]
        records = prepared_item["records"]
        raw_path = raw_dir / source.name
        if source.is_file():
            copy_report_snapshot(
                source, raw_path,
                source_sha256=prepared_item["metadata"]["source_sha256"],
                source_size=prepared_item["metadata"]["source_size"])
        else:
            if item["required"]:
                raise RepairError(
                    "preparation_failed",
                    f"Required diagnostics report disappeared: {source}")
            missing_optional.append({"id": item["id"], "backend": item["backend"]})
            imported.append({"id": item["id"], "backend": item["backend"],
                             "records": 0})
            continue
        ledger.register_import({
            "import_id": item["id"], "backend": item["backend"],
            "format": item["format"], **prepared_item["metadata"],
        })
        for record in records:
            ledger.add(record)
        decision = "exposed" if diagnostics["expose_to_model"] else "filtered"
        for record in ledger.records[-len(records):] if records else []:
            ledger.append_decision(record["id"], decision,
                                   "import-only diagnostics ledger")
        imported.append({"id": item["id"], "backend": item["backend"],
                         "records": len(records)})

    report = {
        "schema": "triage-report-v1",
        "kind": "firmware-triage",
        "status": "diagnostics_only",
        "mode": "import-only",
        "run_id": run_id,
        "backend_filter": backend,
        "imported": imported,
        "missing_optional": missing_optional,
        "counts": ledger.document()["counts"],
        "output": str(output),
    }
    (output / "config-redacted.json").write_text(
        json.dumps(_redact_config(cfg), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def run_firmae_triage(cfg: dict, firmware: Path | str, *,
                      mode: str = "compatibility", brand: str = "unknown") -> dict:
    """Execute diagnostic-only FirmAE triage and persist its observations."""
    from .triage_adapters.firmae import FirmAEAdapter

    adapter = FirmAEAdapter.from_config(cfg)
    config_path = Path(cfg.get("config_path", ".")).resolve()
    firmware_path = Path(firmware)
    if not firmware_path.is_absolute():
        firmware_path = config_path.parent / firmware_path
    firmware_path = firmware_path.resolve()
    adapter.validate_execution(firmware_path, mode, brand)

    output_root = _output_root(cfg, config_path)
    _validate_output_layout(cfg, output_root)
    run_id = f"triage-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 10000:04d}"
    output = output_root / run_id
    if output.exists():
        raise RepairError("preparation_failed", f"Triage output already exists: {output}")
    output.mkdir(parents=True)
    (output / "config-redacted.json").write_text(
        json.dumps(_redact_config(cfg), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return adapter.execute(firmware_path, output=output, run_id=run_id,
                           mode=mode, brand=brand)


def run_greenhouse_triage(cfg: dict, firmware: Path | str, *,
                          service: str, mode: str = "rehost",
                          replay_input: Path | str | None = None,
                          fuzz_seconds: int | None = None) -> dict:
    """Execute diagnostic-only Greenhouse triage and persist observations."""
    from .triage_adapters.greenhouse import GreenhouseAdapter

    adapter = GreenhouseAdapter.from_config(cfg)
    config_path = Path(cfg.get("config_path", ".")).resolve()
    firmware_path = Path(firmware)
    if not firmware_path.is_absolute():
        firmware_path = config_path.parent / firmware_path
    firmware_path = firmware_path.resolve()
    replay_path: Path | None = None
    if replay_input is not None:
        replay_path = Path(replay_input)
        if not replay_path.is_absolute():
            replay_path = config_path.parent / replay_path
        replay_path = replay_path.resolve()
    adapter.validate_execution(firmware_path, service=service, mode=mode,
                               replay_input=replay_path,
                               fuzz_seconds=fuzz_seconds)

    output_root = _output_root(cfg, config_path)
    _validate_output_layout(cfg, output_root)
    run_id = f"triage-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 10000:04d}"
    output = output_root / run_id
    if output.exists():
        raise RepairError("preparation_failed",
                          f"Triage output already exists: {output}")
    output.mkdir(parents=True)
    (output / "config-redacted.json").write_text(
        json.dumps(_redact_config(cfg), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return adapter.execute(firmware_path, output=output, run_id=run_id,
                           service=service, mode=mode,
                           replay_input=replay_path,
                           fuzz_seconds=fuzz_seconds)
