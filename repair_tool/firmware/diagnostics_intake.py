"""Validation and normalization for external firmware diagnostic reports.

External FirmAE/Greenhouse reports are untrusted diagnostic input.  This module
converts a bounded set of structured fields into ``diagnostic-record-v1``; it
never executes commands found in a report and never promotes a suggestion to a
patch site.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

from ..config import RepairError
from ..storage import sha


DIAGNOSTIC_RECORD_SCHEMA = "diagnostic-record-v1"
FIRMAE_REPORT_SCHEMA = "firmae-report-v1"
GREENHOUSE_REPORT_SCHEMA = "greenhouse-report-v1"

BACKENDS = {"firmae", "greenhouse"}
REPORT_SCHEMAS = {FIRMAE_REPORT_SCHEMA, GREENHOUSE_REPORT_SCHEMA}
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_FACTS_DEPTH = 16
DIAGNOSTIC_KINDS = {
    "architecture_observation", "service_observation", "boot_observation",
    "request_observation", "crash_context", "crash_cluster",
    "coverage_observation", "static_analysis", "nday_correlation",
    "external_patch_suggestion", "tool_intervention",
}
CONFIDENCE_LEVELS = {"observed", "derived", "heuristic", "external_claim"}
BINDING_STATUSES = {"bound", "related", "unbound"}

_DIAGNOSTIC_ID = re.compile(r"^d-\d{6}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REDACTED_SECRET = "[REDACTED]"
_REDACTED_PATH = "[REDACTED_HOST_PATH]"
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|token|secret|authorization|cookie|passwd|private[_-]?key)",
    re.I)
_SECRET_VALUE = re.compile(
    r"(?:api[_-]?key|token|secret|authorization|cookie)"
    r"\s*[:=]\s*[^\s,;}\]]+",
    re.I)
_HOST_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/][^\r\n\t\"']*|\\\\[^\r\n\t\"']+"
    r"|/(?:home|mnt|Users|root|tmp|var|opt|etc|proc|dev)/[^\r\n\t\"']*)"
)
_TOP_LEVEL_KEYS = {
    "schema", "id", "run_id", "backend", "backend_version", "kind",
    "observed_at", "binding", "facts", "confidence", "authoritative",
    "raw", "redactions",
}
_BINDING_KEYS = {
    "firmware_sha256", "rootfs_sha256", "original_target_sha256",
    "transformed_target_sha256", "status",
}
_RAW_KEYS = {"file", "sha256", "pointer"}


def _object(value: Any, label: str, keys: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise RepairError("preparation_failed", f"{label} must be an object")
    if keys is not None and set(value) - keys:
        unexpected = sorted(set(value) - keys)
        raise RepairError("preparation_failed",
                          f"Unexpected {label} fields: {unexpected}")
    return value


def _text(value: Any, label: str, *, maximum: int = 1000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RepairError("preparation_failed",
                          f"{label} must be 1..{maximum} characters")
    return value


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RepairError("preparation_failed", f"{label} must be a lowercase SHA256")
    return value


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.fullmatch(value))


def _safe_raw_file(value: Any) -> str:
    value = _text(value, "diagnostic raw file", maximum=255)
    if "\\" in value or Path(value).is_absolute() or ".." in Path(value).parts:
        raise RepairError("preparation_failed",
                          "diagnostic raw file must be a safe relative path")
    return value


def _safe_raw_pointer(value: Any) -> str:
    value = _text(value, "diagnostic raw pointer", maximum=255)
    if "\\" in value or ".." in value.split("/") or _HOST_PATH.search(value):
        raise RepairError("preparation_failed",
                          "diagnostic raw pointer must be a safe report pointer")
    return value


def _field_path(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else str(key)


def _redact_string(value: str) -> tuple[str, str | None]:
    secret = _SECRET_VALUE.search(value)
    if secret is not None:
        return f"{value[:secret.start()]}[REDACTED]", "secret_value"
    redacted = _HOST_PATH.sub(_REDACTED_PATH, value)
    if redacted != value:
        return redacted, "host_path"
    return value, None


def sanitize_facts(value: Any, *, prefix: str = "facts",
                   depth: int = 0) -> tuple[Any, list[dict]]:
    """Remove common secret/host-path strings while preserving diagnostic facts."""
    if depth > MAX_FACTS_DEPTH:
        raise RepairError("preparation_failed",
                          f"Diagnostic facts exceed depth {MAX_FACTS_DEPTH}")
    redactions: list[dict] = []
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RepairError("preparation_failed", "Diagnostic fact keys must be strings")
            path = _field_path(prefix, key)
            if _SECRET_KEY.search(key):
                if item not in (None, ""):
                    redactions.append({"field": path, "reason": "secret_key"})
                result[key] = _REDACTED_SECRET if item not in (None, "") else item
                continue
            sanitized, nested = sanitize_facts(item, prefix=path, depth=depth + 1)
            result[key] = sanitized
            redactions.extend(nested)
        return result, redactions
    if isinstance(value, list):
        items: list[Any] = []
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]"
            sanitized, nested = sanitize_facts(item, prefix=path, depth=depth + 1)
            items.append(sanitized)
            redactions.extend(nested)
        return items, redactions
    if isinstance(value, str):
        sanitized, reason = _redact_string(value)
        if reason is not None:
            redactions.append({"field": prefix, "reason": reason})
        return sanitized, redactions
    if value is None or isinstance(value, (bool, int, float)):
        return value, redactions
    raise RepairError("preparation_failed", "Diagnostic facts must be JSON values")


def validate_diagnostic_record(record: Any) -> dict:
    """Validate and conservatively sanitize one diagnostic record."""
    record = _object(record, "diagnostic record", _TOP_LEVEL_KEYS)
    required = _TOP_LEVEL_KEYS - {"redactions"}
    unexpected = sorted(set(record) - _TOP_LEVEL_KEYS)
    if unexpected:
        raise RepairError("preparation_failed", "Diagnostic record has unexpected fields")
    missing = sorted(required - set(record))
    if missing:
        raise RepairError("preparation_failed",
                          f"Diagnostic record missing fields: {missing}")
    if record["schema"] != DIAGNOSTIC_RECORD_SCHEMA:
        raise RepairError("preparation_failed", "Unsupported diagnostic record schema")
    diagnostic_id = _text(record["id"], "diagnostic id")
    if not _DIAGNOSTIC_ID.fullmatch(diagnostic_id):
        raise RepairError("preparation_failed", "Diagnostic id must match d-NNNNNN")
    _text(record["run_id"], "diagnostic run_id", maximum=255)
    if not isinstance(record["backend"], str) or record["backend"] not in BACKENDS:
        raise RepairError("preparation_failed",
                          f"Unsupported diagnostic backend: {record['backend']}")
    _text(record["backend_version"], "diagnostic backend version", maximum=128)
    if not isinstance(record["kind"], str) or record["kind"] not in DIAGNOSTIC_KINDS:
        raise RepairError("preparation_failed",
                          f"Unsupported diagnostic kind: {record['kind']}")
    _text(record["observed_at"], "diagnostic observed_at", maximum=64)
    if not isinstance(record["confidence"], str) \
            or record["confidence"] not in CONFIDENCE_LEVELS:
        raise RepairError("preparation_failed",
                          f"Unsupported diagnostic confidence: {record['confidence']}")
    if record["authoritative"] is not False:
        raise RepairError("preparation_failed",
                          "External diagnostic records cannot be authoritative")

    binding = _object(record["binding"], "diagnostic binding", _BINDING_KEYS)
    normalized_binding = {
        "firmware_sha256": _optional_hash(binding.get("firmware_sha256"),
                                          "diagnostic firmware_sha256"),
        "rootfs_sha256": _optional_hash(binding.get("rootfs_sha256"),
                                        "diagnostic rootfs_sha256"),
        "original_target_sha256": _optional_hash(binding.get("original_target_sha256"),
                                                 "diagnostic original_target_sha256"),
        "transformed_target_sha256": _optional_hash(binding.get("transformed_target_sha256"),
                                                    "diagnostic transformed_target_sha256"),
        "status": binding.get("status"),
    }
    if normalized_binding["status"] not in BINDING_STATUSES:
        raise RepairError("preparation_failed",
                          f"Unsupported diagnostic binding: {normalized_binding['status']}")
    original = normalized_binding["original_target_sha256"]
    transformed = normalized_binding["transformed_target_sha256"]
    if normalized_binding["status"] == "bound" and (original is None or transformed not in (None, original)):
        raise RepairError("preparation_failed",
                          "bound diagnostic requires an unchanged original target")
    if normalized_binding["status"] == "unbound" and any(
            value for key, value in normalized_binding.items() if key != "status"):
        raise RepairError("preparation_failed",
                          "unbound diagnostic cannot carry identity hashes")

    facts, redactions_from_facts = sanitize_facts(record["facts"])
    _object(facts, "diagnostic facts")
    try:
        json.dumps(facts, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RepairError("preparation_failed", "Diagnostic facts must be finite JSON") from exc

    raw = _object(record["raw"], "diagnostic raw", _RAW_KEYS)
    normalized_raw = {
        "file": _safe_raw_file(raw.get("file")),
        "sha256": _optional_hash(raw.get("sha256"), "diagnostic raw sha256"),
        "pointer": _safe_raw_pointer(raw.get("pointer")),
    }
    if normalized_raw["sha256"] is None:
        raise RepairError("preparation_failed", "Diagnostic raw sha256 is required")

    redactions_input = record.get("redactions", [])
    if not isinstance(redactions_input, list) or any(
            not isinstance(item, dict) or set(item) != {"field", "reason"}
            or not isinstance(item.get("field"), str) or not item["field"]
            or not isinstance(item.get("reason"), str) or not item["reason"]
            for item in redactions_input):
        raise RepairError("preparation_failed", "Invalid diagnostic redactions")
    known_fields = {item["field"] for item in redactions_input}
    redactions = redactions_input + [item for item in redactions_from_facts
                                     if item["field"] not in known_fields]
    redactions.sort(key=lambda item: (item["field"], item["reason"]))

    return {
        "schema": DIAGNOSTIC_RECORD_SCHEMA,
        "id": diagnostic_id,
        "run_id": record["run_id"],
        "backend": record["backend"],
        "backend_version": record["backend_version"],
        "kind": record["kind"],
        "observed_at": record["observed_at"],
        "binding": normalized_binding,
        "facts": facts,
        "confidence": record["confidence"],
        "authoritative": False,
        "raw": normalized_raw,
        "redactions": redactions,
    }


def _binding(*, firmware: str | None = None, rootfs: str | None = None,
             original_target: str | None = None,
             transformed_target: str | None = None,
             verified_target_sha256: str | None = None) -> dict:
    identities = [firmware, rootfs, original_target]
    # A firmware/rootfs digest proves only image-level relation. ``bound`` is
    # reserved for an unchanged original target digest that the controller has
    # verified against the ELF investigated by this repair session.
    if (original_target is not None and original_target == verified_target_sha256
            and transformed_target in (None, original_target)):
        status = "bound"
    elif any(identities + [transformed_target]):
        status = "related"
    else:
        status = "unbound"
    return {
        "firmware_sha256": firmware,
        "rootfs_sha256": rootfs,
        "original_target_sha256": original_target,
        "transformed_target_sha256": transformed_target,
        "status": status,
    }


def _report_object(value: Any, schema: str, label: str = "diagnostic report") -> dict:
    report = _object(value, label)
    if report.get("schema") != schema:
        raise RepairError("preparation_failed", f"Unsupported {label} schema")
    return report


def _version(report: dict) -> str:
    tool = _object(report.get("tool"), "diagnostic report tool")
    version = tool.get("version")
    return version if isinstance(version, str) and version else "unknown"


def _raw(source: Path, pointer: str, *,
         source_sha256: str | None = None) -> dict:
    digest = source_sha256 or sha(Path(source))
    return {"file": f"raw/{Path(source).name}", "sha256": digest,
            "pointer": pointer}


def _record(kind: str, observed_at: str, binding: dict, facts: dict,
            confidence: str, raw: dict, backend: str, version: str) -> dict:
    facts, redactions = sanitize_facts(facts)
    facts = _object(facts, "diagnostic facts")
    return {
        "schema": DIAGNOSTIC_RECORD_SCHEMA,
        "run_id": "",
        "backend": backend,
        "backend_version": version,
        "kind": kind,
        "observed_at": observed_at,
        "binding": binding,
        "facts": facts,
        "confidence": confidence,
        "authoritative": False,
        "raw": raw,
        "redactions": redactions,
    }


def normalize_firmae_report(report: Any, source: Path, *,
                            source_sha256: str | None = None,
                            verified_target_sha256: str | None = None) -> list[dict]:
    """Convert a bounded ``firmae-report-v1`` object to diagnostic records."""
    report = _report_object(report, FIRMAE_REPORT_SCHEMA, "FirmAE report")
    version = _version(report)
    source_input = _object(report.get("input"), "FirmAE report input")
    firmware = _optional_hash(source_input.get("firmware_sha256"), "FirmAE firmware_sha256")
    rootfs = _optional_hash(source_input.get("rootfs_sha256"), "FirmAE rootfs_sha256")
    original = _optional_hash(source_input.get("original_target_sha256"),
                              "FirmAE original_target_sha256")
    observed_at = _text(report.get("observed_at"), "FirmAE observed_at", maximum=64)
    results = _object(report.get("results"), "FirmAE results")
    records: list[dict] = []

    architecture = results.get("architecture")
    if architecture is not None:
        records.append(_record(
            "architecture_observation", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     verified_target_sha256=verified_target_sha256),
            {"architecture": architecture}, "derived",
            _raw(source, "results.architecture", source_sha256=source_sha256),
            "firmae", version))

    boot = results.get("boot")
    if boot is not None:
        records.append(_record(
            "boot_observation", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     verified_target_sha256=verified_target_sha256),
            {"boot": boot, "network": results.get("network"),
             "compatibility": results.get("compatibility")}, "observed",
            _raw(source, "results.boot", source_sha256=source_sha256),
            "firmae", version))

    services = report.get("services", [])
    if not isinstance(services, list):
        raise RepairError("preparation_failed", "FirmAE services must be a list")
    for index, service in enumerate(services):
        service = _object(service, f"FirmAE service {index}")
        service_target = _optional_hash(service.get("target_sha256"),
                                        f"FirmAE service {index} target_sha256")
        binding = _binding(firmware=firmware, rootfs=rootfs,
                           original_target=service_target or original,
                           verified_target_sha256=verified_target_sha256)
        records.append(_record(
            "service_observation", observed_at, binding,
            {"path": service.get("path"), "protocol": service.get("protocol"),
             "port": service.get("port")}, "observed",
            _raw(source, f"services[{index}]",
                 source_sha256=source_sha256), "firmae", version))

    suggestions = report.get("patch_suggestions", [])
    if not isinstance(suggestions, list):
        raise RepairError("preparation_failed", "FirmAE patch_suggestions must be a list")
    for index, suggestion in enumerate(suggestions):
        suggestion = _object(suggestion, f"FirmAE patch suggestion {index}")
        records.append(_record(
            "external_patch_suggestion", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     verified_target_sha256=verified_target_sha256),
            {"suggestion": suggestion.get("suggestion"),
             "address_static": suggestion.get("address_static"),
             "function": suggestion.get("function")}, "external_claim",
            _raw(source, f"patch_suggestions[{index}]",
                 source_sha256=source_sha256), "firmae", version))
    return records


def normalize_greenhouse_report(report: Any, source: Path, *,
                                source_sha256: str | None = None,
                                verified_target_sha256: str | None = None) -> list[dict]:
    """Convert a bounded ``greenhouse-report-v1`` object to diagnostic records."""
    report = _report_object(report, GREENHOUSE_REPORT_SCHEMA, "Greenhouse report")
    version = _version(report)
    source_input = _object(report.get("input"), "Greenhouse report input")
    firmware = _optional_hash(source_input.get("firmware_sha256"),
                              "Greenhouse firmware_sha256")
    rootfs = _optional_hash(source_input.get("rootfs_sha256"),
                            "Greenhouse rootfs_sha256")
    target = _object(report.get("target"), "Greenhouse target")
    original = _optional_hash(target.get("original_target_sha256"),
                              "Greenhouse original_target_sha256")
    transformed = _optional_hash(target.get("transformed_target_sha256"),
                                 "Greenhouse transformed_target_sha256")
    observed_at = _text(report.get("observed_at"), "Greenhouse observed_at", maximum=64)
    records: list[dict] = []

    interventions = report.get("interventions", [])
    if not isinstance(interventions, list):
        raise RepairError("preparation_failed", "Greenhouse interventions must be a list")
    for index, intervention in enumerate(interventions):
        intervention = _object(intervention, f"Greenhouse intervention {index}")
        records.append(_record(
            "tool_intervention", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     transformed_target=transformed,
                     verified_target_sha256=verified_target_sha256),
            intervention, "observed",
            _raw(source, f"interventions[{index}]",
                 source_sha256=source_sha256),
            "greenhouse", version))

    crashes = report.get("crashes", [])
    if not isinstance(crashes, list):
        raise RepairError("preparation_failed", "Greenhouse crashes must be a list")
    for index, crash in enumerate(crashes):
        crash = _object(crash, f"Greenhouse crash {index}")
        facts = {
            "signal": crash.get("signal"), "pc_static": crash.get("pc_static"),
            "ra_static": crash.get("ra_static"), "registers": crash.get("registers", {}),
            "backtrace": crash.get("backtrace", []),
            "crashing_input_ref": crash.get("crashing_input_ref"),
        }
        records.append(_record(
            "crash_context", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     transformed_target=transformed,
                     verified_target_sha256=verified_target_sha256),
            facts, "observed", _raw(source, f"crashes[{index}]",
                                    source_sha256=source_sha256),
            "greenhouse", version))

    suggestions = report.get("patch_suggestions", [])
    if not isinstance(suggestions, list):
        raise RepairError("preparation_failed", "Greenhouse patch_suggestions must be a list")
    for index, suggestion in enumerate(suggestions):
        suggestion = _object(suggestion, f"Greenhouse patch suggestion {index}")
        records.append(_record(
            "external_patch_suggestion", observed_at,
            _binding(firmware=firmware, rootfs=rootfs, original_target=original,
                     transformed_target=transformed,
                     verified_target_sha256=verified_target_sha256),
            suggestion, "external_claim",
            _raw(source, f"patch_suggestions[{index}]",
                 source_sha256=source_sha256),
            "greenhouse", version))
    return records


def normalize_report(report: Any, source: Path, *,
                     source_sha256: str | None = None,
                     verified_target_sha256: str | None = None) -> list[dict]:
    schema = report.get("schema") if isinstance(report, dict) else None
    if schema == FIRMAE_REPORT_SCHEMA:
        return normalize_firmae_report(report, source,
                                       source_sha256=source_sha256,
                                       verified_target_sha256=verified_target_sha256)
    if schema == GREENHOUSE_REPORT_SCHEMA:
        return normalize_greenhouse_report(report, source,
                                           source_sha256=source_sha256,
                                           verified_target_sha256=verified_target_sha256)
    raise RepairError("preparation_failed", f"Unsupported diagnostic report schema: {schema}")


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"Non-finite JSON constant is not allowed: {value}")


def load_report(path: Path, *, required: bool = False,
                verified_target_sha256: str | None = None
                ) -> tuple[dict | None, list[dict], dict]:
    """Load one report and return ``(raw, records, import_metadata)``.

    A missing optional report yields no records; a missing required report is a
    preparation error.  Callers must add returned records to a ledger before
    treating normalized hashes as persisted evidence.
    ``verified_target_sha256`` must come from controller-side target bytes, not
    from the report.  Binding downgrades therefore happen before the lineage
    hash is calculated.
    """
    path = Path(path)
    if not path.is_file():
        if required:
            raise RepairError("preparation_failed",
                              f"Required diagnostics report is missing: {path}")
        return None, [], {}
    status = "preparation_failed" if required else "diagnostics_import_failed"
    if verified_target_sha256 is not None and not is_sha256(verified_target_sha256):
        raise RepairError("preparation_failed",
                          "verified_target_sha256 must be a lowercase SHA256")
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise RepairError(status,
                              f"Diagnostics report exceeds {MAX_REPORT_BYTES} bytes: {path}")
        raw_bytes = path.read_bytes()
        if len(raw_bytes) > MAX_REPORT_BYTES:
            raise RepairError(status,
                              f"Diagnostics report exceeds {MAX_REPORT_BYTES} bytes: {path}")
        report = json.loads(raw_bytes.decode("utf-8"),
                            parse_constant=_reject_json_constant)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError,
            RecursionError) as exc:
        raise RepairError(status, f"Cannot read diagnostics report {path}: {exc}") from exc
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    records = normalize_report(report, path, source_sha256=source_sha256,
                               verified_target_sha256=verified_target_sha256)
    try:
        normalized = "\n".join(
            json.dumps(item, ensure_ascii=False, sort_keys=True,
                       allow_nan=False, separators=(",", ":"))
            for item in records)
    except (TypeError, ValueError) as exc:
        raise RepairError(status, f"Invalid diagnostics report {path}: {exc}") from exc
    metadata = {
        "source_sha256": source_sha256,
        "source_size": len(raw_bytes),
        "normalized_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        "required": required,
    }
    return report, records, metadata


def copy_report_snapshot(source: Path, destination: Path, *,
                         source_sha256: str, source_size: int) -> None:
    """Copy the exact bounded byte snapshot that ``load_report`` validated.

    Re-copying by path would allow a concurrently growing report to replace
    the raw bytes after normalization.  This helper bounds the copy and binds
    it to the already recorded size and digest before making it visible.
    """
    source, destination = Path(source), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise RepairError("preparation_failed",
                          f"Diagnostics raw destination already exists: {destination.name}")
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.importing")
    if temporary.exists() or temporary.is_symlink():
        raise RepairError("preparation_failed",
                          f"Diagnostics raw staging file already exists: {temporary.name}")
    digest = hashlib.sha256()
    total = 0
    try:
        with source.open("rb") as incoming, temporary.open("xb") as outgoing:
            while True:
                chunk = incoming.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_REPORT_BYTES or total > source_size:
                    raise RepairError(
                        "preparation_failed",
                        f"Diagnostics report changed while importing: {source.name}")
                digest.update(chunk)
                outgoing.write(chunk)
        if total != source_size or digest.hexdigest() != source_sha256:
            raise RepairError("preparation_failed",
                              f"Diagnostics report changed while importing: {source.name}")
        temporary.replace(destination)
    except OSError as exc:
        raise RepairError("preparation_failed",
                          f"Cannot copy diagnostics report {source}: {exc}") from exc
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
