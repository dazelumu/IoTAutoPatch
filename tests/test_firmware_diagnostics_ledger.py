"""Diagnostics ledger contracts (W1)."""
from __future__ import annotations

import copy
import json

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware import diagnostics_intake
from repair_tool.firmware.diagnostics_intake import validate_diagnostic_record
from repair_tool.firmware.diagnostics_ledger import DiagnosticsLedger


HASH_A = "a" * 64
HASH_B = "b" * 64


def record(**overrides) -> dict:
    value = {
        "schema": "diagnostic-record-v1",
        "id": "d-000001",
        "run_id": "repair-test",
        "backend": "greenhouse",
        "backend_version": "test",
        "kind": "crash_context",
        "observed_at": "2026-10-20T00:00:00Z",
        "binding": {
            "firmware_sha256": HASH_A,
            "rootfs_sha256": HASH_B,
            "original_target_sha256": HASH_A,
            "transformed_target_sha256": None,
            "status": "bound",
        },
        "facts": {"signal": "SIGSEGV", "command_line": "/home/lumu/tool --run"},
        "confidence": "observed",
        "authoritative": False,
        "raw": {"file": "raw/report.json", "sha256": HASH_B,
                "pointer": "crashes[0]"},
    }
    value.update(overrides)
    return value


def test_validate_sanitizes_secret_and_host_path() -> None:
    result = validate_diagnostic_record(record(
        facts={"api_key": "secret", "host_path": "D:\\IoT\\secret.txt"}))
    assert result["facts"] == {
        "api_key": "[REDACTED]", "host_path": "[REDACTED_HOST_PATH]"
    }
    assert {item["reason"] for item in result["redactions"]} == {"secret_key", "host_path"}
    assert result["authoritative"] is False


def test_validate_rejects_authoritative_external_fact() -> None:
    with pytest.raises(RepairError, match="cannot be authoritative"):
        validate_diagnostic_record(record(authoritative=True))


def test_validate_rejects_bound_fact_without_original_target() -> None:
    binding = record()["binding"]
    binding["original_target_sha256"] = None
    with pytest.raises(RepairError, match="unchanged original target"):
        validate_diagnostic_record(record(binding=binding))


def test_validate_rejects_unbound_fact_with_identity() -> None:
    binding = record()["binding"]
    binding["status"] = "unbound"
    with pytest.raises(RepairError, match="cannot carry identity"):
        validate_diagnostic_record(record(binding=binding))


def test_validate_rejects_unsafe_raw_path() -> None:
    raw = {"file": "../outside.json", "sha256": HASH_A, "pointer": "x"}
    with pytest.raises(RepairError, match="safe relative"):
        validate_diagnostic_record(record(raw=raw))


def test_validate_rejects_unsafe_raw_pointer() -> None:
    raw = {"file": "raw/report.json", "sha256": HASH_A,
           "pointer": "/home/lumu/report.json"}
    with pytest.raises(RepairError, match="safe report pointer"):
        validate_diagnostic_record(record(raw=raw))


def test_validate_handles_malformed_enums_and_secret_values() -> None:
    with pytest.raises(RepairError, match="Unsupported diagnostic backend"):
        validate_diagnostic_record(record(backend=[]))
    with pytest.raises(RepairError, match="Unsupported diagnostic kind"):
        validate_diagnostic_record(record(kind=[]))
    with pytest.raises(RepairError, match="Unsupported diagnostic confidence"):
        validate_diagnostic_record(record(confidence=[]))
    result = validate_diagnostic_record(record(
        facts={"note": "authorization: bearer-value"}))
    assert result["facts"]["note"] == "[REDACTED]"
    assert any(item["reason"] == "secret_value"
               for item in result["redactions"])


def test_ledger_assigns_ids_counts_and_filters(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    first = ledger.add(record())
    second = ledger.add(record(id="d-000002", kind="external_patch_suggestion"))
    assert first == "d-000001"
    assert second == "d-000002"
    assert ledger.document()["counts"] == {
        "total": 2,
        "by_kind": {"crash_context": 1,
                    "external_patch_suggestion": 1},
        "by_binding_status": {"bound": 2},
    }
    listed = ledger.list(kind="external_patch_suggestion", limit=1)
    assert listed["total"] == 1
    assert listed["records"][0]["id"] == second


def test_ledger_reload_is_append_only(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    first = ledger.add(record())
    original = copy.deepcopy(ledger.get(first))
    reloaded = DiagnosticsLedger(tmp_path, run_id="ignored")
    assert reloaded.get(first) == original
    assert reloaded.add(record(id="d-000002")) == "d-000002"
    assert reloaded.get(first) == original


def test_ledger_rejects_out_of_sequence_id(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    with pytest.raises(RepairError, match="Expected diagnostic id"):
        ledger.add(record(id="d-000099"))


def test_ledger_registers_import_and_decision(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    diagnostic_id = ledger.add(record())
    ledger.register_import({
        "import_id": "greenhouse-test", "backend": "greenhouse",
        "format": "greenhouse-report-v1", "source_sha256": HASH_A,
        "source_size": 10, "normalized_sha256": HASH_B, "required": False,
    })
    decision = ledger.append_decision(diagnostic_id, "exposed", "model query")
    assert decision == "decision-000001"
    assert json.loads((tmp_path / "diagnostics-ledger.json").read_text())["imports"]
    assert ledger.document()["decisions"][0]["diagnostic"] == diagnostic_id


def test_ledger_rejects_duplicate_import(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    metadata = {
        "import_id": "firmae-test", "backend": "firmae",
        "format": "firmae-report-v1", "source_sha256": HASH_A,
        "source_size": 10, "normalized_sha256": HASH_B, "required": True,
    }
    ledger.register_import(metadata)
    with pytest.raises(RepairError, match="Duplicate diagnostics import"):
        ledger.register_import(metadata)


def test_ledger_rejects_tampered_or_foreign_records(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    ledger.add(record())
    ledger.add(record(id="d-000002", kind="external_patch_suggestion"))
    path = tmp_path / "diagnostics-ledger.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    original = copy.deepcopy(data)
    data["records"].pop(0)
    data["records"][0]["id"] = "d-000001"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RepairError, match="counts mismatch"):
        DiagnosticsLedger(tmp_path, run_id="repair-test")

    data["counts"] = {
        "total": 1,
        "by_kind": {"external_patch_suggestion": 1},
        "by_binding_status": {"bound": 1},
    }
    data["records"][0]["id"] = "d-000002"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RepairError, match="contiguous"):
        DiagnosticsLedger(tmp_path, run_id="repair-test")

    path.write_text(json.dumps(original), encoding="utf-8")
    clean = DiagnosticsLedger(tmp_path, run_id="repair-test")
    foreign = record(id="d-000003", run_id="another-run")
    with pytest.raises(RepairError, match="another run"):
        clean.add(foreign)
    with pytest.raises(RepairError, match="Invalid diagnostic backend"):
        clean.list(backend=[])


def test_import_metadata_is_validated(tmp_path) -> None:
    ledger = DiagnosticsLedger(tmp_path, run_id="repair-test")
    metadata = {
        "import_id": "greenhouse-test", "backend": [],
        "format": "greenhouse-report-v1", "source_sha256": HASH_A,
        "source_size": 10, "normalized_sha256": HASH_B, "required": False,
    }
    with pytest.raises(RepairError, match="Incomplete diagnostics import"):
        ledger.register_import(metadata)


def test_report_reader_bounds_input_size(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diagnostics_intake, "MAX_REPORT_BYTES", 4)
    source = tmp_path / "too-large.json"
    source.write_text('{"x":1}', encoding="utf-8")
    with pytest.raises(RepairError, match="exceeds"):
        diagnostics_intake.load_report(source, required=True)
