"""Report normalization tests for external diagnostic fixtures (W2)."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware import diagnostics_intake
from repair_tool.firmware.diagnostics_intake import (
    copy_report_snapshot, load_report, normalize_report)
from repair_tool.firmware.diagnostics_ledger import DiagnosticsLedger


FIXTURES = Path(__file__).parent / "fixtures" / "diagnostics"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_firmae_fixture_normalizes_architecture_boot_service_and_suggestion() -> None:
    path = FIXTURES / "firmae-valid.json"
    records = normalize_report(fixture("firmae-valid.json"), path)
    kinds = [item["kind"] for item in records]
    assert kinds == [
        "architecture_observation", "boot_observation",
        "service_observation", "external_patch_suggestion",
    ]
    assert all(item["backend"] == "firmae" for item in records)
    assert all(item["authoritative"] is False for item in records)
    # A report cannot make itself ``bound`` by claiming a target digest.
    assert all(item["binding"]["status"] == "related" for item in records)
    verified = normalize_report(fixture("firmae-valid.json"), path,
                                verified_target_sha256="c" * 64)
    assert all(item["binding"]["status"] == "bound" for item in verified)
    assert records[2]["facts"]["path"] == "sbin/httpd"


def test_greenhouse_transformed_target_is_related_not_bound() -> None:
    path = FIXTURES / "greenhouse-crash.json"
    records = normalize_report(fixture("greenhouse-crash.json"), path)
    by_kind = {item["kind"]: item for item in records}
    assert set(by_kind) == {"tool_intervention", "crash_context",
                            "external_patch_suggestion"}
    crash = by_kind["crash_context"]
    assert crash["binding"]["status"] == "related"
    assert crash["binding"]["transformed_target_sha256"] != crash["binding"]["original_target_sha256"]
    assert crash["facts"]["pc_static"] == "0x00407e88"


def test_untrusted_suggestion_stays_non_authoritative_and_redacts_host_path(
        tmp_path) -> None:
    path = FIXTURES / "untrusted-text.json"
    ledger = DiagnosticsLedger(tmp_path, run_id="normalization-test")
    records, metadata = load_report(path, required=True)[1:]
    suggestion_record = records[-1]
    assert "/home/lumu/tools/tool.sh" not in \
        suggestion_record["facts"]["suggestion"]
    assert any(item["reason"] == "host_path"
               for item in suggestion_record["redactions"])
    normalized = "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True,
                                      allow_nan=False, separators=(",", ":"))
                           for item in records)
    assert metadata["normalized_sha256"] == hashlib.sha256(
        normalized.encode("utf-8")).hexdigest()
    for item in records:
        ledger.add(item)
    suggestion = ledger.list(kind="external_patch_suggestion")["records"][0]
    assert suggestion["authoritative"] is False
    assert suggestion["binding"]["status"] == "unbound"
    assert "/home/lumu/tools/tool.sh" not in suggestion["facts"]["suggestion"]
    assert any(item["reason"] == "host_path" for item in suggestion["redactions"])


def test_non_finite_json_constants_are_rejected(tmp_path) -> None:
    report = fixture("firmae-valid.json")
    report["patch_suggestions"][0]["suggestion"] = float("nan")
    source = tmp_path / "nonfinite.json"
    source.write_text(json.dumps(report, allow_nan=True), encoding="utf-8")
    with pytest.raises(RepairError, match="Cannot read diagnostics report"):
        load_report(source, required=True)


def test_load_required_missing_report_fails_and_optional_is_empty(tmp_path) -> None:
    missing = tmp_path / "missing.json"
    raw, records, metadata = load_report(missing)
    assert raw is None and records == [] and metadata == {}
    with pytest.raises(RepairError, match="Required diagnostics report"):
        load_report(missing, required=True)


def test_load_report_returns_source_and_normalized_hashes() -> None:
    path = FIXTURES / "firmae-valid.json"
    raw, records, metadata = load_report(path, required=True)
    assert raw["schema"] == "firmae-report-v1"
    assert len(records) == 4
    assert len(metadata["source_sha256"]) == 64
    assert len(metadata["normalized_sha256"]) == 64


def test_binding_downgrade_happens_before_lineage_hash() -> None:
    claimed_target = "c" * 64
    actual_target = "f" * 64
    _, records, metadata = load_report(
        FIXTURES / "firmae-valid.json", required=True,
        verified_target_sha256=actual_target)
    assert claimed_target != actual_target
    assert all(record["binding"]["status"] == "related" for record in records)
    normalized = "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")) for item in records)
    assert metadata["normalized_sha256"] == hashlib.sha256(
        normalized.encode("utf-8")).hexdigest()


def test_diagnostic_fact_depth_is_bounded() -> None:
    report = fixture("untrusted-text.json")
    suggestion = report["patch_suggestions"][0]
    root: dict = {}
    item = root
    for _ in range(32):
        item["nested"] = {}
        item = item["nested"]
    item["value"] = "deep"
    suggestion["suggestion"] = root

    with pytest.raises(RepairError, match="exceed depth"):
        normalize_report(report, FIXTURES / "untrusted-text.json")


def test_report_snapshot_is_bound_to_size_and_digest(tmp_path) -> None:
    source = tmp_path / "report.json"
    source.write_text('{"schema":"test"}\n', encoding="utf-8")
    source_bytes = source.read_bytes()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    source_size = len(source_bytes)
    destination = tmp_path / "raw" / source.name
    destination.parent.mkdir()

    with pytest.raises(RepairError, match="changed while importing"):
        copy_report_snapshot(source, destination,
                             source_sha256=source_sha256,
                             source_size=source_size + 1)
    assert not destination.exists()
    assert not list(destination.parent.glob(".*.importing"))

    copy_report_snapshot(source, destination,
                         source_sha256=source_sha256,
                         source_size=source_size)
    assert source.read_bytes() == destination.read_bytes()


def test_load_report_uses_one_snapshot_hash_for_raw_records(
        monkeypatch) -> None:
    stale_hash = "b" * 64
    monkeypatch.setattr(diagnostics_intake, "sha", lambda path: stale_hash)

    _, records, metadata = load_report(
        FIXTURES / "firmae-valid.json", required=True)

    assert metadata["source_sha256"] != stale_hash
    assert all(record["raw"]["sha256"] == metadata["source_sha256"]
               for record in records)
