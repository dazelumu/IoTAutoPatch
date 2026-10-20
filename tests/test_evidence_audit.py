"""Offline audit and rejected-evidence safety tests using inert fixtures."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from repair_tool.config import RepairError
from repair_tool.evidence_audit import audit_records, pagination_summary
from repair_tool.firmware.evidence import (
    EvidenceLedger, localization_view, register_model_code_site,
)
from repair_tool.firmware.propose import validate_proposal
from repair_tool.firmware.query import EvidenceSession


@pytest.fixture
def inert_ledger(tmp_path):
    target = tmp_path / "inert.bin"
    target.write_bytes(b"inert audit fixture")
    return EvidenceLedger(tmp_path / "evidence", target)


def fake_analysis(ledger):
    return SimpleNamespace(
        path=ledger.target_path, symbol_records=[],
        indirect_call_at=lambda site: {
            "vaddr": site, "bytes_hex": "00" * 16, "callee": "fixture",
            "got_vaddr": 0, "got_value": 0, "delay_slot_hex": "00000000",
        })


def test_rejection_is_durable_append_only_and_filtered(inert_ledger):
    ledger = inert_ledger
    site_id = register_model_code_site(ledger, fake_analysis(ledger), 4096)
    original = copy.deepcopy(ledger.get(site_id))
    decision_id = ledger.reject_code_site(
        site_id, session_id="fixture-session", semantic_class="fixture-class")
    assert ledger.get(site_id) == original
    assert ledger.get(decision_id)["decision"] == "rejected"
    reloaded = EvidenceLedger(ledger.root, ledger.target_path)
    assert reloaded.code_site_rejected(site_id)
    assert localization_view(reloaded, None)["model_code_sites"] == []
    assert audit_records(reloaded.entries)["rejected_nomination_ids"] == [site_id]


def test_repeated_registration_has_distinct_audit_identity(inert_ledger):
    analysis = fake_analysis(inert_ledger)
    first = register_model_code_site(inert_ledger, analysis, 4096)
    inert_ledger.reject_code_site(first, session_id="first", semantic_class="fixture")
    second = register_model_code_site(inert_ledger, analysis, 4096)
    assert first != second
    assert inert_ledger.code_site_rejected(first)
    assert not inert_ledger.code_site_rejected(second)
    assert len(inert_ledger.by_kind("model_code_site")) == 2


def test_register_query_does_not_reuse_cache(inert_ledger):
    session = EvidenceSession(inert_ledger, fake_analysis(inert_ledger))
    query = {"op": "register_patch_site", "address": 4096}
    first = session.handle(query)
    second = session.handle(query)
    assert first["evidence"] != second["evidence"]
    assert second.get("cached") is not True


def test_invalid_rejection_does_not_append(inert_ledger):
    with pytest.raises(ValueError):
        inert_ledger.reject_code_site("missing", session_id="fixture", semantic_class="fixture")
    assert inert_ledger.entries == []


def test_proposal_cannot_cite_rejected_evidence(inert_ledger):
    site_id = register_model_code_site(inert_ledger, fake_analysis(inert_ledger), 8192)
    inert_ledger.reject_code_site(site_id, session_id="fixture", semantic_class="fixture")
    with pytest.raises(RepairError, match="rejected nomination"):
        validate_proposal({"edits": [{
            "site": 8192, "expected_hex": "00" * 16, "evidence": [site_id],
        }]}, inert_ledger)

@pytest.mark.skipif(os.name != "posix", reason="Workflow imports Unix session control")
def test_conclusion_does_not_expose_callee_and_refuses_rejected(inert_ledger):
    from repair_tool.firmware.loop import FirmwareWorkflow

    flow = object.__new__(FirmwareWorkflow)
    flow.ledger_for_target = lambda: inert_ledger
    evidence_id = register_model_code_site(
        inert_ledger, fake_analysis(inert_ledger), 4096)
    payload = flow._conclusion_payload(
        "localize", {"evidence": evidence_id}, {"signal": "SIGSEGV"})
    assert "callee" not in payload["registered_patch_sites"][0]
    inert_ledger.reject_code_site(
        evidence_id, session_id="fixture", semantic_class="fixture")
    with pytest.raises(RepairError, match="registered site was rejected"):
        flow._conclusion_payload("localize", {"evidence": evidence_id}, {})


@pytest.mark.skipif(os.name != "posix", reason="Workflow imports Unix session control")
def test_conclusion_validation_persists_new_semantic_rejection(inert_ledger):
    from repair_tool.firmware.loop import FirmwareWorkflow

    flow = object.__new__(FirmwareWorkflow)
    flow.ledger_for_target = lambda: inert_ledger
    evidence_id = register_model_code_site(
        inert_ledger, fake_analysis(inert_ledger), 4096)
    entry = inert_ledger.get(evidence_id)
    entry["callee"] = "free"
    inert_ledger.save()

    with pytest.raises(RepairError, match="semantic nomination gate"):
        flow._conclusion_payload(
            "localize", {"evidence": evidence_id}, {"signal": "SIGSEGV"})

    assert inert_ledger.code_site_rejected(evidence_id)
    decision = inert_ledger.by_kind("nomination_decision")[-1]
    assert decision["session_id"] == "localize-conclusion-validation"

@pytest.mark.skipif(os.name != "posix", reason="Workflow imports Unix session control")
def test_final_localization_cannot_cite_rejected_record(inert_ledger):
    from repair_tool.firmware.loop import FirmwareWorkflow

    flow = object.__new__(FirmwareWorkflow)
    flow.ledger_for_target = lambda: inert_ledger
    evidence_id = register_model_code_site(
        inert_ledger, fake_analysis(inert_ledger), 4096)
    session = SimpleNamespace(answers=[{
        "query": {"op": "register_patch_site", "address": 4096},
        "answer": {"op": "register_patch_site", "evidence": evidence_id,
                   "site": 4096, "bytes_hex": "00" * 16},
    }])
    inert_ledger.reject_code_site(
        evidence_id, session_id="fixture", semantic_class="fixture")
    with pytest.raises(RepairError, match="rejected nomination"):
        flow._write_localization(
            {"evidence": [evidence_id], "reasoning": "inert fixture"}, session)


def page(offset, count, total=12, *, contains="fixture", digest="target-a",
         target_kind="baseline", truncated=False):
    return {
        "status": "answered", "target_kind": target_kind,
        "target_sha256": digest,
        "query": {"op": "symbols", "contains": contains},
        "answer": {"op": "symbols", "contains": contains,
                   "offset": offset, "total": total,
                   "symbols": [{} for _ in range(count)],
                   "truncated": truncated},
    }


def test_last_page_does_not_hide_an_earlier_gap():
    summary = pagination_summary([page(0, 4), page(8, 4)])[0]
    assert summary["missing_intervals"] == [[4, 8]]
    assert summary["next_missing_offset"] == 4
    assert not summary["complete"]


def test_overlapping_out_of_order_and_repeated_pages_merge():
    summary = pagination_summary([
        page(8, 4), page(2, 8), page(0, 4), page(0, 4),
    ])[0]
    assert summary["covered_intervals"] == [[0, 12]]
    assert summary["missing_intervals"] == []
    assert summary["complete"]


def test_page_starting_in_middle_keeps_unseen_prefix():
    summary = pagination_summary([page(6, 6)])[0]
    assert summary["missing_intervals"] == [[0, 6]]


def test_multiple_filters_and_target_builds_are_independent():
    summaries = pagination_summary([
        page(0, 4), page(0, 4, contains="second-filter"),
        page(4, 8, digest="target-b"), page(4, 8, target_kind="candidate"),
    ])
    assert len(summaries) == 4
    assert all(not summary["complete"] for summary in summaries)


def test_session_coverage_is_not_falsely_completed_by_another_session():
    first = page(0, 6)
    first.update(phase="localize", session_id="session-a")
    second = page(6, 6)
    second.update(phase="relocalize", session_id="session-b")

    per_session = pagination_summary([first, second])
    cumulative = pagination_summary(
        [first, second], group_by_session=False)

    assert len(per_session) == 2
    assert all(not item["complete"] for item in per_session)
    assert cumulative[0]["complete"]
    report = audit_records([first, second])
    assert report["pagination"] == per_session
    assert report["pagination_cumulative"] == cumulative


def test_changing_totals_cannot_be_marked_complete():
    summary = pagination_summary([page(0, 4, total=4), page(4, 4, total=8)])[0]
    assert summary["missing_intervals"] == []
    assert not summary["consistent_total"]
    assert not summary["complete"]


def test_old_compaction_only_proves_visible_items():
    summary = pagination_summary([page(0, 3, truncated=True)])[0]
    assert summary["historical_compaction"]
    assert summary["missing_intervals"] == [[3, 12]]


def test_original_page_count_survives_compaction_for_audit():
    record = page(0, 3, truncated=True)
    record["pagination"] = {"offset": 0, "returned_count": 12, "total": 12}
    summary = pagination_summary([record])[0]
    assert summary["complete"]
    assert not summary["historical_compaction"]


def test_query_ledger_saves_original_page_count(inert_ledger):
    session = EvidenceSession(inert_ledger, fake_analysis(inert_ledger))
    record = page(0, 50, total=50)
    record["answer"]["symbols"] = [{"name": "x" * 120} for _ in range(50)]
    session._log(record["query"], record["answer"])
    saved = inert_ledger.by_kind("model_query")[0]
    assert len(saved["answer"]["symbols"]) < 50
    assert saved["pagination"]["returned_count"] == 50
    assert pagination_summary(inert_ledger.entries)[0]["complete"]


@pytest.mark.parametrize("op", ["elf_bytes", "candidate_elf_bytes"])
def test_byte_queries_survive_historical_compaction_symmetrically(op):
    history = [{
        "query": {"op": op, "address": 4096, "size": 4096},
        "answer": {"op": op, "address": 4096, "size": 4096,
                   "hex": "ab" * 4096},
        "target_kind": "candidate" if op.startswith("candidate_") else "baseline",
        "target_sha256": "fixture-digest",
    }]
    compact = EvidenceSession.compact_answers(history)
    assert len(compact) == 1
    assert compact[0]["query"]["op"] == op
    assert compact[0]["answer"] == {
        "op": op, "address": 4096, "size": 4096, "truncated": True,
    }


@pytest.mark.parametrize("record", [
    page(-1, 3), page(13, 0), page(10, 4),
    {**page(0, 12), "status": "rejected"},
])
def test_invalid_or_rejected_pages_do_not_prove_coverage(record):
    assert pagination_summary([record]) == []


def test_empty_result_is_complete():
    summary = pagination_summary([page(0, 0, total=0)])[0]
    assert summary["complete"]


def test_audit_cli_does_not_change_input(tmp_path):
    path = tmp_path / "ledger.json"
    original = json.dumps([page(0, 4), page(8, 4)]).encode()
    path.write_bytes(original)
    result = subprocess.run([
        sys.executable, "-m", "repair_tool.evidence_audit", str(path),
    ], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)["pagination"][0]["missing_intervals"] == [[4, 8]]
    assert path.read_bytes() == original


def test_audit_cli_rejects_non_array_input(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{}", encoding="utf-8")
    result = subprocess.run([
        sys.executable, "-m", "repair_tool.evidence_audit", str(path),
    ], capture_output=True, text=True)
    assert result.returncode == 2
    assert "JSON array" in result.stderr
