"""Read-only, offline completeness checks for saved query evidence.

This module never calls a model, queries a binary, or changes a repair run.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


_PAGED_RESULTS = {
    "symbols": "symbols", "ascii_search": "matches",
    "indirect_calls": "calls", "callers": "callers",
}
_FILTER_FIELDS = {
    "symbols": "contains", "ascii_search": "text",
    "indirect_calls": "contains", "callers": "address",
}


def pagination_summary(records: list[dict], *,
                       group_by_session: bool = True) -> list[dict]:
    """Merge page intervals per session/target/filter, keeping all gaps.

    Old compacted answers prove only their retained items, not the full page
    originally returned. New records carry separate original page counts.
    ``group_by_session=False`` produces a separate cumulative ledger view.
    """
    groups: dict[str, dict] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("status") == "rejected":
            continue
        query, answer = record.get("query"), record.get("answer")
        if not isinstance(query, dict) or not isinstance(answer, dict):
            continue
        op = query.get("op")
        if op not in _PAGED_RESULTS or answer.get("op") != op:
            continue
        field = _FILTER_FIELDS[op]
        value = answer.get(field, query.get(field, ""))
        if field == "address":
            if type(value) is not int:
                continue
        elif not isinstance(value, str):
            continue
        target = record.get("target_kind", "baseline")
        digest = record.get("target_sha256")
        phase = record.get("phase") if group_by_session else None
        session_id = record.get("session_id") if group_by_session else None
        identity = [phase, session_id, target, digest, op, field, value]
        key = json.dumps(identity, sort_keys=True)
        page = record.get("pagination")
        authoritative = isinstance(page, dict)
        page = page if authoritative else answer
        offset, total = page.get("offset"), page.get("total")
        items = answer.get(_PAGED_RESULTS[op])
        count = page.get("returned_count") if authoritative else (
            len(items) if isinstance(items, list) else None)
        if (type(offset) is not int or type(total) is not int
                or type(count) is not int or offset < 0 or total < 0
                or count < 0 or offset + count > total):
            continue
        group = groups.setdefault(key, {
            **({"phase": phase, "session_id": session_id}
               if group_by_session else {}),
            "target_kind": target, "target_sha256": digest,
            "op": op, "filter": {field: value}, "totals": set(),
            "intervals": [], "historical_compaction": False,
        })
        group["totals"].add(total)
        group["historical_compaction"] |= (
            not authoritative and answer.get("truncated") is True)
        if count:
            group["intervals"].append((offset, offset + count))

    summaries = []
    for group in groups.values():
        intervals = []
        for start, end in sorted(group.pop("intervals")):
            if intervals and start <= intervals[-1][1]:
                intervals[-1][1] = max(intervals[-1][1], end)
            else:
                intervals.append([start, end])
        totals = sorted(group.pop("totals"))
        total, missing, cursor = max(totals), [], 0
        for start, end in intervals:
            if cursor < start:
                missing.append([cursor, start])
            cursor = max(cursor, end)
        if cursor < total:
            missing.append([cursor, total])
        consistent = len(totals) == 1
        summaries.append({
            **group, "total": total, "observed_totals": totals,
            "consistent_total": consistent, "covered_intervals": intervals,
            "missing_intervals": missing,
            "next_missing_offset": missing[0][0] if missing else None,
            "complete": consistent and not missing,
        })
    return summaries


def audit_records(records: list[dict]) -> dict:
    rejected = {
        entry.get("evidence") for entry in records
        if isinstance(entry, dict)
        and entry.get("kind") == "nomination_decision"
        and entry.get("decision") == "rejected"
    }
    rejected.update(
        entry.get("id") for entry in records
        if isinstance(entry, dict)
        and entry.get("kind") == "model_code_site"
        and entry.get("nomination_status") == "rejected")
    rejected.discard(None)
    return {
        "mode": "offline_read_only",
        "record_count": len(records),
        "rejected_nomination_ids": sorted(rejected),
        "pagination": pagination_summary(records),
        "pagination_cumulative": pagination_summary(
            records, group_by_session=False),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path, help="Saved evidence-ledger.json")
    args = parser.parse_args()
    try:
        records = json.loads(args.ledger.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("Evidence ledger must be a JSON array")
        report = audit_records(records)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Cannot audit evidence: {exc}\n")
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
