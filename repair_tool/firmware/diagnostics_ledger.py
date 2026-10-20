"""Append-only ledger for normalized external firmware diagnostics.

Diagnostic records are deliberately separate from the authoritative repair
evidence ledger.  A ``d-*`` record can help the model investigate an ELF, but
it is never a patch-site nomination and never counts as verification evidence.
"""
from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from ..config import RepairError
from ..storage import save_json
from .diagnostics_intake import (BACKENDS, BINDING_STATUSES,
                                 DIAGNOSTIC_KINDS,
                                 DIAGNOSTIC_RECORD_SCHEMA, is_sha256,
                                 validate_diagnostic_record)


DIAGNOSTICS_LEDGER_SCHEMA = "diagnostics-ledger-v1"
_LEDGER_FILE = "diagnostics-ledger.json"
_LEDGER_KEYS = {"schema", "run_id", "imports", "decisions", "records", "counts"}
_IMPORT_KEYS = {
    "import_id", "backend", "format", "source_sha256", "source_size",
    "normalized_sha256", "required",
}
_DECISION_KEYS = {"id", "diagnostic", "decision", "reason"}
_DECISION_ID = re.compile(r"^decision-\d{6}$")


def _counts(records: list[dict]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    by_binding: dict[str, int] = {}
    for record in records:
        by_kind[record["kind"]] = by_kind.get(record["kind"], 0) + 1
        binding = record["binding"]["status"]
        by_binding[binding] = by_binding.get(binding, 0) + 1
    return {"total": len(records), "by_kind": by_kind,
            "by_binding_status": by_binding}


class DiagnosticsLedger:
    """Load, append and persist ``diagnostics-ledger-v1`` records."""

    def __init__(self, root: Path, *, run_id: str):
        self.root = Path(root)
        if not isinstance(run_id, str) or not run_id:
            raise RepairError("preparation_failed", "Diagnostics ledger requires run_id")
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / _LEDGER_FILE
        self.run_id = run_id
        self.imports: list[dict] = []
        self.decisions: list[dict] = []
        self.records: list[dict] = []
        self._next_number = 1
        self.load()

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RepairError("preparation_failed",
                              f"Invalid diagnostics ledger: {self.path}") from exc
        if not isinstance(data, dict) or data.get("schema") != DIAGNOSTICS_LEDGER_SCHEMA:
            raise RepairError("preparation_failed",
                              f"Unsupported diagnostics ledger schema: {self.path}")
        if set(data) != _LEDGER_KEYS:
            raise RepairError("preparation_failed",
                              f"Invalid diagnostics ledger fields: {self.path}")
        if not isinstance(data.get("run_id"), str) or not data["run_id"]:
            raise RepairError("preparation_failed", "Diagnostics ledger requires run_id")
        if not isinstance(data.get("imports"), list) \
                or not isinstance(data.get("decisions"), list) \
                or not isinstance(data.get("records"), list):
            raise RepairError("preparation_failed",
                              f"Invalid diagnostics ledger containers: {self.path}")
        self.run_id = data["run_id"]
        self.imports = [self._validate_import(item)
                        for item in data["imports"]]
        import_ids = [item["import_id"] for item in self.imports]
        if len(import_ids) != len(set(import_ids)):
            raise RepairError("preparation_failed",
                              f"Duplicate diagnostics import: {self.path}")
        self.decisions = list(data["decisions"])
        self.records = []
        seen: set[str] = set()
        for expected_number, raw in enumerate(data["records"], start=1):
            record = validate_diagnostic_record(raw)
            expected_id = f"d-{expected_number:06d}"
            if record["id"] != expected_id:
                raise RepairError("preparation_failed",
                                  f"Diagnostic ids must be contiguous from {expected_id}")
            if record["run_id"] != self.run_id:
                raise RepairError("preparation_failed",
                                  f"Diagnostic {record['id']} belongs to another run")
            diagnostic_id = record["id"]
            if diagnostic_id in seen:
                raise RepairError("preparation_failed",
                                  f"Duplicate diagnostic id: {diagnostic_id}")
            seen.add(diagnostic_id)
            self.records.append(record)
            number = int(diagnostic_id[2:])
            self._next_number = max(self._next_number, number + 1)
        if data["counts"] != _counts(self.records):
            raise RepairError("preparation_failed",
                              f"Diagnostics ledger counts mismatch: {self.path}")
        known_ids = set(seen)
        seen_decisions: set[str] = set()
        for expected_number, raw in enumerate(self.decisions, start=1):
            if not isinstance(raw, dict) or set(raw) != _DECISION_KEYS:
                raise RepairError("preparation_failed",
                                  f"Invalid diagnostics decision: {self.path}")
            expected_id = f"decision-{expected_number:06d}"
            if not isinstance(raw["id"], str) or raw["id"] != expected_id \
                    or not _DECISION_ID.fullmatch(raw["id"]):
                raise RepairError("preparation_failed",
                                  f"Invalid diagnostics decision id: {raw.get('id')}")
            if raw["id"] in seen_decisions:
                raise RepairError("preparation_failed",
                                  f"Duplicate diagnostics decision: {raw['id']}")
            if not isinstance(raw["diagnostic"], str) \
                    or raw["diagnostic"] not in known_ids:
                raise RepairError("preparation_failed",
                                  f"Decision references unknown diagnostic: {raw['diagnostic']}")
            if raw["decision"] not in {"exposed", "filtered", "rejected"}:
                raise RepairError("preparation_failed",
                                  f"Invalid diagnostic decision: {raw['decision']}")
            if not isinstance(raw["reason"], str) or not raw["reason"]:
                raise RepairError("preparation_failed",
                                  "Diagnostic decision requires a reason")
            seen_decisions.add(raw["id"])

    def save(self) -> None:
        save_json(self.path, self.document())

    def document(self) -> dict:
        records = deepcopy(self.records)
        imports = deepcopy(self.imports)
        decisions = deepcopy(self.decisions)
        return {
            "schema": DIAGNOSTICS_LEDGER_SCHEMA,
            "run_id": self.run_id,
            "imports": imports,
            "decisions": decisions,
            "records": records,
            "counts": _counts(self.records),
        }

    def add(self, record: dict) -> str:
        if not isinstance(record, dict):
            raise RepairError("preparation_failed", "Diagnostic record must be an object")
        candidate = dict(record)
        if candidate.get("run_id") in (None, ""):
            candidate["run_id"] = self.run_id
        elif candidate.get("run_id") != self.run_id:
            raise RepairError("preparation_failed",
                              "Diagnostic record belongs to another run")
        if self._next_number > 999999:
            raise RepairError("preparation_failed", "Diagnostics id range exhausted")
        diagnostic_id = f"d-{self._next_number:06d}"
        if "id" in candidate:
            if candidate["id"] != diagnostic_id:
                raise RepairError("preparation_failed",
                                  f"Expected diagnostic id {diagnostic_id}, got {candidate['id']}")
        else:
            candidate["id"] = diagnostic_id
        normalized = validate_diagnostic_record(candidate)
        self.records.append(normalized)
        self._next_number += 1
        self.save()
        return diagnostic_id

    @staticmethod
    def _validate_import(metadata: dict) -> dict:
        required = _IMPORT_KEYS
        if not isinstance(metadata, dict) or set(metadata) != required:
            raise RepairError("preparation_failed", "Invalid diagnostics import metadata")
        if any(not isinstance(metadata[key], str) or not metadata[key]
               for key in ("import_id", "backend", "format")):
            raise RepairError("preparation_failed", "Incomplete diagnostics import metadata")
        if metadata["backend"] not in BACKENDS \
                or metadata["format"] != f"{metadata['backend']}-report-v1":
            raise RepairError("preparation_failed",
                              "Diagnostics import backend/format mismatch")
        if not is_sha256(metadata["source_sha256"]) \
                or not is_sha256(metadata["normalized_sha256"]):
            raise RepairError("preparation_failed", "Diagnostics import hashes must be SHA256")
        if type(metadata["source_size"]) is not int or metadata["source_size"] < 0:
            raise RepairError("preparation_failed", "Diagnostics source size must be non-negative")
        if not isinstance(metadata["required"], bool):
            raise RepairError("preparation_failed", "Diagnostic import required must be boolean")
        return deepcopy(metadata)

    def register_import(self, metadata: dict) -> None:
        normalized = self._validate_import(metadata)
        if any(item.get("import_id") == normalized["import_id"]
               for item in self.imports):
            raise RepairError("preparation_failed",
                              f"Duplicate diagnostics import: {normalized['import_id']}")
        self.imports.append(normalized)
        self.save()

    def append_decision(self, diagnostic_id: str, decision: str, reason: str) -> str:
        if not isinstance(diagnostic_id, str) or not isinstance(decision, str):
            raise RepairError("preparation_failed", "Invalid diagnostic decision")
        if self.get(diagnostic_id) is None:
            raise RepairError("preparation_failed", f"Unknown diagnostic: {diagnostic_id}")
        if decision not in {"exposed", "filtered", "rejected"}:
            raise RepairError("preparation_failed", f"Invalid diagnostic decision: {decision}")
        if not isinstance(reason, str) or not reason:
            raise RepairError("preparation_failed", "Diagnostic decision requires a reason")
        decision_id = f"decision-{len(self.decisions) + 1:06d}"
        self.decisions.append({"id": decision_id, "diagnostic": diagnostic_id,
                               "decision": decision, "reason": reason})
        self.save()
        return decision_id

    def get(self, diagnostic_id: str) -> dict | None:
        record = next((item for item in self.records
                       if item["id"] == diagnostic_id), None)
        return deepcopy(record) if record is not None else None

    def list(self, *, offset: int = 0, limit: int = 20,
             backend: str | None = None, kind: str | None = None,
             binding: str | None = None) -> dict:
        if type(offset) is not int or type(limit) is not int or offset < 0 or limit < 1:
            raise RepairError("preparation_failed", "Invalid diagnostic list pagination")
        if binding is not None and (
                not isinstance(binding, str) or binding not in BINDING_STATUSES):
            raise RepairError("preparation_failed", f"Invalid diagnostic binding: {binding}")
        if kind is not None and (
                not isinstance(kind, str) or kind not in DIAGNOSTIC_KINDS):
            raise RepairError("preparation_failed", f"Invalid diagnostic kind: {kind}")
        if backend is not None and (
                not isinstance(backend, str) or backend not in BACKENDS):
            raise RepairError("preparation_failed", f"Invalid diagnostic backend: {backend}")
        selected = [
            item for item in self.records
            if (backend is None or item["backend"] == backend)
            and (kind is None or item["kind"] == kind)
            and (binding is None or item["binding"]["status"] == binding)
        ]
        page = selected[offset:offset + limit]
        return {"offset": offset, "total": len(selected), "returned": len(page),
                "records": deepcopy(page)}
