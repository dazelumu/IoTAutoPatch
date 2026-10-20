"""Evidence organization for the localization stage.

Evidence classes have stable ids (e1, e2, ...):
  model_code_site  - an address supplied by the model, registered only after
                     its redirectable instruction shape is verified
  runtime_exit     - a kernel-backed exit event (annotated: bound to the
                     registered instance pid/sha256)
  model_query      - a query the model issued and its bounded answer

The three-level localization chain is: binary -> function -> call site.
Functions come from ELF symbols; the model must connect levels with query
answers, never with invented addresses.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..arch.mips32 import ElfAnalysis
from ..storage import sha

MAX_FUNCTION_RANGE = 0x10000


class EvidenceLedger:
    """Append-only ledger; every claim in later stages cites ledger ids."""

    def __init__(self, root: Path, target_path: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.target_path = Path(target_path)
        self.target_sha = sha(self.target_path)
        self.entries: list[dict] = []
        self.load()

    def load(self):
        path = self.root / "evidence-ledger.json"
        if path.is_file():
            self.entries = json.loads(path.read_text(encoding="utf-8"))

    def save(self):
        path = self.root / "evidence-ledger.json"
        path.write_text(json.dumps(self.entries, indent=2), encoding="utf-8")

    def add(self, kind: str, payload: dict) -> str:
        evidence_id = f"e{len(self.entries) + 1}"
        payload = dict(payload)
        if payload.get("target_sha256") is None:
            payload["target_sha256"] = self.target_sha
        self.entries.append({"id": evidence_id, "kind": kind,
                             "time": time.time(), "target_sha256": self.target_sha,
                             **payload})
        self.save()
        return evidence_id

    def get(self, evidence_id: str) -> dict | None:
        return next((e for e in self.entries if e["id"] == evidence_id), None)

    def by_kind(self, kind: str) -> list[dict]:
        return [e for e in self.entries if e["kind"] == kind]

    def ids(self) -> list[str]:
        return [e["id"] for e in self.entries]

    def code_site_rejected(self, evidence_id: str) -> bool:
        entry = self.get(evidence_id)
        return bool(entry and (
            entry.get("nomination_status") == "rejected"
            or any(event.get("evidence") == evidence_id
                   and event.get("decision") == "rejected"
                   for event in self.by_kind("nomination_decision"))))

    def reject_code_site(self, evidence_id: str, *, session_id: str,
                         semantic_class: str) -> str:
        """Append a terminal rejection without rewriting historical evidence."""
        entry = self.get(evidence_id)
        if entry is None or entry.get("kind") != "model_code_site":
            raise ValueError("A nomination decision requires code-site evidence")
        return self.add("nomination_decision", {
            "evidence": evidence_id, "decision": "rejected",
            "session_id": session_id, "semantic_class": semantic_class,
        })


def register_model_code_site(ledger: EvidenceLedger, analysis: ElfAnalysis,
                             site: int) -> str:
    """Verify and register the concrete patch address selected by the model.

    Nothing is scanned or ranked here.  ``site`` must already be present in
    the model's query, and the architecture backend must verify that the exact
    bytes at that address form a redirectable indirect call sequence.
    """
    call = analysis.indirect_call_at(site)
    return ledger.add("model_code_site", {
        "annotation": "model-supplied address; redirectable call shape verified",
        "nomination_status": "pending",
        "site": call["vaddr"],
        "bytes_hex": call["bytes_hex"],
        "function": containing_function(analysis, site),
        "callee": call["callee"],
        "got_vaddr": call["got_vaddr"],
        "got_value": call["got_value"],
        "delay_slot_hex": call["delay_slot_hex"],
    })


def containing_function(analysis: ElfAnalysis, vaddr: int) -> dict | None:
    """Smallest STT_FUNC symbol containing vaddr."""
    best = None
    for symbol in analysis.symbol_records:
        if symbol["type"] != "STT_FUNC":
            continue
        name, value, size = symbol["name"], symbol["value"], symbol["size"]
        if not value or value > vaddr:
            continue
        if size and vaddr >= value + size:
            continue
        if vaddr - value <= MAX_FUNCTION_RANGE:
            if best is None or value > best["value"]:
                best = {"name": name, "value": value, "size": size}
    return best


def register_runtime_exits(ledger: EvidenceLedger, exits: list[dict]) -> list[str]:
    ids = []
    for record in exits:
        evidence_id = ledger.add("runtime_exit", {
            "annotation": "kernel-backed waitpid event; pid/sha256 bound",
            "pid": record.get("pid"), "signal": record.get("signal_name"),
            "intentional": record.get("intentional"),
            "record": record})
        ids.append(evidence_id)
    return ids


def localization_view(ledger: EvidenceLedger, analysis: ElfAnalysis) -> dict:
    """Compact view of evidence the model created plus observed exits."""
    code_sites = []
    for entry in ledger.by_kind("model_code_site"):
        if ledger.code_site_rejected(entry["id"]):
            continue
        code_sites.append({"evidence": entry["id"], "site": entry["site"],
                           "bytes_hex": entry["bytes_hex"]})
    exits = [{"evidence": e["id"], "signal": e["signal"], "pid": e["pid"]}
             for e in ledger.by_kind("runtime_exit")]
    return {"target_sha256": ledger.target_sha,
            "levels": ["binary", "function", "call_site"],
            "model_code_sites": code_sites,
            "runtime_exits": exits}
