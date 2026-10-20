"""Repair-proposal contract: the model proposes, deterministic validators
decide.

A proposal is a list of edits. Each edit must cite code-site evidence, place
its site on the exact 16-byte sequence recorded in that evidence, and match
the recorded bytes (expected_hex) -- fabricating an address or bytes is
structurally impossible. ``model_code_site`` records a location selected through
the model's own investigation. The repair is a C leaf function with a declared
behaviour contract; the implant stage cross-compiles it and rejects anything
with relocations or external calls.
"""
from __future__ import annotations

import json
import re

from ..config import RepairError
from .evidence import EvidenceLedger

MAX_SOURCE_BYTES = 8192
MAX_EDITS = 4

CONTRACT_FIELDS = {"abi": r".{1,800}", "bounds": r".{1,800}",
                   "preserve": r".{1,800}", "invalid": r".{1,800}"}


def _hex16(text) -> bool:
    return isinstance(text, str) and re.fullmatch(r"[0-9a-fA-F]{32}", text) is not None


def validate_proposal(proposal, ledger: EvidenceLedger, *, target_sha: str | None = None) -> dict:
    """Validate one model proposal against the ledger. Returns the sanitized
    proposal or raises with a machine-readable reason. Explanatory keys the
    model sometimes adds (analysis/notes/explanation) are tolerated -- they
    are dropped from the sanitized result."""
    if not isinstance(proposal, dict):
        raise RepairError("model_output_invalid",
                          "Proposal must contain exactly edits (+ optional rationale)")
    explanatory = {"analysis", "notes", "explanation", "comment", "comments"}
    extra = set(proposal) - {"edits", "rationale"} - explanatory
    if extra:
        raise RepairError("model_output_invalid",
                          "Proposal must contain exactly edits (+ optional "
                          f"rationale); unexpected keys: {sorted(extra)}")
    edits = proposal.get("edits")
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_EDITS:
        raise RepairError("model_output_invalid",
                          f"Between 1 and {MAX_EDITS} edits required")
    if target_sha is not None and ledger.target_sha != target_sha:
        raise RepairError("model_output_invalid",
                          "Evidence ledger belongs to a different target build")
    clean = []
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) - {"site", "expected_hex",
                                                      "evidence", "contract", "source"}:
            raise RepairError("model_output_invalid",
                              "Edit fields: site, expected_hex, evidence, contract, source")
        site = edit.get("site")
        if type(site) is not int or not 0x1000 < site < 0x80000000 or site % 4 != 0:
            raise RepairError("model_output_invalid",
                              "site must be a word-aligned 32-bit virtual address")
        if any(abs(e["site"] - site) < 16 for e in clean):
            raise RepairError("model_output_invalid", "Duplicate or overlapping edit sites")
        if not _hex16(edit.get("expected_hex")):
            raise RepairError("model_output_invalid",
                              "expected_hex must be 16 bytes hex (the site sequence)")
        cited = edit.get("evidence")
        if not isinstance(cited, list) or not cited \
                or not all(isinstance(e, str) for e in cited):
            raise RepairError("model_output_invalid",
                              "evidence must be a non-empty list of ledger ids")
        entries = []
        for evidence_id in cited:
            entry = ledger.get(evidence_id)
            if entry is None:
                raise RepairError("model_output_invalid",
                                  f"Unknown evidence id: {evidence_id}")
            if entry.get("kind") == "model_code_site" and ledger.code_site_rejected(evidence_id):
                raise RepairError("model_output_invalid",
                                  "Proposal cites rejected nomination evidence")
            entries.append(entry)
        anchors = [e for e in entries if e["kind"] == "model_code_site"]
        if not anchors:
            raise RepairError("model_output_invalid",
                              "No model_code_site evidence cited; register a "
                              "model-selected redirectable call site before "
                              "proposing")
        if not any(a["site"] == site and a["bytes_hex"].lower() == edit["expected_hex"].lower()
                   for a in anchors):
            raise RepairError("model_output_invalid",
                              "site/expected_hex do not match any cited evidence "
                              "(fabricated or stale edit)")
        contract = edit.get("contract")
        if not isinstance(contract, dict) or set(contract) - set(CONTRACT_FIELDS):
            raise RepairError("model_output_invalid",
                              "contract requires fields: " + ", ".join(CONTRACT_FIELDS))
        for field, pattern in CONTRACT_FIELDS.items():
            value = contract.get(field)
            if not isinstance(value, str) or not re.fullmatch(pattern, value, re.DOTALL):
                raise RepairError("model_output_invalid",
                                  f"contract.{field} must be 1..800 chars")
        source = edit.get("source")
        if not isinstance(source, str) or not 16 <= len(source) <= MAX_SOURCE_BYTES:
            raise RepairError("model_output_invalid",
                              f"source must be {16}..{MAX_SOURCE_BYTES} chars of C")
        clean.append({"site": site,
                      "expected_hex": edit["expected_hex"].lower(),
                      "evidence": cited,
                      "contract": {f: contract[f] for f in CONTRACT_FIELDS},
                      "source": source})
    rationale = proposal.get("rationale")
    if rationale is not None and (not isinstance(rationale, str)
                                  or not 1 <= len(rationale) <= 2000):
        raise RepairError("model_output_invalid", "rationale must be 1..2000 chars")
    return {"edits": clean, **({"rationale": rationale} if rationale is not None else {})}


def candidate_payload(entry: dict) -> dict:
    """Return only fields needed to cite one model-selected code site."""
    return {"evidence": entry.get("evidence", entry.get("id")),
            "site": entry["site"], "bytes_hex": entry["bytes_hex"]}


def proposal_prompt(localization: dict, fault: dict, *, rounds_left: int) -> str:
    """Prompt for one repair round using only model-selected code sites."""
    candidates = localization.get("model_code_sites", [])
    listing = "\n".join(
        "  - " + json.dumps(candidate_payload(c), separators=(",", ":"),
                            ensure_ascii=False)
        for c in candidates[:40])
    if not listing:
        listing = "  (no model-selected code-site evidence supplied)"
    candidates_block = f"""Code sites selected during model localization:
Each item is one evidence record. Use its evidence id and copy its site and
bytes_hex exactly.
{listing}"""
    return f"""Target: MIPS32 big-endian ELF (sha256 {localization['target_sha256'][:16]}...).
Confirmed fault: request {fault['request'].get('method', 'GET')} {fault['request']['path']} causes {fault.get('signal', 'fatal exit')} in the
target process (pid {fault['exit_record'].get('pid')}) -- kernel-backed exit evidence.

{candidates_block}

You must output ONE repair proposal as JSON:
{{"edits": [{{"site": <vaddr int>, "expected_hex": "<16 bytes hex of the site>",
             "evidence": ["e3"], "contract": {{"abi": "...", "bounds": "...",
             "preserve": "...", "invalid": "..."}},
             "source": "<complete C source>"}}]}}

Rules:
- site+expected_hex MUST copy one selected code-site record above exactly.
- evidence MUST cite that record's evidence id.
- source must define exactly one function named `repair_entry`. It must be a
  self-contained leaf: no external calls, libc, globals, or helper functions.
- Infer the parameter use, original semantics, safety conditions, and repair
  behavior from the cited disassembly and query evidence. Do not assume a
  fixed C prototype or a predetermined repair algorithm.
- contract: abi=the inferred calling convention; bounds=memory access
  assumptions and limits; preserve=behavior retained for valid inputs;
  invalid=behavior for invalid inputs.
- The compiler is clang --target=mips-linux-gnu -march=mips32 -EB -G0; the
  generated object must satisfy the leaf-function restrictions above.
- rounds_left: {rounds_left}. If the supplied evidence and failure feedback
  are insufficient, investigate in the localization/relocalization phase
  instead of guessing; only return the proposal JSON when you can justify
  the cited edit.
"""
