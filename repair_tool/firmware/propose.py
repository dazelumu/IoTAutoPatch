"""Repair-proposal contract: the model proposes, deterministic validators
decide.

A proposal is a list of edits. Each edit must cite code-site evidence, place
its site on the exact 16-byte sequence recorded in that evidence, and match
the recorded bytes (expected_hex) -- fabricating an address or bytes is
structurally impossible. ``model_code_site`` records a location selected through
the model's own investigation. A normal edit is a C leaf function. A wrapper
edit supplies only the C decision function; the controller generates the
call-preservation trampoline. The implant stage cross-compiles the result and
rejects unsupported relocations or external calls.
"""
from __future__ import annotations

import json
import re

from ..config import RepairError
from .evidence import EvidenceLedger

MAX_SOURCE_BYTES = 8192
MAX_EDITS = 4
MAX_REJECTION_REASON_CHARS = 2000

CONTRACT_FIELDS = {"abi": r".{1,800}", "bounds": r".{1,800}",
                   "preserve": r".{1,800}", "invalid": r".{1,800}"}


def _hex16(text) -> bool:
    return isinstance(text, str) and re.fullmatch(r"[0-9a-fA-F]{32}", text) is not None


def _contains_local_path(text: str) -> bool:
    return re.search(
        r"(?:[A-Za-z]:[\\/][^\r\n]+|"
        r"/(?:tmp|mnt|home|root|Users|var|opt|workspace)(?:/[^\r\n]+)?)",
        text) is not None


def _validate_semantic_rejection(proposal: dict) -> dict:
    """Validate the one controlled no-edit outcome.

    An empty edit list is not a generic escape hatch.  It means the currently
    selected redirect site cannot preserve required valid behavior, so the
    controller must relocalize instead of forcing the model to fabricate a
    leaf replacement.
    """
    allowed = {"edits", "rejection_reason", "retry_scope", "rationale"}
    extra = set(proposal) - allowed
    if extra:
        raise RepairError("model_output_invalid",
                          "Semantic rejection has unexpected top-level keys: "
                          f"{sorted(extra)}")
    reason = proposal.get("rejection_reason")
    if (not isinstance(reason, str) or not 20 <= len(reason)
            <= MAX_REJECTION_REASON_CHARS or _contains_local_path(reason)):
        raise RepairError(
            "model_output_invalid",
            "rejection_reason must be 20..2000 chars and contain no local path")
    if proposal.get("retry_scope", "relocalize") != "relocalize":
        raise RepairError("model_output_invalid",
                          "A semantic rejection must request relocalize")
    clean = {"edits": [], "rejection_reason": reason,
             "retry_scope": "relocalize"}
    rationale = proposal.get("rationale")
    if rationale is not None:
        if not isinstance(rationale, str) or not 1 <= len(rationale) <= 2000:
            raise RepairError("model_output_invalid",
                              "rationale must be 1..2000 chars")
        clean["rationale"] = rationale
    return clean


def validate_proposal(proposal, ledger: EvidenceLedger, *, target_sha: str | None = None) -> dict:
    """Validate one model proposal against the ledger. Returns the sanitized
    proposal or raises with a machine-readable reason. Explanatory keys the
    model sometimes adds (analysis/notes/explanation) are tolerated -- they
    are dropped from the sanitized result."""
    if not isinstance(proposal, dict):
        raise RepairError("model_output_invalid",
                          "Proposal must contain exactly edits (+ optional rationale)")
    explanatory = {"analysis", "notes", "explanation", "comment", "comments"}
    semantic_keys = {"rejection_reason", "retry_scope"}
    extra = (set(proposal) - {"edits", "rationale"} - semantic_keys
             - explanatory)
    if extra:
        raise RepairError("model_output_invalid",
                          "Proposal must contain exactly edits (+ optional "
                          f"rationale); unexpected keys: {sorted(extra)}")
    edits = proposal.get("edits")
    if edits == []:
        return _validate_semantic_rejection(proposal)
    if set(proposal) & semantic_keys:
        raise RepairError("model_output_invalid",
                          "Semantic rejection keys require an empty edits list")
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_EDITS:
        raise RepairError("model_output_invalid",
                          f"Between 1 and {MAX_EDITS} edits required")
    if target_sha is not None and ledger.target_sha != target_sha:
        raise RepairError("model_output_invalid",
                          "Evidence ledger belongs to a different target build")
    clean = []
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) - {"site", "expected_hex",
                                                      "evidence", "contract",
                                                      "source", "mode"}:
            raise RepairError("model_output_invalid",
                              "Edit fields: site, expected_hex, evidence, "
                              "contract, source, mode")
        mode = edit.get("mode", "leaf")
        if mode not in {"leaf", "wrapper"}:
            raise RepairError("model_output_invalid",
                              "edit.mode must be leaf or wrapper")
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
                      "mode": mode,
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
    request = fault.get("request") if isinstance(fault.get("request"), dict) else {}
    if request.get("method") is not None and request.get("path") is not None:
        fault_description = (
            f"request {request.get('method', 'GET')} {request['path']} causes "
            f"{fault.get('signal', 'fatal exit')}")
    else:
        marker = fault.get("marker") if isinstance(fault.get("marker"), dict) else {}
        marker_description = ""
        if marker:
            marker_description = (
                f" The confirmed marker is {marker.get('guest_path')!r}"
                f" (created={bool(marker.get('created'))}, "
                f"empty={bool(marker.get('empty'))}).")
        fault_description = (
            f"outcome {fault.get('outcome', 'fault confirmed')} under protocol "
            f"{fault.get('protocol', 'unknown')}.{marker_description}")
    exit_record = (fault.get("exit_record")
                   if isinstance(fault.get("exit_record"), dict) else {})
    pid_description = (
        f" in target process (pid {exit_record.get('pid')})"
        if exit_record.get("pid") is not None else
        " with stable target identity and no fatal exit")
    candidates_block = f"""Code sites selected during model localization:
Each item is one evidence record. Use its evidence id and copy its site and
bytes_hex exactly.
{listing}"""
    localization_rules = """Critical localization/feedback rules:
- The already selected site is not mandatory when prior candidate feedback
  shows that its layer cannot preserve required behavior. In that case return
  the explicit semantic rejection form so the controller relocalizes; do not
  invent a leaf replacement that guesses behavior.
- A command sink, input lookup, and state lookup have different effects on
  valid requests. A replacement that returns a status cannot perform the
  original callee's effect. Only propose an edit when the cited call evidence
  shows how both the confirmed invalid trigger and every required control
  request are preserved or safely bypassed.
- Feedback with retry_scope=relocalize is authoritative evidence that the
  previous site or call layer failed validation. It overrides rounds_left;
  semantic rejection is preferable to another deployment from the same unsafe
  layer.
- Feedback with retry_scope=same_localization and controller_required_edits
  means the controller authorized one wrapper-predicate correction. Keep every
  required site and mode exactly unchanged and correct only repair_entry. Do
  not spend that correction on a new site or a leaf mode."""
    return f"""Target: MIPS32 big-endian ELF (sha256 {localization['target_sha256'][:16]}...).
Confirmed fault: {fault_description}{pid_description}.

{candidates_block}

{localization_rules}

You must output exactly ONE of two JSON forms.

Normal repair proposal:
{{"edits": [{{"site": <vaddr int>, "expected_hex": "<16 bytes hex of the site>",
             "evidence": ["e3"], "contract": {{"abi": "...", "bounds": "...",
             "preserve": "...", "invalid": "..."}},
             "mode": "leaf",
             "source": "<complete C source>"}}]}}

Semantic rejection (only when the already selected site cannot preserve a
required valid behavior; do not use it for missing evidence):
{{"edits": [], "rejection_reason": "<why no leaf replacement at this site can
preserve the observed valid behavior>", "retry_scope": "relocalize"}}

Rules:
- site+expected_hex MUST copy one selected code-site record above exactly.
- evidence MUST cite that record's evidence id.
- source must define exactly one function named `repair_entry`.
- mode=leaf is the default when mode is omitted: source must be a
  self-contained leaf replacement with no external calls, libc, globals, or
  helper functions.
- mode=wrapper: source must still define exactly one C function
  `repair_entry`, and it must only decide whether to permit the original call.
  Return 0 to call the original callee with all original arguments; return
  nonzero to block the original call. Do not call or reimplement the original
  callee. The controller generates the trampoline and derives the original
  callee from the verified call site; never hard-code an address in C.
- For a wrapper, derive the decision from the actual command/argument format
  and attacker-controlled fragment. Do not reject merely because any shell
  metacharacter occurs anywhere in the whole vendor command: a legitimate
  command may contain such characters outside attacker-controlled data. You
  must justify why every required valid/control request returns 0. If you
  cannot prove that, return semantic rejection instead of guessing.
- Do not use string literals, compound literals, static/const data, or other
  constants that require an allocated data section. The object must contain
  executable `.text` only; derive pointers from the caller-provided arguments
  when an empty string is needed.
- Infer the parameter use, original semantics, safety conditions, and repair
  behavior from the cited disassembly and query evidence. Do not assume a
  fixed C prototype or a predetermined repair algorithm.
- The redirect replaces the original call. A leaf replacement cannot perform
  the original callee's external effect. If valid requests depend on that
  effect and the call arguments are already available at the selected site,
  prefer mode=wrapper: return nonzero only for the confirmed invalid trigger
  and return 0 for required valid triggers. If neither leaf nor wrapper can
  preserve the observed valid behavior, return the explicit semantic
  rejection form. Never fabricate a patch merely to make edits non-empty.
- contract: abi=the inferred calling convention; bounds=memory access
  assumptions and limits; preserve=behavior retained for valid inputs;
  invalid=behavior for invalid inputs.
- contract.preserve must reference observed valid/control behavior, and
  contract.invalid must explain how the confirmed malicious trigger is blocked.
- The compiler is clang --target=mips-linux-gnu -march=mips32 -EB -G0; the
  generated object must satisfy the leaf-function restrictions above.
- rounds_left: {rounds_left}. If the supplied evidence and failure feedback
  are insufficient, investigate in the localization/relocalization phase
  instead of guessing; only return the proposal JSON when you can justify
  the cited edit.
"""
