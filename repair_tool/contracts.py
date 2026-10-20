"""Shared controller/model contracts; paths in helper contents are never templated."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .config import RepairError

PLACEHOLDERS = {
    "project": "current mutable project directory",
    "poc": "original PoC snapshot FILE, never a directory",
    "poc_dir": "original PoC snapshot directory",
    "tests": "external test snapshot, available only if configured (file or directory)",
    "adapter": "fixed adapter directory, adapter stage only",
    "suite": "writable test helper copy, test stage only",
}
RUNTIME = {
    "REPAIR_PROJECT": "current project directory (also cwd)",
    "REPAIR_POC": "original PoC snapshot FILE",
    "REPAIR_POC_DIR": "PoC snapshot directory, including adjacent payloads",
    "REPAIR_POC_ARGS": "JSON array of original PoC arguments; preserve exactly",
    "REPAIR_BUILD_DIR": "CMake .repair-build; otherwise project root, not a promise of Make output location",
    "REPAIR_BUILD_ARTIFACTS": "JSON array of actual current build artifact paths relative to REPAIR_PROJECT",
}
STAGE_RUNTIME = {
    "adapter": {"REPAIR_ADAPTER": "fixed helper directory; do not modify it",
                "REPAIR_WORK": "writable scratch under project/.repair-poc"},
    "test": {"REPAIR_SUITE": "writable copy of fixed test helpers",
             "REPAIR_WORK": "writable isolated test scratch directory",
             "REPAIR_TEST_RESULT": "write PASS JSON here only after assertions succeed"},
}
CONTEXT_BATCHES = 3
CONTEXT_FILES = 20
CONTEXT_TEXT = (
    "You may return read_files (or read_files_needed) before the final answer: at most "
    f"{CONTEXT_BATCHES} additional batches, {CONTEXT_FILES} entries per batch, within context_max_bytes. "
    "Project reads are existing C/C++ sources/headers only; original PoC and adjacent text "
    "files use inputs/poc/<relative-path>. No binary, symlink or escaping paths. Use positive "
    "start_line/end_line and narrower ranges when budget is exceeded. requested_context is cumulative."
)
TEST_KINDS = {"regression": "pass", "vulnerability": "asan", "independent": None}
HELPER_MAX_FILES = 20
HELPER_MAX_BYTES = 128 * 1024
TEST_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
HELPER_FORBIDDEN = re.compile(r"\b(?:sudo|curl|wget)\b|no_sanitize|ASAN_OPTIONS\s*=|LSAN_OPTIONS\s*=")
PATCH_FORBIDDEN = re.compile(
    r"\b(?:no_sanitize\w*|disable_sanitizer_instrumentation|__asan_\w+|"
    r"exit|_exit|quick_exit|abort|system|popen|execl\w*|execv\w*|socket|connect|"
    r"setenv|putenv)\b|ASAN_OPTIONS|LSAN_OPTIONS|__SANITIZE_ADDRESS__|"
    r"__has_feature\s*\(\s*address_sanitizer", re.I)

ANALYSIS_CONTRACT = (
    "Read evidence and analyze project impact BEFORE proposing repair. Return diagnosis, evidence, "
    "affected_files (existing source/header paths only), interfaces, callers, contracts, "
    "ownership_effects, test_plan. contracts must be an array containing nonempty strings. "
    "Set contract_uncertain to boolean true ONLY when a missing behavioral contract prevents "
    "deciding which file to change or how to change it; state the missing item in reason. "
    "When the primary defect has a diagnosis, behavioral contract and repair approach, do not "
    "set this flag. Describe secondary low-confidence concerns in contracts. "
    "If more source or PoC context is needed, request "
    "{read_files:[{file:...,start_line:...,end_line:...}]} before declaring uncertainty. "
    "poc_file is supplied in the request. Project paths are relative to the project; "
    "original PoC and adjacent text files use inputs/poc/<filename>. "
    "Reassess contracts after reading requested_context."
)


def analysis_contract_decision(data: dict) -> tuple[str | None, str | None]:
    """Return a pending status/message; filesystem validation stays in allowed_files.

    A nonblocking message is a warning, committed only after file validation.
    """
    if "contract_uncertain" not in data:
        return None, None
    uncertain = data["contract_uncertain"]
    if type(uncertain) is not bool:
        return "model_output_invalid", "contract_uncertain must be a boolean, not a string, number or null"
    if not uncertain:
        return None, None
    reason = next((data[key].strip() for key in
                   ("reason", "uncertainty_reason", "contract_uncertainty_reason")
                   if isinstance(data.get(key), str) and data[key].strip()), None)
    diagnosis = data.get("diagnosis")
    contracts = data.get("contracts")
    files = data.get("affected_files")
    complete = (isinstance(diagnosis, str) and bool(diagnosis.strip()) and
                isinstance(contracts, list) and
                any(isinstance(item, str) and item.strip() for item in contracts) and
                isinstance(files, list) and bool(files) and
                all(isinstance(item, str) and item.strip() for item in files))
    if complete:
        return None, ("Impact analysis set contract_uncertain=true despite a diagnosis, behavioral "
                      "contracts and affected_files; continuing after file validation. Uncertainty: " +
                      (reason or "No nonempty reason supplied; see contracts for secondary concerns."))
    if reason:
        return "contract_information_required", reason
    return "model_output_invalid", (
        "contract_uncertain=true without complete diagnosis/contracts/affected_files or a nonempty reason. "
        "Withdraw the flag or explain in reason which missing behavioral contract changes the repair approach."
    )


def allowed_placeholders(kind: str) -> tuple[str, ...]:
    return tuple(k for k in PLACEHOLDERS if k not in {"suite", "adapter"} or
                 k == {"adapter": "adapter", "test": "suite"}.get(kind))


def runtime_env(kind: str, project: Path, poc: Path, helper: Path, *, args=(),
                work: Path | None = None, result: Path | None = None, artifacts=()) -> dict:
    values = {"REPAIR_PROJECT": str(project), "REPAIR_POC": str(poc),
              "REPAIR_POC_DIR": str(poc.parent), "REPAIR_POC_ARGS": json.dumps(list(args)),
              "REPAIR_BUILD_DIR": str(project / ".repair-build" if (project / "CMakeLists.txt").is_file() else project),
              "REPAIR_BUILD_ARTIFACTS": json.dumps(list(artifacts))}
    if kind == "adapter":
        values.update(REPAIR_ADAPTER=str(helper), REPAIR_WORK=str(project / ".repair-poc"))
    elif kind == "test":
        if work is None or result is None:
            raise ValueError("Test runtime requires work and result paths")
        values.update(REPAIR_SUITE=str(helper), REPAIR_WORK=str(work), REPAIR_TEST_RESULT=str(result))
    else:
        raise ValueError(f"Unknown runtime kind: {kind}")
    return values


def contract_text(kind: str) -> str:
    names = allowed_placeholders(kind)
    env = {**RUNTIME, **STAGE_RUNTIME[kind]}
    return ("\nRuntime contract: cwd is REPAIR_PROJECT. Placeholders are expanded ONLY in command argv; "
            "files[].content is written verbatim. Prefer os.environ in scripts, not placeholder literals. "
            f"files[].path is relative, unique; 1..{HELPER_MAX_FILES} files, <={HELPER_MAX_BYTES} UTF-8 bytes each. Python must compile; "
            "shell must pass bash -n. No sudo/curl/wget, no_sanitize or assignment to sanitizer options.\n" +
            "\n".join("{" + k + "}: " + PLACEHOLDERS[k] for k in names) + "\n" +
            "\n".join(k + ": " + v for k, v in env.items()) +
            "\nCommands are nonempty argv arrays, no shell splitting; explicitly invoke bash -c for shell code. "
            "Unrecognized placeholders in path arguments are rejected. Unavailable optional placeholders are rejected. "
            "Directories REPAIR_WORK/REPAIR_SUITE are writable; baseline, PoC, fixed helpers/tests are immutable. "
            "Use supplied build artifact catalog; Make/custom builds have no universal output layout.\n" + CONTEXT_TEXT)


def test_contract(allow_independent: bool = True) -> str:
    return ("Test IDs must fully match " + TEST_ID.pattern + "; positive integer expected_cases, nonempty basis. " +
            "; ".join(kind + " requires baseline=" + baseline for kind, baseline in TEST_KINDS.items() if baseline) +
            (". Independent entries have one baseline each; the base set needs separate pass and asan entries."
             if allow_independent else ". Only regression and vulnerability kinds are allowed; additional_tests may be omitted."))


def patch_contract(max_lines: int) -> str:
    return (f"Exact unified diff against original baseline; at most {max_lines} added+deleted lines. "
            "Headers must be --- a/path and +++ b/path. Old start lines and all old/context text must "
            "match the baseline exactly; no fuzzy search. The controller derives old/new counts and "
            "new-file offsets from hunk bodies. Pure insertion requires old count 0 and inserts after "
            "the old start line (0 means before the first line). Prefer standard unified diff headers. "
            "Every modified file must appear in affected_files and be an existing editable source/header. "
            "No creation, deletion, rename, build changes or edits to tests/PoC. "
            "Added lines (including comments) reject this case-insensitive pattern: " + PATCH_FORBIDDEN.pattern +
            ". Return strict JSON; escape newlines/backslashes inside patch strings.")


def validate_placeholder_names(command: list[str], error_status: str) -> None:
    for index, arg in enumerate(command):
        # Inline code has native braces. It is not a sequence of path operands.
        if index and command[index - 1] in {"-c", "-e"}:
            continue
        for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", arg):
            if name not in PLACEHOLDERS:
                raise RepairError(error_status, "Unknown command placeholder {" + name +
                                  "}; available names: " + ", ".join("{" + k + "}" for k in PLACEHOLDERS))
