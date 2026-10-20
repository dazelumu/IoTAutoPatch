"""Bounded feedback with prior attempts; complete responses remain in audit files."""
from __future__ import annotations

import json
import re

from .contracts import PLACEHOLDERS


def attempt_summary(data) -> dict:
    if not isinstance(data, dict):
        return {}
    # Never expose holdout details to repair requests, including added tests.
    public = {k: v for k, v in data.items() if k != "additional_tests"}
    if isinstance(data.get("additional_tests"), list):
        public["additional_tests"] = [t for t in data["additional_tests"] if isinstance(t, dict)
                                      and t.get("kind") in ("regression", "vulnerability")]
    serialized = json.dumps(public, ensure_ascii=False)
    if len(serialized) > 24000:
        # Keep the launcher invocation available even when a large helper is first.
        command = public.get("command", [])
        return {"command": [arg[:256] for arg in command[:16] if isinstance(arg, str)]
                           if isinstance(command, list) else [],
                "output_excerpt": serialized[:16000], "truncated": True}
    return public


def helper_hints(files) -> list[str]:
    hints = []
    for file in files or []:
        if isinstance(file, dict) and isinstance(file.get("content"), str):
            found = ["{" + k + "}" for k in PLACEHOLDERS if "{" + k + "}" in file["content"]]
            if found:
                hints.append(f"Possible literal placeholder in {file.get('path')}: {', '.join(found)}. "
                             "Helper contents are not expanded; use REPAIR_* env or argv. "
                             "Native f-string/dict braces may be intentional.")
    return hints


def failure_feedback(stage: str, exc, attempts: list, data=None) -> dict:
    data = getattr(exc, "model_output", data)
    category = getattr(exc, "status", "model_output_invalid")
    error = str(exc)
    try:
        observed = json.loads(error)
    except (ValueError, TypeError):
        observed = {"error": error}
    if not isinstance(observed, dict):
        observed = {"error": observed}
    excerpt = observed.pop("log_excerpt", "")
    if len(json.dumps(observed, ensure_ascii=False)) > 12000:
        observed = {"excerpt": json.dumps(observed, ensure_ascii=False)[:12000], "truncated": True}
    rules = {
        "model_output_invalid": "Follow the output/runtime schema; helpers are literal files and paths come from argv/env.",
        "adapter_execution_failed": "Launcher must execute current target and propagate diagnostics/status.",
        "binding_failed": "Require complete trace and successful exec/load of a fresh ASan target in the reporting image.",
        "generated_test_failed": "Require target binding, unchanged project, valid PASS assertions or matching baseline ASan.",
        "patch_rejected": "Exact baseline diff, allowed existing sources, correct hunks and no forbidden added behavior.",
        "invalid_path": "Only existing permitted files within the snapshot may be read or patched.",
    }
    raw_files = data.get("files", []) if isinstance(data, dict) else []
    files = list(raw_files) if isinstance(raw_files, list) else []
    if isinstance(data, dict) and isinstance(data.get("tests"), list):
        files += [f for t in data["tests"] if isinstance(t, dict) and isinstance(t.get("files"), list)
                  for f in t["files"]]
    hints = helper_hints(files)
    if re.search(r"\{(?:project|poc|suite|adapter)\}", error + excerpt):
        hints.append("A literal path placeholder may have reached the process; helper contents are not templated.")
    if "Invalid \\escape" in error:
        hints.append("Return strict JSON; encode a literal backslash as \\\\.")
    result = observed.get("result", observed)
    command = result.get("command", []) if isinstance(result, dict) else []
    if isinstance(command, list) and any(arg == "" for arg in command):
        hints.append("Observed empty argv argument; verify required path arguments. Original empty PoC args may be intentional.")
    if re.search(r"[/\\]([^/\\\s]+\.[A-Za-z0-9]+)[/\\]\1(?:\b|$)", error + excerpt):
        hints.append("Possible file-as-directory path: a filename is repeated in adjacent path components; use REPAIR_POC for the file.")
    attempts.append({"category": category, "output": attempt_summary(data)})
    return {"stage": stage, "category": category, "status": category,
            "rule": observed.get("rule", rules.get(category, "Follow the stated stage contract and inspect the execution evidence.")),
            "observed": observed, "error": error[:16000], "log_excerpt": excerpt[:12000],
            "hints": hints[:10], "previous_attempts": attempts[-2:]}
