from __future__ import annotations

import re
from pathlib import Path

from .config import RepairError
from .contracts import PATCH_FORBIDDEN
from .storage import SOURCE_SUFFIXES, protected_source, safe_file

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")
SUSPICIOUS = PATCH_FORBIDDEN


def apply_patch(project: Path, diff: str, allowed: set[str], max_lines: int) -> list[str]:
    """Apply hunks at exact old positions, deriving counts from their bodies."""
    lines = diff.splitlines(keepends=True)
    if not lines:
        raise RepairError("patch_rejected", "Empty patch")
    index, changed, edits = 0, 0, {}
    while index < len(lines):
        line = lines[index]
        if line.startswith("diff --git ") or line.startswith("index "):
            index += 1
            continue
        if not line.startswith("--- a/"):
            raise RepairError("patch_rejected", f"Unsupported patch line: {line[:100]}")
        old = line[len("--- a/"):].rstrip("\r\n")
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ b/"):
            raise RepairError("patch_rejected", "Missing +++ b/path header")
        new = lines[index][len("+++ b/"):].rstrip("\r\n")
        index += 1
        if old != new or old in edits:
            raise RepairError("patch_rejected", "Rename, creation, deletion or duplicate file patch")
        path = safe_file(project, old)
        if Path(old).suffix.lower() not in SOURCE_SUFFIXES or protected_source(old):
            build_file = Path(old).name in {"Makefile", "makefile", "CMakeLists.txt", "configure", "configure.ac", "meson.build"} or \
                Path(old).suffix.lower() == ".cmake"
            raise RepairError("needs_build_change" if build_file else "patch_rejected",
                              f"Protected/non-source file: {old}")
        if old not in allowed or not path.is_file():
            raise RepairError("patch_rejected", f"File not justified in impact analysis: {old}")
        original = path.read_bytes().decode("utf-8").splitlines(keepends=True)
        output, cursor, hunks = [], 0, 0
        def reject(message):
            raise RepairError("patch_rejected", f"{old}, hunk {hunks + 1}: {message}")
        while index < len(lines) and lines[index].startswith("@@ "):
            match = HUNK.match(lines[index].rstrip("\r\n"))
            if not match:
                reject("Malformed hunk")
            old_start = int(match[1])
            header_old_count = int(match[2]) if match[2] is not None else 1
            index += 1
            before, after = [], []
            previous = None
            while index < len(lines) and not lines[index].startswith(("@@ ", "--- a/", "diff --git ")):
                body = lines[index]
                if body.startswith("\\ No newline at end of file"):
                    if previous in {" ", "-"} and before:
                        before[-1] = before[-1].rstrip("\r\n")
                    if previous in {" ", "+"} and after:
                        after[-1] = after[-1].rstrip("\r\n")
                elif body and body[0] in " +-":
                    previous = body[0]
                    text = body[1:]
                    if previous in " -":
                        before.append(text)
                    if previous in " +":
                        after.append(text)
                    if previous in "+-":
                        changed += 1
                    if previous == "+" and SUSPICIOUS.search(text):
                        raise RepairError("patch_rejected", f"Suspicious added behavior in {old}: {text.strip()}")
                else:
                    reject("Invalid hunk body")
                index += 1
            if not before and not after:
                reject("Hunk has no changes or context")
            if not before and header_old_count != 0:
                reject("Hunk declares existing lines but body has none")
            # Pure insertion anchors after old_start; otherwise old_start is 1-based.
            pos = old_start if not before else old_start - 1
            if pos < cursor or pos > len(original):
                reject("Overlapping/out-of-range hunk")
            output.extend(original[cursor:pos])
            if before and original[pos:pos + len(before)] != before:
                baseline = original[pos:pos + len(before)]
                first = next((i for i, (a, b) in enumerate(zip(baseline, before)) if a != b), min(len(baseline), len(before)))
                reject(f"Patch does not match baseline exactly at line {pos + first + 1}: "
                       f"baseline={baseline[first][:200]!r} vs patch={before[first][:200]!r}" if first < len(baseline) and first < len(before)
                       else "Patch does not match baseline exactly: baseline ends before hunk")
            output.extend(after)
            cursor = pos + len(before)
            hunks += 1
        if not hunks:
            raise RepairError("patch_rejected", "File patch has no hunks")
        output.extend(original[cursor:])
        edits[old] = "".join(output).encode("utf-8")
    if not changed or changed > max_lines:
        raise RepairError("patch_rejected", f"Changed lines {changed} exceed allowed range 1..{max_lines}")
    # Validate every hunk before mutating any file.
    for relative, content in edits.items():
        safe_file(project, relative).write_bytes(content)
    return sorted(edits)
