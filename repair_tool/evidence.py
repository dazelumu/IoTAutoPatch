from __future__ import annotations

import re
from pathlib import Path

from .config import RepairError
from .contracts import CONTEXT_FILES
from .storage import is_binary, safe_file, source_files, SKIP_DIRS


def parse_asan(text: str, project: Path, catalog: set[str] | None = None) -> dict:
    error = re.search(r"ERROR: AddressSanitizer: ([\w-]+)", text)
    access = re.search(r"(READ|WRITE) of size (\d+)", text)
    frames = []
    available = set(source_files(project))
    for line in text.splitlines():
        if not re.match(r"\s*#\d+\s", line):
            continue
        location = re.search(r"([^\s()]+\.(?:c|h|cc|cpp|cxx|hpp|hh)):(\d+)(?::\d+)?", line)
        item = {"raw": line.strip()}
        if location:
            path = Path(location[1])
            try:
                relative = path.resolve().relative_to(project.resolve()).as_posix() if path.is_absolute() else path.as_posix()
                source = safe_file(project, relative)
                if (not source.is_file() or source not in available or
                        any(p.startswith(".repair-") for p in Path(relative).parts) or
                        (catalog is not None and relative not in catalog)):
                    raise ValueError("Not an original project source frame")
                item.update({"file": relative, "line": int(location[2])})
            except (ValueError, RepairError):
                # External library frames are preserved as text, not opened.
                item["external"] = True
        frames.append(item)
    return {"type": error[1] if error else None,
            "access": access[1] if access else None, "size": int(access[2]) if access else None,
            "frames": frames}


def fingerprint(evidence: dict) -> tuple:
    return (evidence["type"], evidence["access"],
            tuple((f.get("file"), f.get("line")) for f in evidence["frames"] if "file" in f)[:3])


def function_context(path: Path, line: int) -> tuple[str, str]:
    data = path.read_bytes()
    lines = data.decode("utf-8", errors="replace").splitlines()
    try:
        from tree_sitter import Language, Parser
        if path.suffix in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}:
            import tree_sitter_cpp as grammar
        else:
            import tree_sitter_c as grammar
        parser = Parser(Language(grammar.language()))
        tree = parser.parse(data)
        row = max(0, line - 1)
        node = tree.root_node.descendant_for_point_range((row, 0), (row, 0))
        while node and node.type != "function_definition":
            node = node.parent
        if node and not node.has_error:
            start, end = node.start_point.row, node.end_point.row + 1
            return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, min(end, len(lines)))), "tree-sitter function"
    except (ImportError, ValueError, TypeError, IndexError):
        pass
    start, end = max(0, line - 31), min(len(lines), line + 30)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end)), "fallback line window (incomplete)"


def initial_context(project: Path, evidence: dict, limit: int) -> dict:
    snippets, used = {}, 0
    for frame in evidence["frames"]:
        if "file" not in frame or frame["file"] in snippets:
            continue
        path = safe_file(project, frame["file"])
        if not path.is_file():
            continue
        text, mode = function_context(path, frame["line"])
        size = len(text.encode())
        if used + size > limit:
            break
        snippets[frame["file"]] = {"mode": mode, "text": text}
        used += size
    # Include a catalog for requesting call sites/types/headers across files.
    catalog = [p.relative_to(project).as_posix() for p in source_files(project)]
    docs = {}
    for path in sorted(project.iterdir()):
        if path.is_file() and path.name.lower().startswith(("readme", "contributing")):
            text = path.read_text(errors="replace")[:8000]
            size = len(text.encode())
            if used + size <= limit:
                docs[path.name] = text
                used += size
    return {"snippets": snippets, "catalog": catalog[:2000], "catalog_truncated": len(catalog) > 2000,
            "documentation": docs}


def read_requested(project: Path, requests: list, limit: int, poc_root: Path | None = None) -> dict:
    result, used = {}, 0
    if len(requests) > CONTEXT_FILES:
        raise ValueError(f"At most {CONTEXT_FILES} context entries per batch")
    for request in requests:
        if isinstance(request, str):
            request = {"file": request}
        if not isinstance(request, dict) or not isinstance(request.get("file"), str):
            raise ValueError("Each read_files entry must be a path or an object with a string file")
        relative = request["file"]
        if relative.startswith("inputs/poc/"):
            if poc_root is None:
                raise ValueError("PoC snapshot is unavailable for context reads")
            path = safe_file(poc_root, relative[len("inputs/poc/"):])
            if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(poc_root).parts):
                raise ValueError("Only existing PoC snapshot text files may be requested")
            with path.open("rb") as handle:
                head = handle.read(4096)
            if is_binary(path) or b"\x00" in head:
                raise ValueError("Binary PoC files cannot be requested as text context")
        else:
            path = safe_file(project, relative)
            if path not in source_files(project):
                raise ValueError("Only project C/C++ sources and headers or inputs/poc/ text files may be requested")
        lines = path.read_text(errors="replace").splitlines()
        start = request.get("start_line", 1)
        end = request.get("end_line", len(lines))
        if (isinstance(start, bool) or not isinstance(start, int) or start < 1 or
                isinstance(end, bool) or not isinstance(end, int) or end < start):
            raise ValueError("Context ranges require positive integer start_line <= end_line")
        end = min(len(lines), end)
        text = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start - 1, end))
        if used + len(text.encode()) > limit:
            result[request["file"]] = {"error": "Context budget exceeded; request a narrower range"}
            continue
        result[request["file"]] = {"text": text}
        used += len(text.encode())
    return result
