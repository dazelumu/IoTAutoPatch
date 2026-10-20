from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

from .config import RepairError

SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
ARTIFACT_SUFFIXES = {".o", ".obj", ".a", ".so", ".dll", ".exe", ".pyc"}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "node_modules", "CMakeFiles"}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or "\\" in relative:
        raise RepairError("invalid_path", f"Invalid relative path: {relative}")
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts or not part.parts:
        raise RepairError("invalid_path", f"Path escapes project: {relative}")
    path = root / part
    resolved = path.resolve()
    if root.resolve() not in resolved.parents:
        raise RepairError("invalid_path", f"Path escapes project: {relative}")
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise RepairError("invalid_path", f"Symlink editing/reading is not allowed: {relative}")
    return path


def inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[rel] = {"link": os.readlink(path)}
        elif path.is_file():
            result[rel] = {"sha256": sha(path), "mode": stat.S_IMODE(path.stat().st_mode)}
    return result


def check_links(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            target = path.resolve()
            if not target.exists() or (target != root.resolve() and root.resolve() not in target.parents):
                raise RepairError("preparation_failed", f"External or broken symlink: {path}")


def snapshot(source: Path, destination: Path) -> None:
    check_links(source)
    git_pointer = source / ".git"
    if git_pointer.is_file():
        text = git_pointer.read_text(errors="replace").strip()
        if text.startswith("gitdir:"):
            target = (source / text.split(":", 1)[1].strip()).resolve()
            if source.resolve() not in target.parents:
                raise RepairError("preparation_failed", "External Git worktree metadata: use a standalone clone/copy")
    # Preserve repository metadata when local: build scripts may use git describe.
    shutil.copytree(source, destination, symlinks=True)
    # Absolute internal links must point into the snapshot rather than original input.
    for link in destination.rglob("*"):
        if link.is_symlink() and Path(os.readlink(link)).is_absolute():
            target = Path(os.readlink(link)).resolve().relative_to(source.resolve())
            link.unlink()
            link.symlink_to(os.path.relpath(destination / target, link.parent))


def is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(4096)
        return head.startswith((b"\x7fELF", b"MZ", b"!<arch>\n"))
    except OSError:
        return False


def clean_artifacts(project: Path) -> list[str]:
    removed = []
    for path in sorted(project.rglob("*"), reverse=True):
        if path.is_symlink() or not path.is_file():
            continue
        if (path.suffix.lower() in ARTIFACT_SUFFIXES or ".so." in path.name or
                path.name in {"CMakeCache.txt", "compile_commands.json"} or is_binary(path)):
            removed.append(path.relative_to(project).as_posix())
            path.unlink()
    for path in sorted(project.rglob("CMakeFiles"), reverse=True):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    return removed


def fresh_project(baseline: Path, destination: Path) -> list[str]:
    shutil.copytree(baseline, destination, symlinks=True)
    return clean_artifacts(destination)


def source_files(project: Path) -> list[Path]:
    return [p for p in sorted(project.rglob("*")) if p.is_file() and not p.is_symlink()
            and p.suffix.lower() in SOURCE_SUFFIXES
            and not any(part in SKIP_DIRS for part in p.relative_to(project).parts)]


def protected_source(relative: str) -> bool:
    parts = Path(relative).parts
    return any(p.lower() in {"test", "tests", "testing", "examples", "fuzz", "fuzzing"} for p in parts) or \
        Path(relative).stem.lower().startswith(("test_", "fuzz_")) or \
        Path(relative).stem.lower().endswith("_test")
