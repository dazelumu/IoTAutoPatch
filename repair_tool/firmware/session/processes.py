"""Generic Linux process identity and session cleanup helpers.

These functions deliberately know nothing about DIR-825, httpd, or a device
brand. Device profiles compose them with their own target identity policy.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path


def sha(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def alive(pid: int) -> bool:
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except (OSError, ValueError):
        return False


def process_cmdline(pid: int) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None


def process_matches(pid: int, marker: bytes) -> bool:
    if not pid or not alive(pid):
        return False
    cmdline = process_cmdline(pid)
    return cmdline is not None and marker in cmdline


def process_start_id(pid: int) -> str | None:
    """Return Linux /proc start ticks so PID reuse cannot preserve identity."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return fields[19]
    except (OSError, IndexError):
        return None


def process_identity(pid: int) -> dict:
    """Collect bounded, local-only /proc facts for a cleanup failure."""
    identity: dict = {"pid": pid}
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text()
        fields = stat_text.rsplit(") ", 1)[1].split()
        identity.update({
            "state": fields[0] if fields else None,
            "ppid": int(fields[1]) if len(fields) > 1 else None,
            "pgrp": int(fields[2]) if len(fields) > 2 else None,
            "session": int(fields[5]) if len(fields) > 5 else None,
        })
    except (OSError, ValueError, IndexError):
        pass
    cmdline = process_cmdline(pid)
    identity["cmdline"] = (
        cmdline.replace(b"\0", b" ").decode(errors="replace").strip()
        if cmdline is not None else None
    )
    start_id = process_start_id(pid)
    if start_id is not None:
        identity["process_start_id"] = start_id
    return identity


def listener_pids(port: int) -> set[int]:
    """Resolve LISTEN socket inodes for *port* back to namespace PIDs."""
    inodes: set[str] = set()
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if local_port == port:
                inodes.add(fields[9])
    if not inodes:
        return set()

    owners: set[int] = set()
    for process_dir in Path("/proc").iterdir():
        if not process_dir.name.isdigit():
            continue
        try:
            descriptors = (process_dir / "fd").iterdir()
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor)
                except OSError:
                    continue
                if target.startswith("socket:[") and target[8:-1] in inodes:
                    owners.add(int(process_dir.name))
                    break
        except OSError:
            continue
    return owners


def matching_pids(marker: bytes) -> set[int]:
    pids: set[int] = set()
    try:
        process_dirs = list(Path("/proc").iterdir())
    except OSError:
        return pids
    for process_dir in process_dirs:
        if process_dir.name.isdigit() and process_matches(int(process_dir.name), marker):
            pids.add(int(process_dir.name))
    return pids


def remove_socket_path(path: Path) -> None:
    """Remove a stale Unix socket without deleting an unexpected user file."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(mode):
        raise RuntimeError(f"Refusing to replace non-socket path: {path}")
    path.unlink()


def copy_tree(source: Path, target: Path) -> None:
    """Copy regular files/symlinks; skip device nodes for host binds."""
    target.mkdir(parents=True, exist_ok=True)
    for entry in source.iterdir():
        dest = target / entry.name
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            dest.symlink_to(os.readlink(entry))
        elif stat.S_ISDIR(mode):
            copy_tree(entry, dest)
        elif stat.S_ISREG(mode):
            shutil.copy2(entry, dest)
        elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            continue
        else:
            raise RuntimeError(f"Unsupported special file: {entry}")
    shutil.copystat(source, target)
