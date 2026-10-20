"""Parse strace syscall fields and retain process/image relationships."""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path


def split_args(text: str) -> list[str]:
    parts, start, depth, quoted, escaped, annotation = [], 0, 0, False, False, False
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif annotation:
            if char == ">":
                annotation = False
                depth -= 1
        elif char == '"':
            quoted = True
        elif char == "<":
            annotation = True
            depth += 1
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


def unquote(value: str) -> str | None:
    if not re.fullmatch(r'"(?:[^"\\]|\\.)*"', value):
        return None
    content = value[1:-1]
    output = bytearray()
    index = 0
    escapes = {"n": 10, "r": 13, "t": 9, "b": 8, "f": 12, "v": 11, '"': 34, "\\": 92}
    while index < len(content):
        char = content[index]
        if char != "\\":
            output.extend(char.encode("utf-8"))
            index += 1
            continue
        match = re.match(r'\\(?:([0-7]{1,3})|x([0-9a-fA-F]{2})|(.))', content[index:])
        if not match:
            return None
        octal, hexadecimal, other = match.groups()
        if octal:
            number = int(octal, 8)
            if number > 255:
                return None
            output.append(number)
        elif hexadecimal:
            output.append(int(hexadecimal, 16))
        elif other in escapes:
            output.append(escapes[other])
        else:
            return None
        index += len(match[0])
    return os.fsdecode(bytes(output)) if 0 not in output else None


def fd_path(value: str) -> Path | None:
    match = re.fullmatch(r'\d+<(.+)>', value)
    if not match or match[1].endswith(" (deleted)"):
        return None
    name = unquote('"' + match[1] + '"')
    if name is None:
        return None
    path = Path(name)
    return path.resolve() if path.is_absolute() else None


def syscalls(text: str) -> tuple[list, list[str]]:
    calls, pending, errors = [], {}, []
    for index, line in enumerate(text.splitlines()):
        prefix = re.match(r'^\s*(?:\[pid\s+(\d+)\]\s*|(\d+)\s+)?(.*)$', line)
        pid, body = int(prefix[1] or prefix[2] or 0), prefix[3]
        if "<unfinished ...>" in body:
            pending[pid] = (index, body.split("<unfinished ...>")[0])
            continue
        resumed = re.match(r'<\.\.\. (\w+) resumed>(.*)', body)
        if resumed:
            beginning = pending.pop(pid, None)
            if beginning is None or not beginning[1].startswith(resumed[1] + "("):
                errors.append(f"unmatched_resumed:{pid}")
                continue
            index, first = beginning
            body = first + resumed[2]
        match = re.match(r'^(\w+)\((.*)\)\s+=\s+(.+)$', body)
        if match:
            calls.append((index, pid, match[1], split_args(match[2]), match[3]))
        elif re.match(r'^\w+\(', body):
            errors.append(f"unparsed_syscall:{pid}")
    # An unfinished call has no proven success and cannot contribute evidence.
    errors.extend(f"unfinished_syscall:{pid}" for pid in pending)
    return sorted(calls), errors


def execution_images(text: str, cwd: Path) -> dict:
    """An image begins at successful exec and ends at the next exec in that PID.

    Forks inherit images; threads share them. Only successful executable file
    mappings count as DSO load evidence. Opening a file alone never does.
    """
    calls, errors = syscalls(text)
    processes, images, accessed, relations = {}, [], set(), []

    def process(pid):
        if pid not in processes:
            processes[pid] = {"fs": {"cwd": cwd.resolve()}, "fds": {}, "cloexec": set(), "image": None, "last_image": None}
        return processes[pid]

    def path_arg(value, state, directory=None):
        name = unquote(value)
        if name is None:
            return None
        path = Path(name)
        if path.is_absolute():
            return path.resolve()
        base = state["fs"]["cwd"]
        if directory is not None and directory != "AT_FDCWD":
            base = fd_path(directory) or state["fds"].get(directory.split("<", 1)[0])
        return (base / path).resolve() if base is not None else None

    for order, pid, call, args, returned in calls:
        minimum = {"execve": 3, "execveat": 5, "open": 2, "openat": 3, "openat2": 3,
                   "mmap": 6, "mmap2": 6, "close": 1, "dup": 1, "dup2": 2, "dup3": 3,
                   "chdir": 1, "fchdir": 1}.get(call, 0)
        if len(args) < minimum:
            errors.append(f"invalid_syscall_arguments:{pid}:{call}")
            continue
        state = process(pid)
        number = re.match(r'^(0x[\da-fA-F]+|\d+)\b', returned)
        if not number:
            continue
        value = int(number[1], 0) if number[1].startswith("0x") else int(number[1])
        if call in {"clone", "clone3", "fork", "vfork"} and value > 0:
            child = {"fs": state["fs"] if "CLONE_FS" in ",".join(args) else dict(state["fs"]),
                     "fds": state["fds"] if "CLONE_FILES" in ",".join(args) else dict(state["fds"]),
                     "cloexec": state["cloexec"] if "CLONE_FILES" in ",".join(args) else set(state["cloexec"]),
                     "image": state["image"] if "CLONE_VM" in ",".join(args) else copy.deepcopy(state["image"]),
                     "last_image": None}
            if child["image"] is not None and child["image"] is not state["image"]:
                child["image"]["pid"] = value
                child["image"]["inherited_from"] = pid
                images.append(child["image"])
            child["last_image"] = child["image"]
            processes[value] = child
            relations.append({"parent": pid, "child": value, "syscall": call, "order": order})
        elif call in {"execve", "execveat"} and value == 0:
            target = path_arg(args[0], state) if call == "execve" else path_arg(args[1], state, args[0])
            if call == "execveat" and unquote(args[1]) == "" and "AT_EMPTY_PATH" in args[-1]:
                target = fd_path(args[0]) or state["fds"].get(args[0].split("<", 1)[0])
            if target is None:
                errors.append(f"unresolved_exec:{pid}")
            state["fds"] = {fd: path for fd, path in state["fds"].items() if fd not in state["cloexec"]}
            state["cloexec"] = set()
            state["image"] = {"pid": pid, "executable": str(target) if target else None,
                              "exec_order": order, "loads": [], "opens": [], "inherited_from": None}
            state["last_image"] = state["image"]
            images.append(state["image"])
            if target:
                accessed.add(target)
        elif call in {"open", "openat", "openat2"}:
            target = fd_path(returned)
            if target is None:
                target = path_arg(args[0], state) if call == "open" else path_arg(args[1], state, args[0])
            state["fds"][str(value)] = target
            state["cloexec"].discard(str(value))
            if "O_CLOEXEC" in ",".join(args):
                state["cloexec"].add(str(value))
            if target:
                accessed.add(target)
                if state["image"] is not None:
                    state["image"].setdefault("opens", []).append({
                        "path": str(target), "flags": args[1] if call == "open" else args[2], "order": order})
        elif call == "close" and value == 0:
            state["fds"].pop(args[0].split("<", 1)[0], None)
            state["cloexec"].discard(args[0].split("<", 1)[0])
        elif call in {"dup", "dup2", "dup3"}:
            state["fds"][str(value)] = fd_path(args[0]) or state["fds"].get(args[0].split("<", 1)[0])
            if call != "dup2" or str(value) != args[0].split("<", 1)[0]:
                state["cloexec"].discard(str(value))
                if call == "dup3" and "O_CLOEXEC" in args[-1]:
                    state["cloexec"].add(str(value))
        elif call == "chdir" and value == 0:
            state["fs"]["cwd"] = path_arg(args[0], state)
        elif call == "fchdir" and value == 0:
            state["fs"]["cwd"] = fd_path(args[0]) or state["fds"].get(args[0].split("<", 1)[0])
        elif call in {"mmap", "mmap2"} and len(args) == 6 and "PROT_EXEC" in args[2] and "MAP_ANONYMOUS" not in args[3]:
            target = fd_path(args[4]) or state["fds"].get(args[4].split("<", 1)[0])
            if target is None:
                errors.append(f"unresolved_executable_mapping:{pid}")
            if target and state["image"] is not None:
                state["image"]["loads"].append({"pid": pid, "path": str(target), "syscall": call, "order": order})
                accessed.add(target)
        elif call == "exit_group":
            state["image"] = None
    return {"images": images, "processes": processes, "accessed": accessed,
            "relations": relations, "errors": sorted(set(errors))}
