from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .config import model_secret, RepairError
from .contracts import PLACEHOLDERS, validate_placeholder_names
from .elf import elf_evidence
from .storage import is_binary, save_json, sha
from .tracing import execution_images

ASAN = re.compile(r"(?:ERROR: AddressSanitizer:|AddressSanitizer:DEADLYSIGNAL|ERROR: LeakSanitizer:|runtime error:)")
FLAGS = "-fsanitize=address -g -fno-omit-frame-pointer"


def content_excerpt(path: str, limit: int = 12000) -> str:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if len(text) <= limit:
        return text
    errors = [line for line in text.splitlines() if re.search(
        r"error|fatal|Traceback|Exception|undefined reference", line, re.I)]
    selected = "\n".join(errors)[:limit // 3] if errors else text[:limit // 3]
    return selected + "\n<log truncated for prompt; original retained>\n" + text[-2 * limit // 3:]


def expand(command: list[str], project: Path, poc: Path, tests: Path | None = None,
           suite: Path | None = None, *, adapter: Path | None = None,
           error_status: str = "preparation_failed") -> list[str]:
    if (not isinstance(command, list) or not command or
            not all(isinstance(arg, str) for arg in command) or not command[0]):
        raise RepairError(error_status, "Expected a nonempty command argv array")
    mapping = {"{project}": str(project), "{poc}": str(poc), "{poc_dir}": str(poc.parent),
               "{tests}": str(tests) if tests is not None else None,
               "{suite}": str(suite) if suite is not None else None,
               "{adapter}": str(adapter) if adapter is not None else None}
    validate_placeholder_names(command, error_status)
    placeholders = re.compile(r"\{(?:" + "|".join(PLACEHOLDERS) + r")\}")
    for arg in command:
        if re.search(r"\{poc\}[/\\]", arg):
            raise RepairError(error_status,
                              f"Command treats {{poc}} as a directory: {arg}. "
                              "{poc} is the full path to the original PoC file; "
                              "use {poc} directly or {poc_dir}/filename for adjacent payloads")
        if tests is not None and tests.is_file() and re.search(r"\{tests\}[/\\]", arg):
            raise RepairError(error_status, "{tests} refers to an external test file, not a directory")
        for match in placeholders.finditer(arg):
            if mapping[match[0]] is None:
                raise RepairError(error_status, f"Command placeholder {match[0]} is unavailable in this context")
    # Resolve only tokens from the original argv. Paths can themselves contain
    # braces; they must never be interpreted as another controller placeholder.
    return [placeholders.sub(lambda match: mapping[match[0]], arg) for arg in command]


def child_env(secret_name: str, extra: dict | None = None) -> dict:
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env.pop(secret_name, None)
    env.update({"ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=0:symbolize=1",
                "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    if extra:
        env.update(extra)
    return env


def group_rss_kb(pgid: int) -> int:
    total = 0
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            text = (path / "stat").read_text()
            fields = text[text.rfind(")") + 2:].split()
            if int(fields[2]) == pgid:
                for line in (path / "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
    return total


class Runner:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    def run(self, command: list[str], cwd: Path, log: Path, timeout: int,
            extra_env: dict | None = None, trace: bool = False) -> dict:
        if os.name != "posix" or not Path("/proc").exists():
            raise RepairError("preparation_failed", "Execution requires Ubuntu/Linux; Windows only supports offline tests")
        log.parent.mkdir(parents=True, exist_ok=True)
        actual = list(command)
        trace_path = log.with_suffix(".trace")
        if trace:
            if not shutil.which("strace"):
                raise RepairError("preparation_failed", "Install strace to verify PoC artifact binding")
            actual = ["strace", "-f", "-s", "4096", "-yy", "-e",
                      "trace=execve,execveat,open,openat,openat2,mmap,mmap2,close,dup,dup2,dup3,"
                      "chdir,fchdir,clone,clone3,fork,vfork", "-o", str(trace_path), "--", *actual]
        started = time.monotonic()
        reason, code = None, None
        secret = model_secret(self.cfg)
        limit = self.cfg["execution"]["max_log_mb"] * 1024 * 1024
        process = None
        with log.open("wb") as output:
            try:
                process = subprocess.Popen(actual, cwd=cwd,
                                           env=child_env(self.cfg["model"]["api_key_env"], extra_env),
                                           stdin=subprocess.DEVNULL, stdout=output,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                while process.poll() is None:
                    if time.monotonic() - started > timeout:
                        reason = "timeout"
                    elif log.stat().st_size > limit or (trace and trace_path.exists() and trace_path.stat().st_size > limit):
                        reason = "output_limit"
                    elif group_rss_kb(process.pid) > self.cfg["execution"]["memory_limit_mb"] * 1024:
                        reason = "memory_limit"
                    if reason:
                        break
                    time.sleep(0.05)
                if process.poll() is not None:
                    code = process.returncode
            except OSError as exc:
                reason = f"launch_failed: {exc}"
                output.write((reason + "\n").encode("utf-8", errors="replace"))
            finally:
                if process is not None:
                    # Also terminate children left behind by an exited parent.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    code = process.wait()
        if log.stat().st_size > limit:
            reason = reason or "output_limit"
        with log.open("r+b") as handle:
            handle.truncate(min(log.stat().st_size, limit))
        content = log.read_text(encoding="utf-8", errors="replace")
        if secret:
            content = content.replace(secret, "<redacted>")
            log.write_text(content, encoding="utf-8")
        if trace and trace_path.exists() and trace_path.stat().st_size > limit:
            with trace_path.open("r+b") as handle:
                handle.truncate(limit)
            reason = reason or "output_limit"
        result = {"command": command, "cwd": str(cwd), "returncode": code,
                  "reason": reason, "seconds": round(time.monotonic() - started, 3),
                  "log": str(log), "sanitizer_error": bool(ASAN.search(content)),
                  "passed": code == 0 and reason is None and not ASAN.search(content),
                  "trace": str(trace_path) if trace else None}
        save_json(log.with_suffix(".json"), result)
        return result


def build_plan(cfg: dict, project: Path, poc: Path) -> tuple[str, list[list[str]]]:
    if cfg["build"]["command"]:
        return "custom", [expand(cfg["build"]["command"], project, poc)]
    jobs = str(cfg["build"]["jobs"])
    if (project / "CMakeLists.txt").is_file():
        return "cmake", [
            ["cmake", "-S", ".", "-B", ".repair-build", "-DCMAKE_BUILD_TYPE=Debug",
             f"-DCMAKE_C_FLAGS={FLAGS}", f"-DCMAKE_CXX_FLAGS={FLAGS}",
             "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address", "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address",
             "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DBUILD_TESTING=ON"],
            ["cmake", "--build", ".repair-build", "--parallel", jobs]]
    if (project / "Makefile").is_file() or (project / "makefile").is_file():
        return "make", [["make", "-B", "-j", jobs]]
    raise RepairError("build_information_required", "No supported root build entry; set build.command (argv array)")


def instrumented(path: Path) -> bool:
    """Compatibility API: returns structural ASan association, not coverage proof."""
    return elf_evidence(path)["asan"]


def artifact_inventory(project: Path) -> dict:
    return {path.relative_to(project).as_posix(): {"sha256": sha(path), **elf_evidence(path)}
            for path in sorted(project.rglob("*"))
            if path.is_file() and not path.is_symlink() and is_binary(path)}


def binding_evidence(result: dict, project: Path, artifacts: dict, *, extra_targets: dict | None = None) -> dict:
    """Require successful exec/load, freshness, and the ASan reporter's image."""
    project = project.resolve()
    try:
        text = Path(result["trace"]).read_text(encoding="utf-8", errors="replace")
        traced = execution_images(text, Path(result.get("cwd", project)))
    except (OSError, KeyError, TypeError, ValueError):
        traced = {"images": [], "processes": {}, "accessed": set(), "relations": [], "errors": ["trace_unavailable"]}
    accessed, foreign, mismatched, targets, bindings = set(), set(), set(), set(), []
    runtime_targets = set()
    foreign_bindings, unavailable = [], set()
    cache = {}

    def inspect(path):
        if path is None:
            return None, None
        candidate = Path(path).resolve()
        if candidate not in cache:
            info = elf_evidence(candidate)
            relative = candidate.relative_to(project).as_posix() if candidate.is_relative_to(project) else None
            extra = (extra_targets or {}).get(str(candidate))
            expected = artifacts.get(relative) if relative is not None else None
            if extra is not None:
                relative, expected = extra["label"], extra
            if expected is not None:
                try:
                    if sha(candidate) != expected["sha256"]:
                        mismatched.add(relative)
                        relative = None
                except OSError:
                    mismatched.add(relative)
                    relative = None
            else:
                relative = None
            cache[candidate] = (relative, info)
        return cache[candidate]

    for path in traced["accessed"]:
        relative, _ = inspect(path)
        if relative:
            accessed.add(relative)
    image_targets = {}
    for image in traced["images"]:
        matched = set()
        for kind, path in [("exec", image["executable"]), *[("load", e["path"]) for e in image["loads"]]]:
            if path and not Path(path).is_file():
                unavailable.add(path)
            relative, info = inspect(path)
            if not info or not info["runtime_target"]:
                continue
            if kind == "load" and info["elf_type"] != "ET_DYN":
                continue
            if relative:
                runtime_targets.add(relative)
            if not info["asan"] or info["asan_runtime"]:
                continue
            if relative:
                matched.add(relative)
                bindings.append({"pid": image["pid"], "executable": image["executable"],
                                 "target": relative, "kind": kind,
                                 "exec_order": image["exec_order"], "inherited_from": image["inherited_from"]})
            else:
                foreign.add(str(Path(path).resolve()))
                foreign_bindings.append({"pid": image["pid"], "executable": image["executable"],
                                         "target": path, "kind": kind, "asan_evidence": info["asan_evidence"]})
        image_targets[id(image)] = matched
        targets.update(matched)
    reporters = result.get("sanitizer_pids", [])
    unbound = []
    for pid in reporters:
        state = traced["processes"].get(pid, {})
        if not image_targets.get(id(state.get("last_image"))):
            unbound.append(pid)
    failures = []
    if traced["errors"] or result.get("reason"):
        failures.append("incomplete_trace")
    if unavailable:
        failures.append("runtime_file_unavailable")
    if not targets:
        failures.append("no_fresh_executed_or_loaded_asan_target")
    if foreign:
        failures.append("foreign_asan_target")
    if mismatched:
        failures.append("artifact_hash_mismatch")
    if unbound or (result.get("sanitizer_error") and not reporters):
        failures.append("sanitizer_process_unbound")
    return {"passed": not failures, "failure_categories": failures,
            "fresh_runtime_targets": sorted(runtime_targets),
            "fresh_asan_targets": sorted(targets), "accessed_artifacts": sorted(accessed),
            "foreign_asan_targets": sorted(foreign), "hash_mismatches": sorted(mismatched),
            "sanitizer_pids": reporters, "unbound_sanitizer_pids": unbound,
            "process_bindings": bindings, "process_relations": traced["relations"],
            "execution_images": traced["images"], "foreign_bindings": foreign_bindings,
            "unavailable_runtime_files": sorted(unavailable), "trace_errors": traced["errors"]}


def generated_binding(result: dict, project: Path, artifacts: dict, work: Path,
                      source_catalog: set[str]) -> dict:
    """Bind fresh project targets or drivers with traced system-compiler provenance.

    This verifies compilation inputs and execution, not semantic assertion correctness.
    An unrelated launcher read cannot establish compiler provenance.
    """
    extra, provenance = {}, []
    try:
        text = Path(result["trace"]).read_text(encoding="utf-8", errors="replace")
        traced = execution_images(text, project)
        successful = {int(p) for p in re.findall(r"(?m)^\s*(?:\[pid\s+)?(\d+)\]?\s+\+\+\+ exited with 0 \+\+\+", text)}
        compilers = {str(Path(p).resolve()) for name in ("cc", "gcc", "clang", "c++", "g++", "clang++")
                     if (p := shutil.which(name))}
        inputs = {str((project / p).resolve()): sha(project / p) for p in source_catalog
                  if (project / p).is_file()}
        inputs.update({str((project / p).resolve()): a["sha256"] for p, a in artifacts.items()})
        for root in traced["images"]:
            if root["executable"] not in compilers or root["pid"] not in successful:
                continue
            children = {root["pid"]}
            for relation in sorted(traced["relations"], key=lambda r: r["order"]):
                if relation["order"] >= root["exec_order"] and relation["parent"] in children:
                    children.add(relation["child"])
            opens = [o for im in traced["images"] if im["pid"] in children and im["exec_order"] >= root["exec_order"]
                     for o in im.get("opens", []) if o["order"] >= root["exec_order"]]
            reads = sorted({o["path"] for o in opens if o["path"] in inputs and
                            "O_WRONLY" not in o["flags"] and "O_RDWR" not in o["flags"]})
            if not reads or any(sha(Path(p)) != inputs[p] for p in reads):
                continue
            for opened in opens:
                path = Path(opened["path"])
                if (not path.is_relative_to(work.resolve()) or not path.is_file() or path.is_symlink() or
                        not any(f in opened["flags"] for f in ("O_WRONLY", "O_RDWR")) or
                        not any(f in opened["flags"] for f in ("O_CREAT", "O_TRUNC"))):
                    continue
                later_writes = [o for im in traced["images"] for o in im.get("opens", [])
                                if o["path"] == str(path) and o["order"] > opened["order"] and
                                any(f in o["flags"] for f in ("O_WRONLY", "O_RDWR"))]
                if later_writes:
                    continue
                info = elf_evidence(path)
                if not info["asan"] or not info["runtime_target"] or info["asan_runtime"]:
                    continue
                # The compiled file must be executed/mapped after its compiler wrote it.
                used = any((im["executable"] == str(path) and im["exec_order"] > opened["order"]) or
                           any(e["path"] == str(path) and e["order"] > opened["order"] for e in im["loads"])
                           for im in traced["images"])
                if used:
                    extra[str(path)] = {"label": "driver:" + path.relative_to(work.resolve()).as_posix(),
                                        "sha256": sha(path), **info}
                    provenance.append({"driver": str(path), "compiler": root["executable"],
                                       "compiler_pid": root["pid"], "inputs": reads,
                                       "input_hashes": {p: inputs[p] for p in reads}})
    except (OSError, KeyError, TypeError, ValueError):
        # Missing/incomplete provenance fails closed via normal binding checks.
        extra = {}
    binding = binding_evidence(result, project, artifacts, extra_targets=extra)
    binding["driver_provenance"] = provenance
    return binding


def artifact_summary(artifacts: dict, limit: int = 80) -> dict:
    """Bounded model-facing inventory; full metadata/hashes remain in audit files."""
    targets = [{"path": path, "elf_type": info["elf_type"], "asan_associated": info["asan"]}
               for path, info in artifacts.items() if info.get("runtime_target")]
    return {"runtime_targets": targets[:limit], "runtime_target_count": len(targets),
            "omitted_runtime_targets": max(0, len(targets) - limit), "artifact_count": len(artifacts)}


def binding_summary(binding: dict) -> dict:
    rejected = binding["foreign_asan_targets"] + binding["hash_mismatches"] + binding["unavailable_runtime_files"]
    return {"failure_categories": binding["failure_categories"],
            "matched_targets": binding["fresh_asan_targets"][:16],
            "rejected_files": rejected[:16], "rejected_file_count": len(rejected),
            "unbound_sanitizer_pids": binding["unbound_sanitizer_pids"][:16]}


def discover_project_tests(project: Path, kind: str, runner: Runner, cfg: dict, poc: Path,
                           logs: Path) -> list[dict]:
    explicit = cfg["tests"]["project_command"]
    if explicit:
        return [{"id": "project", "command": expand(explicit, project, poc), "count": None}]
    if kind == "cmake":
        result = runner.run(["ctest", "--test-dir", ".repair-build", "--show-only=json-v1"], project,
                            logs / "ctest-discovery.log", 30)
        def discovery_error(reason):
            return RepairError("test_information_required", json.dumps({
                "reason": reason, "result": result, "log_excerpt": content_excerpt(result["log"])}))
        if not result["passed"]:
            raise discovery_error("CTest discovery failed; set tests.project_command")
        try:
            data = json.loads(Path(result["log"]).read_text())
            if not isinstance(data, dict):
                raise ValueError("CTest result must be an object")
            entries = data.get("tests", [])
            if not isinstance(entries, list) or not all(
                    isinstance(e, dict) and isinstance(e.get("name"), str) and e["name"] for e in entries):
                raise ValueError("CTest tests must be an array of named objects")
            for entry in entries:
                properties = entry.get("properties", [])
                if not isinstance(properties, list) or not all(
                        isinstance(p, dict) and isinstance(p.get("name"), str) and "value" in p
                        for p in properties):
                    raise ValueError("Invalid CTest properties")
        except (ValueError, TypeError):
            raise discovery_error("Invalid CTest discovery output")
        if entries:
            # Run individual CTest commands; empty, disabled and skipped tests are rejected.
            tests = []
            for entry in entries:
                properties = {p["name"]: p["value"] for p in entry.get("properties", [])}
                if properties.get("DISABLED") or properties.get("SKIP_RETURN_CODE") is not None:
                    raise RepairError("test_information_required", "CTest disabled/skip semantics require tests.project_command")
                if not entry.get("command"):
                    raise RepairError("test_information_required", "CTest test has no command")
                tests.append({"id": "project:" + entry["name"],
                              "command": ["ctest", "--test-dir", ".repair-build", "--no-tests=error",
                                          "--output-on-failure", "-R", "^" + re.escape(entry["name"]) + "$"],
                              "count": 1, "ctest": True})
            return tests
    elif kind == "make":
        makefile = project / ("Makefile" if (project / "Makefile").exists() else "makefile")
        text = makefile.read_text(errors="replace")
        matches = [name for name in ("check", "test") if re.search(r"(?m)^" + name + r"\s*:", text)]
        if matches:
            return [{"id": "project:" + matches[0], "command": ["make", matches[0]], "count": None}]
    found = any(path.is_dir() and path.name.lower() in {"test", "tests", "testing"}
                for path in project.rglob("*") if not path.is_symlink())
    if found:
        raise RepairError("test_information_required", "Tests found but no recognized launcher; set tests.project_command")
    return []
