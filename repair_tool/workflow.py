from __future__ import annotations

import copy
import html
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from . import __version__
from .config import model_secret, RepairError, public_config
from .contracts import (CONTEXT_BATCHES, CONTEXT_TEXT, HELPER_FORBIDDEN, TEST_KINDS, TEST_ID,
                        HELPER_MAX_FILES, HELPER_MAX_BYTES, ANALYSIS_CONTRACT, analysis_contract_decision,
                        contract_text, patch_contract, runtime_env, test_contract)
from .diagnostics import failure_feedback, helper_hints
from .evidence import fingerprint, initial_context, parse_asan, read_requested
from .execution import (FLAGS, Runner, artifact_inventory, binding_evidence, build_plan,
                        discover_project_tests, expand, artifact_summary, binding_summary,
                        generated_binding, content_excerpt as tail)
from .model import ModelClient, redact, redact_data
from .patching import apply_patch
from .storage import (SOURCE_SUFFIXES, fresh_project, inventory, protected_source, safe_file,
                      save_json, sha, snapshot, source_files, is_binary, ARTIFACT_SUFFIXES)

ADAPTER_SPEC = """Return {files:[{path:'launch.py',content:'...'}], command:[...]}.
Files live outside the project in an adapter directory. Use {adapter}/filename, {project},
{poc}, and {poc_dir} ONLY in command arguments. {poc} is the full path to the original
PoC file in the copied snapshot, NOT a directory; NEVER append /filename to {poc}.
{poc_dir} is the copied PoC directory; use {poc_dir}/payload for adjacent payloads.
files[].path must be a relative filename such as
launch.py or helpers/launch.py, NEVER {adapter}/launch.py or adapter/launch.py.
Original PoC args are supplied below, include them unchanged. You may wrap/compile the
original PoC and point it to freshly built project binaries/libraries, but NEVER change PoC
input, filter output, swallow status, or replace its triggering logic. Prefer exec/subprocess
with inherited stdout/stderr and propagate return status. Build output is .repair-build for
CMake. Files cannot be project sources. Do not install dependencies or use sudo/network.
The controller requires successful execution of a fresh ELF executable or executable
mapping of a fresh ELF shared library. Merely opening an artifact is insufficient.
On a crash, the ASan-reporting process must use the fresh target. ASan symbols/dependencies
are association evidence, not proof that every source file was instrumented.
If compiling a PoC driver, create its binary under {project}/.repair-poc/ (mkdir allowed),
so the controller can verify its provenance; do not overwrite existing project files.
Do not hardcode snapshot/run absolute paths; placeholders in argv are resolved by controller."""

TEST_ENTRY_SPEC = """Entries contain {id:'unique-id',kind:'allowed kind for this stage',
baseline:'pass|asan',basis:'documented/code/test evidence for expected values',
files:[{path:'test.py',content:'...'}],command:['python3','{suite}/test.py',...],
expected_cases:1}.
Generate regression tests for impacted APIs/whole-project behavior FIRST, then vulnerability
boundaries.
Test IDs must match [A-Za-z0-9_-]{1,80}, unique across the task; expected_cases is a positive integer.
Regression baseline must be pass; vulnerability baseline must be asan; nonempty basis required.
Each test is a self-contained driver; compile drivers outside
the project, with ASan and debug flags, linking current project artifacts or original sources.
Use {project}, {poc}, {poc_dir}, {suite} in argv, not hardcoded paths. {poc} is the full
path to the original PoC file in the copied snapshot, NOT a directory; NEVER append
/filename to {poc}. {poc_dir} is the copied PoC directory; use {poc_dir}/payload for
adjacent payloads. No modifying project or existing tests.
The command must actually assert outputs, exit nonzero on failure, and on PASS write a JSON
object to os.environ['REPAIR_TEST_RESULT']: {cases:[{id:'case-name',passed:true}]}.
expected_cases must equal executed case count. No skipped tests or unconditional PASS records.
baseline=pass means the original version must pass. baseline=asan means raw ASan error must
occur on the original version with nonzero exit, matching the PoC ASan type AND containing
an existing original project source frame (generated driver frames do not count).
The SAME fixed script must support both original and patched versions, without stage-specific
flags or hardcoded expectations that a crash must always occur. On target nonzero exit, print
raw target stdout/stderr and propagate failure (map negative signal returncodes to nonzero).
On target exit 0 with no ASan, assert the documented functional outputs, write the executed
passing cases to REPAIR_TEST_RESULT and return 0. Do not fail with 'EXPECTED ASan ... none
observed' when the target succeeds. The controller, not the script, requires matching ASan
on the original baseline. Zero exit alone is not enough: retain functional assertions.
The patched version must pass normally. Every run requires a complete trace and execution/load
binding to the current ASan project artifact, or a newly compiled ASan driver with traced
compiler input provenance from current project sources/artifacts. Opening a project file or
writing a PASS record alone cannot satisfy this gate. Compile drivers in REPAIR_WORK, keep
them until execution finishes, with cc/gcc/clang/c++/g++/clang++ from the system PATH.
For crashing tests write results only when the target succeeds. Preserve target diagnostics
and returncode. Test files remain fixed; later rounds may only append new test IDs.
Test correctness is not established just because the generated baseline behaves as expected.
No sudo, network, or sanitizer suppression. ASAN_OPTIONS supplied by controller disables leak
detection because ptrace is used for PoC AND generated tests."""

ADAPTER_SPEC += contract_text("adapter") + """
Script example (adjust includes/libraries using actual build catalog):
import json, os, subprocess, sys
project = os.environ['REPAIR_PROJECT']
poc = os.environ['REPAIR_POC']
args = json.loads(os.environ['REPAIR_POC_ARGS'])
work = os.environ['REPAIR_WORK']
os.makedirs(work, exist_ok=True)
out = os.path.join(work, 'poc')
subprocess.run(['cc', '-fsanitize=address', '-g', '-fno-omit-frame-pointer', poc, '-o', out], check=True)
sys.exit(subprocess.run([out, *args]).returncode)
Include original args in command OR read REPAIR_POC_ARGS in the script, never duplicate them.
You may request additional project or PoC text with read_files before returning the adapter.
"""
TEST_ENTRY_SPEC += contract_text("test")
TEST_SPEC = ("Return {tests:[...]}. Include all three kinds: regression, vulnerability, independent. "
             "Independent coverage must include separate baseline=pass and baseline=asan entries. " +
             TEST_ENTRY_SPEC + "\n" + test_contract())
APPEND_TEST_SPEC = (
    "additional_tests is optional; omit it or return [] if no new coverage is needed. "
    "Return additional_tests:[...] with regression or vulnerability entries only, never independent. "
    "Use new IDs, avoiding public_fixed_tests and other entries in this batch. " +
    TEST_ENTRY_SPEC + "\n" + test_contract(allow_independent=False)
)


def fixed_inventory(paths: list[Path]) -> dict:
    return {str(path): inventory(path) for path in paths if path.exists()}


def write_model_files(root: Path, files: list) -> None:
    if not isinstance(files, list) or not files or len(files) > HELPER_MAX_FILES:
        raise RepairError("model_output_invalid", f"Expected 1..{HELPER_MAX_FILES} helper files")
    seen, validated = set(), []
    for file in files:
        if not isinstance(file, dict) or not isinstance(file.get("path"), str):
            raise RepairError("model_output_invalid", "Each helper file must have a string path and content")
        if "{" in file["path"] or "}" in file["path"]:
            raise RepairError("model_output_invalid",
                              "files[].path must be relative to its helper directory, without placeholders; "
                              "use launch.py, not {adapter}/launch.py. Placeholders belong only in command arguments")
        try:
            path = safe_file(root, file["path"])
        except RepairError as exc:
            raise RepairError("model_output_invalid", str(exc)) from exc
        content = file.get("content")
        if path in seen or not isinstance(content, str) or len(content.encode()) > HELPER_MAX_BYTES:
            raise RepairError("model_output_invalid", "Duplicate/oversized helper file")
        seen.add(path)
        if HELPER_FORBIDDEN.search(content):
            raise RepairError("model_output_invalid", "Forbidden helper behavior")
        if path.suffix == ".py":
            try:
                compile(content, file["path"], "exec")
            except SyntaxError as exc:
                raise RepairError("model_output_invalid", f"Python syntax in {file['path']}:{exc.lineno}:{exc.offset}: {exc.msg}") from exc
        elif path.suffix == ".sh" and os.name == "posix":
            checked = subprocess.run(["bash", "-n"], input=content, text=True, capture_output=True, timeout=10,
                                     env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"})
            if checked.returncode:
                raise RepairError("model_output_invalid", f"Shell syntax in {file['path']}: {checked.stderr[:4000]}")
        if any(path in other.parents or other in path.parents for other, _ in validated):
            raise RepairError("model_output_invalid", "Helper paths conflict as file and directory")
        validated.append((path, content))
    for path, content in validated:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)


def argv(value) -> list[str]:
    if not isinstance(value, list) or not value or not value[0] or not all(isinstance(a, str) for a in value):
        raise RepairError("model_output_invalid", "Expected nonempty argv array")
    if Path(value[0]).name in {"sudo", "curl", "wget"}:
        raise RepairError("model_output_invalid", "Forbidden command")
    return value


def check_helper_references(command: list[str], placeholder: str, root: Path) -> None:
    for index, arg in enumerate(command):
        match = re.search(re.escape(placeholder) + r"[/\\]", arg)
        if not match:
            continue
        prefix = arg[:match.start()]
        # Check path operands and option values. Composite shell/Python snippets
        # need their own parser and must not be treated as a single filename.
        if not re.fullmatch(r"(?:--[\w-]+=|-[A-Za-z]+)?", prefix):
            continue
        if prefix in {"-o", "--output="} or (index and command[index - 1] in {"-o", "--output"}):
            continue
        relative = arg[match.end():].replace("\\", "/")
        try:
            target = safe_file(root, relative)
        except RepairError as exc:
            raise RepairError("model_output_invalid", str(exc)) from exc
        if not target.exists():
            raise RepairError("model_output_invalid",
                              f"Command references missing helper: {arg}. "
                              f"Match command {placeholder}/launch.py with files[].path launch.py")


class Workflow:
    def __init__(self, cfg: dict, model_factory=ModelClient):
        self.cfg = cfg
        self.root = Path(cfg["output"]["directory"]) / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        self.root.mkdir(parents=True)
        self.runner = Runner(cfg)
        self.model_factory = model_factory
        self.model = None
        self.tests = []
        self.adapter = None
        self.evidence = None
        self.analysis = None
        self.report = {"run_id": self.root.name, "version": __version__, "status": "running",
                       "rounds": [], "warnings": [], "source_upload": [], "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        self.baseline = self.root / "baseline" / "project"
        self.poc = self.root / "inputs" / "poc" / Path(cfg["poc"]["path"]).name
        self.external = None
        self.original_inventory = inventory(Path(cfg["project"]["path"]))
        self.source_catalog = {p.relative_to(Path(cfg["project"]["path"])).as_posix()
                               for p in source_files(Path(cfg["project"]["path"]))}
        self.started = time.monotonic()
        self.fixed_start = None

    def event(self, stage: str):
        self.report["stage"] = stage
        save_json(self.root / "report.json", self.report)
        print(f"[{self.root.name}] {stage}", flush=True)

    def immutable_paths(self) -> list[Path]:
        return [self.root / "baseline", self.root / "inputs", self.root / "adapter",
                self.root / "generated-tests"]

    def guard(self, before: dict):
        if fixed_inventory([Path(p) for p in before]) != before:
            raise RepairError("integrity_failed", "Protected baseline/input/adapter/test files changed during execution")

    def execute(self, command: list[str], project: Path, log: Path, timeout: int,
                extra_env: dict | None = None, trace=False) -> dict:
        before = fixed_inventory(self.immutable_paths())
        tracked = {}
        if self.baseline.exists():
            for original in self.baseline.rglob("*"):
                if not original.is_file() or original.is_symlink() or is_binary(original) or original.suffix in ARTIFACT_SUFFIXES:
                    continue
                if original.name in {"CMakeCache.txt", "compile_commands.json"} or "CMakeFiles" in original.parts:
                    continue
                relative = original.relative_to(self.baseline)
                target = project / relative
                if target.is_file():
                    tracked[str(target)] = sha(target)
        try:
            result = self.runner.run(command, project, log, timeout, extra_env, trace)
        finally:
            self.guard(before)
            for filename, digest in tracked.items():
                path = Path(filename)
                if not path.is_file() or path.is_symlink() or sha(path) != digest:
                    raise RepairError("integrity_failed", f"Execution modified a tracked input file: {filename}")
        return result

    def prepare(self):
        self.event("snapshot")
        snapshot(Path(self.cfg["project"]["path"]), self.baseline)
        # Save the PoC directory so adjacent payloads/imports remain usable.
        poc_source = Path(self.cfg["poc"]["path"])
        parent = poc_source.parent
        if parent == Path(parent.anchor) or parent == Path.home():
            raise RepairError("preparation_failed", "Put the PoC and its payloads in a dedicated directory, not HOME/root")
        project_source = Path(self.cfg["project"]["path"])
        output = Path(self.cfg["output"]["directory"])
        if parent == output or parent in output.parents:
            # Avoid recursive snapshot when case.yaml/results share the PoC directory.
            def ignore(directory, names):
                ignored = {".git", ".venv", "__pycache__"} & set(names)
                for name in names:
                    candidate = Path(directory) / name
                    if candidate == output or candidate == project_source:
                        ignored.add(name)
                return ignored
            from .storage import check_links
            check_links(parent)
            shutil.copytree(parent, self.poc.parent, symlinks=False, ignore=ignore)
        else:
            snapshot(parent, self.poc.parent)
        # A case YAML adjacent to the PoC is copied with its directory. Sanitize
        # that copy before it becomes immutable or enters model context.
        config_source = Path(self.cfg["config_path"])
        if self.cfg["model"].get("api_key") and config_source.is_relative_to(parent):
            copied_config = self.poc.parent / config_source.relative_to(parent)
            if copied_config.is_file() and copied_config != self.poc:
                import yaml
                copied_config.write_text(yaml.safe_dump(public_config(self.cfg)), encoding="utf-8")
        external = self.cfg["tests"]["external_path"]
        if external:
            source = Path(external)
            if source.is_dir():
                self.external = self.root / "inputs" / "external-tests"
                if source == output or source in output.parents:
                    raise RepairError("preparation_failed", "External test directory cannot contain output")
                snapshot(source, self.external)
            else:
                self.external = self.root / "inputs" / "external-tests" / source.name
                self.external.parent.mkdir(parents=True)
                shutil.copy2(source, self.external)
        save_json(self.root / "config.json", public_config(self.cfg))
        save_json(self.root / "manifest.json", {
            "version": __version__, "baseline": inventory(self.baseline),
            "original_project": self.original_inventory, "inputs": inventory(self.root / "inputs"),
            "config": public_config(self.cfg)})
        self.fixed_start = fixed_inventory([self.root / "baseline", self.root / "inputs"])
        self.model = self.model_factory(self.cfg, self.root)

    def build(self, project: Path, logs: Path) -> dict:
        kind, commands = build_plan(self.cfg, project, self.poc)
        source_hashes = {str(p): sha(p) for p in source_files(project)}
        env = {"CFLAGS": FLAGS, "CXXFLAGS": FLAGS, "LDFLAGS": "-fsanitize=address"}
        results = []
        for index, command in enumerate(commands):
            result = self.execute(command, project, logs / f"build-{index}.log",
                                  self.cfg["build"]["timeout_seconds"], env)
            results.append(result)
            if not result["passed"]:
                raise RepairError("build_failed", json.dumps({"result": result, "log_excerpt": tail(result["log"])}))
        for path, value in source_hashes.items():
            if not Path(path).is_file() or sha(Path(path)) != value:
                raise RepairError("integrity_failed", f"Build modified input source: {path}")
        artifacts = artifact_inventory(project)
        if not any(a["asan"] and a["runtime_target"] and not a["asan_runtime"] for a in artifacts.values()):
            save_json(logs / "build.json", {"kind": kind, "artifacts": artifacts, "commands": results,
                                           "runtime_targets": artifact_summary(artifacts)})
            raise RepairError("build_information_required", "No fresh ET_EXEC/ET_DYN target with ASan association; build may ignore flags. Set build.command")
        tests = discover_project_tests(project, kind, self.runner, self.cfg, self.poc, logs)
        record = {"kind": kind, "artifacts": artifacts, "commands": results, "project_tests": tests}
        record["runtime_targets"] = artifact_summary(artifacts)
        save_json(logs / "build.json", record)
        return record

    def external_command(self, project: Path) -> list[str] | None:
        if not self.external:
            return None
        if self.cfg["tests"]["external_command"]:
            return expand(self.cfg["tests"]["external_command"], project, self.poc, self.external)
        if self.external.is_file():
            if self.external.suffix == ".py":
                return ["python3", str(self.external)]
            if self.external.suffix == ".sh":
                return ["bash", str(self.external)]
            if os.access(self.external, os.X_OK):
                return [str(self.external)]
        elif any(self.external.glob("test_*.py")):
            return ["python3", "-m", "pytest", str(self.external), "-q", "-r", "s"]
        raise RepairError("test_information_required", "Set tests.external_command for external tests")

    def run_existing(self, project: Path, build: dict, logs: Path) -> list[dict]:
        commands = copy.deepcopy(build["project_tests"])
        external = self.external_command(project)
        if external:
            commands.append({"id": "external", "command": external, "count": None})
        if not commands and "No project/external test suite; generated tests are the main functional evidence" not in self.report["warnings"]:
            self.report["warnings"].append("No project/external test suite; generated tests are the main functional evidence")
        results = []
        for index, test in enumerate(commands):
            result = self.execute(test["command"], project, logs / f"existing-{index}.log",
                                  self.cfg["validation"]["test_timeout_seconds"])
            result["id"] = test["id"]
            result["case_count"] = test["count"]
            content = Path(result["log"]).read_text(errors="replace")
            if test.get("ctest") and not re.search(r"100% tests passed, 0 tests failed out of 1", content):
                result["passed"] = False
                result["reason"] = "CTest did not execute exactly one passing test"
            if re.search(r"(?i)(\*\*\*Not Run|\*\*\*Skipped|\b\d+ skipped\b|collected 0 items|no tests ran)", content):
                result["passed"] = False
                result["reason"] = "Missing/skipped tests"
            if test["count"] is None:
                match = re.search(r"(\d+) passed", content)
                result["case_count"] = int(match[1]) if match else None
                if result["case_count"] is None:
                    warning = f"{test['id']}: launcher exit checked, individual test count unavailable"
                    if warning not in self.report["warnings"]:
                        self.report["warnings"].append(warning)
            results.append(result)
            save_json(Path(result["log"]).with_suffix(".json"), result)
            if not result["passed"]:
                raise RepairError("functional_failed", json.dumps({"result": result, "log_excerpt": tail(result["log"])}))
        return results

    def poc_command(self, project: Path) -> list[str]:
        if self.adapter is None:
            raise RepairError("adaptation_failed", "No fixed PoC adapter")
        command = expand(self.adapter["command"], project, self.poc, self.external,
                         adapter=self.root / "adapter", error_status="model_output_invalid")
        if self.adapter.get("source") == "model":
            check_helper_references(self.adapter["command"], "{adapter}", self.root / "adapter")
        return command

    def run_poc(self, project: Path, build: dict, logs: Path, baseline: bool) -> list[dict]:
        count = self.cfg["validation"]["baseline_runs" if baseline else "poc_runs"]
        results = []
        fingerprints = []
        for index in range(count):
            result = self.execute(self.poc_command(project), project, logs / f"poc-{index}.log",
                                  self.cfg["validation"]["poc_timeout_seconds"],
                                  runtime_env("adapter", project, self.poc, self.root / "adapter",
                                              args=self.cfg.get("poc", {}).get("args", []), artifacts=build["artifacts"]), trace=True)
            current_artifacts = artifact_inventory(project)
            # Adapters may compile drivers in this fresh project, but existing build
            # outputs may not be replaced between build and PoC execution.
            replaced = [p for p, info in build["artifacts"].items() if current_artifacts.get(p) != info]
            content = Path(result["log"]).read_text(errors="replace")
            result["sanitizer_pids"] = sorted({int(p) for p in re.findall(
                r"==(\d+)==\s*ERROR: AddressSanitizer:", content)})
            result["binding"] = binding_evidence(result, project, current_artifacts)
            result["artifacts"] = current_artifacts
            if replaced:
                result["binding"]["passed"] = False
                result["binding"]["failure_categories"].append("preexisting_artifact_replaced")
                result["binding"]["hash_mismatches"] = sorted(set(result["binding"]["hash_mismatches"] + replaced))
            evidence = parse_asan(content, project, getattr(self, "source_catalog", None))
            result["evidence"] = evidence
            results.append(result)
            # Persist the failed invocation too, before any gate raises or retries.
            save_json(logs / "poc-results.json", results)
            diagnostic = {"command": result["command"], "returncode": result["returncode"],
                          "reason": result["reason"], "binding": binding_summary(result["binding"])}
            # Only a complete trace can establish that the launcher failed before
            # executing/loading any fresh runtime artifact. Keep resource-limit,
            # trace and integrity failures in their existing categories.
            launch_failed = (result["reason"] or "").startswith("launch_failed:")
            if ((launch_failed or (result["returncode"] not in {None, 0} and not result["reason"]
                                   and not result["binding"]["trace_errors"]))
                    and not result["sanitizer_error"] and not evidence["type"]
                    and not result["binding"]["fresh_runtime_targets"]
                    and not replaced):
                raise RepairError("adapter_execution_failed", json.dumps({
                    **diagnostic, "log_excerpt": tail(result["log"])}))
            if not result["binding"]["passed"]:
                raise RepairError("binding_failed", json.dumps({
                    **diagnostic, "log_excerpt": tail(result["log"])}))
            if baseline:
                if result["reason"] or result["returncode"] in {None, 0} or not evidence["type"]:
                    raise RepairError("reproduction_failed", json.dumps({"result": diagnostic, "log_excerpt": tail(result["log"])}))
                fingerprints.append(fingerprint(evidence))
            elif not result["passed"]:
                raise RepairError("vulnerability_failed", json.dumps({"result": diagnostic, "log_excerpt": tail(result["log"])}))
        if baseline and len(set(fingerprints)) != 1:
            raise RepairError("reproduction_failed", "PoC error fingerprint not stable across baseline runs")
        save_json(logs / "poc-results.json", results)
        return results

    def reset_project(self, project: Path, logs: Path) -> dict:
        resolved = project.resolve()
        if (self.root.resolve() not in resolved.parents or
                any(resolved == p.resolve() or p.resolve() in resolved.parents for p in self.immutable_paths())):
            raise RepairError("integrity_failed", "Cannot reset a project outside the mutable run workspace")
        shutil.rmtree(project)
        fresh_project(self.baseline, project)
        return self.build(project, logs)

    def adapt(self, project: Path, build: dict) -> list[dict]:
        adapter_dir = self.root / "adapter"
        adapter_dir.mkdir()
        if self.cfg["poc"]["command"]:
            self.adapter = {"command": self.cfg["poc"]["command"] + self.cfg["poc"]["args"], "source": "user"}
            results = self.run_poc(project, build, self.root / "baseline-validation" / "logs", True)
            save_json(adapter_dir / "adapter.json", self.adapter)
            return results
        feedback = None
        attempts = []
        poc_data = self.poc.read_bytes()
        poc_text = poc_data.decode("utf-8", errors="replace")[:20000] if b"\x00" not in poc_data[:4096] else "Binary PoC: cannot inspect source; require documented invocation"
        docs = initial_context(project, {"frames": []}, self.cfg["repair"]["context_max_bytes"])
        for attempt in range(3):
            if attempt:
                # Failed adapters can leave drivers or replace build outputs.
                # Restore the mutable project before asking for a correction.
                rebuilt = self.reset_project(project, self.root / "adaptation-attempts" / str(attempt + 1) / "rebuild-logs")
                build.clear()
                build.update(rebuilt)
            data = None
            try:
                data = self.ask_with_context("poc-adaptation", {"task": ADAPTER_SPEC,
                    "poc_name": self.poc.name, "poc_content": poc_text, "poc_args": self.cfg["poc"]["args"],
                    "project": docs, "context": docs, "context_max_bytes": self.cfg["repair"]["context_max_bytes"],
                    "build": {"kind": build["kind"],
                        **artifact_summary(build["artifacts"]),
                        "commands": [r["command"] for r in build["commands"]]}, "feedback": feedback},
                    project, self.root / "adaptation-attempts" / str(attempt + 1))
                # Remove only generated adapter files between attempts.
                shutil.rmtree(adapter_dir)
                adapter_dir.mkdir()
                write_model_files(adapter_dir, data["files"])
                for hint in helper_hints(data["files"]):
                    if hint not in self.report["warnings"]:
                        self.report["warnings"].append(hint)
                shutil.copytree(adapter_dir, self.root / "adaptation-attempts" / str(attempt + 1) / "files")
                self.adapter = {"command": argv(data["command"]), "source": "model"}
                results = self.run_poc(project, build,
                                       self.root / "adaptation-attempts" / str(attempt + 1) / "logs", True)
                save_json(adapter_dir / "adapter.json", self.adapter)
                return results
            except RepairError as exc:
                if exc.status in {"infrastructure_failed", "needs_build_change", "integrity_failed"}:
                    raise
                feedback = failure_feedback("poc-adaptation", exc, attempts, data)
            except (KeyError, TypeError, ValueError) as exc:
                feedback = failure_feedback("poc-adaptation", exc, attempts, data)
        raise RepairError("adaptation_failed", json.dumps(feedback))

    def ask_with_context(self, stage: str, payload: dict, project: Path, directory: Path) -> dict:
        additions = {}
        budget = self.cfg["repair"]["context_max_bytes"]
        used = len(json.dumps(payload.get("context", {}), ensure_ascii=False).encode())
        def context_error(message):
            exc = RepairError("model_output_invalid", message)
            exc.model_output = data
            return exc
        for batch in range(CONTEXT_BATCHES + 1):
            data = self.model.ask(stage, {**payload, "context_max_bytes": budget,
                                         "context_contract": CONTEXT_TEXT, "requested_context": additions}, directory / str(batch))
            requests = []
            for key in ("read_files", "read_files_needed"):
                value = data.get(key)
                if value is None:
                    continue
                if not isinstance(value, list):
                    raise context_error(f"{key} must be an array")
                requests.extend(value)
            if not requests:
                return data
            if batch == CONTEXT_BATCHES:
                raise context_error("Maximum additional-context batches exceeded")
            remaining = max(0, budget - used)
            try:
                content = read_requested(project, requests, remaining, self.poc.parent)
            except (KeyError, TypeError, ValueError, RepairError) as exc:
                raise context_error(f"Invalid context request: {exc}") from exc
            used += len(json.dumps(content, ensure_ascii=False).encode())
            additions.update(content)
            self.report["source_upload"].extend(content.keys())
        raise AssertionError("unreachable")

    def analyze(self, project: Path, results: list[dict]):
        self.evidence = results[0]["evidence"]
        if not any("file" in f for f in self.evidence["frames"]):
            raise RepairError("reproduction_failed", "ASan lacks project source locations; install llvm-symbolizer and build with -g")
        context = initial_context(project, self.evidence, self.cfg["repair"]["context_max_bytes"])
        self.report["source_upload"].extend(context["snippets"])
        payload = {
            "task": ANALYSIS_CONTRACT,
            "evidence": self.evidence, "asan_log": tail(results[0]["log"]), "context": context,
            "poc_file": self.poc.relative_to(self.root).as_posix()}
        feedback, attempts = None, []
        for attempt in range(3):
            data = None
            try:
                data = self.ask_with_context("impact-analysis", {**payload, "feedback": feedback},
                                             project, self.root / "analysis" / str(attempt + 1))
                status, message = analysis_contract_decision(data)
                if status == "model_output_invalid":
                    raise RepairError(status, message)
                # Supplied paths must not turn path errors into a request for contracts.
                if status == "contract_information_required":
                    if data.get("affected_files"):
                        self.allowed_files(project, data["affected_files"])
                    raise RepairError(status, message)
                self.allowed_files(project, data.get("affected_files"))
                if message and message not in self.report["warnings"]:
                    self.report["warnings"].append(message)
                self.analysis = data
                save_json(self.root / "analysis.json", self.analysis)
                return
            except RepairError as exc:
                if exc.status not in {"model_output_invalid", "patch_rejected", "invalid_path"}:
                    raise
                feedback = failure_feedback("impact-analysis", exc, attempts, data)
        raise RepairError("model_output_invalid", json.dumps(feedback))

    def allowed_files(self, project: Path, files) -> set[str]:
        if not isinstance(files, list) or not files or not all(isinstance(x, str) for x in files):
            raise RepairError("model_output_invalid", "Impact analysis must list affected_files")
        for relative in files:
            path = safe_file(project, relative)
            if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES or protected_source(relative):
                raise RepairError("patch_rejected", f"Not an editable project source/header: {relative}")
            original_root = Path(self.cfg["project"]["path"])
            for input_path in (self.cfg["poc"]["path"], self.cfg["tests"]["external_path"]):
                if input_path:
                    input_original = Path(input_path)
                    original = original_root / relative
                    if original == input_original or (input_original.is_dir() and input_original in original.parents):
                        raise RepairError("patch_rejected", f"PoC/external test source is protected: {relative}")
        return set(files)

    def install_tests(self, data: dict, prefix: str, *, allow_independent=True, require_base=False) -> list[dict]:
        entries = data.get("tests")
        if not isinstance(entries, list) or not entries:
            raise RepairError("model_output_invalid", "Nonempty tests array required")
        target = safe_file(self.root / "generated-tests", prefix)
        if target.exists():
            raise RepairError("model_output_invalid", "Cannot overwrite fixed test batch")
        staging = self.root / (".test-install-" + uuid.uuid4().hex)
        try:
            return self._stage_tests(entries, existing={t["id"] for t in self.tests}, staging=staging,
                                     target=target, allow_independent=allow_independent, require_base=require_base)
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    def _stage_tests(self, entries: list, existing: set, staging: Path, target: Path,
                     allow_independent: bool, require_base: bool) -> list[dict]:
        new = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise RepairError("model_output_invalid", "Each test entry must be an object")
            ident = entry.get("id")
            if not isinstance(ident, str) or not TEST_ID.fullmatch(ident) or ident in existing:
                raise RepairError("model_output_invalid", "Test IDs must be new and unique; "
                                  f"rejected ID={ident!r}; occupied IDs={sorted(existing)!r}. "
                                  "In repair, omit additional_tests entirely if no new tests are needed.")
            existing.add(ident)
            if not isinstance(entry.get("kind"), str) or entry["kind"] not in TEST_KINDS:
                raise RepairError("model_output_invalid", "Invalid test kind")
            if entry["kind"] == "independent" and not allow_independent:
                raise RepairError("model_output_invalid", "Repair may append public regression/vulnerability tests only; holdouts are fixed before repair")
            if entry.get("baseline") not in ("pass", "asan"):
                raise RepairError("model_output_invalid", "Invalid baseline expectation")
            required = TEST_KINDS[entry["kind"]]
            if required is not None and entry["baseline"] != required:
                raise RepairError("model_output_invalid", f"{entry['kind']} baseline must be {required}")
            if not isinstance(entry.get("expected_cases"), int) or isinstance(entry["expected_cases"], bool) or entry["expected_cases"] < 1:
                raise RepairError("model_output_invalid", "expected_cases must be positive")
            if not isinstance(entry.get("basis"), str) or not entry["basis"].strip():
                raise RepairError("model_output_invalid", "Test assertion basis is required")
            directory = staging / ident
            directory.mkdir(parents=True)
            write_model_files(directory, entry.get("files"))
            entry = copy.deepcopy(entry)
            entry["command"] = argv(entry.get("command"))
            expand(entry["command"], self.baseline, self.poc, self.external, directory,
                   error_status="model_output_invalid")
            check_helper_references(entry["command"], "{suite}", directory)
            entry["directory"] = str(target / ident)
            save_json(directory / "test.json", entry)
            new.append(entry)
        if require_base:
            if not set(TEST_KINDS).issubset({t["kind"] for t in new}):
                raise RepairError("model_output_invalid", "Need regression, vulnerability and independent tests")
            if {t["baseline"] for t in new if t["kind"] == "independent"} != {"pass", "asan"}:
                raise RepairError("model_output_invalid", "Independent set needs separate pass and asan entries")
        target.parent.mkdir(parents=True, exist_ok=True)
        staging.rename(target)
        for entry in new:
            for hint in helper_hints(entry["files"]):
                if hint not in self.report["warnings"]:
                    self.report["warnings"].append(hint)
        return new

    def generated_test(self, test: dict, project: Path, logs: Path, baseline: bool) -> dict:
        work = logs / ("work-" + test["id"])
        work.mkdir(parents=True)
        suite = work / "suite"
        shutil.copytree(Path(test["directory"]), suite)
        result_path = work / "result.json"
        command = expand(test["command"], project, self.poc, self.external, suite,
                         error_status="model_output_invalid")
        check_helper_references(test["command"], "{suite}", suite)
        before = inventory(project)
        artifacts = artifact_inventory(project)
        result = self.execute(command, project, logs / (test["id"] + ".log"),
                              self.cfg["validation"]["test_timeout_seconds"],
                              runtime_env("test", project, self.poc, suite, work=work, result=result_path,
                                          args=self.cfg["poc"]["args"], artifacts=artifacts), trace=True)
        result.update({"id": test["id"], "kind": test["kind"]})
        if inventory(project) != before:
            result.update(passed=False, reason="Generated test modified project files or artifacts")
            save_json(Path(result["log"]).with_suffix(".json"), result)
            raise RepairError("integrity_failed", result["reason"])
        content = Path(result["log"]).read_text(errors="replace")
        result["sanitizer_pids"] = sorted({int(p) for p in re.findall(r"==(\d+)==\s*ERROR: AddressSanitizer:", content)})
        result["binding"] = generated_binding(result, project, artifacts, work, self.source_catalog)
        if baseline and test["baseline"] == "asan":
            evidence = parse_asan(content, project, self.source_catalog)
            result["evidence"] = evidence
            result["passed"] = result["reason"] is None and result["returncode"] not in {None, 0} and \
                evidence["type"] == self.evidence["type"] and any("file" in f for f in evidence["frames"])
            if not result["passed"] and not result["reason"]:
                result["reason"] = "Baseline test did not reproduce matching ASan evidence"
        elif result["passed"]:
            try:
                data = json.loads(result_path.read_text())
                if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
                    raise ValueError("Result must be an object with a cases array")
                cases = data["cases"]
                if not all(isinstance(case, dict) and isinstance(case.get("id"), str)
                           and case["id"].strip() for case in cases):
                    raise ValueError("Cases must be objects with nonempty string IDs")
                ids = [case["id"] for case in cases]
                result["passed"] = len(cases) == test["expected_cases"] and len(set(ids)) == len(ids) and \
                    all(case.get("passed") is True and not case.get("skipped", False) for case in cases)
                result["cases"] = cases
                if not result["passed"]:
                    result["reason"] = "Missing/invalid test result contract"
            except (OSError, ValueError, KeyError, TypeError):
                result["passed"] = False
                result["reason"] = "Missing/invalid test result contract"
        if result["passed"] and not result["binding"]["passed"]:
            result.update(passed=False, reason="Generated test target binding failed: " +
                          ", ".join(result["binding"]["failure_categories"]))
        # Runner records the process exit; persist the controller's final verdict
        # too, including contract/ASan validation, before raising.
        save_json(Path(result["log"]).with_suffix(".json"), result)
        if not result["passed"]:
            summary = {k: v for k, v in result.items() if k != "binding"}
            summary["binding"] = binding_summary(result["binding"])
            raise RepairError("generated_test_failed", json.dumps({"result": summary, "log_excerpt": tail(result["log"])}))
        return result

    def generate_base_tests(self, project: Path):
        if not self.cfg["validation"]["generate_tests"]:
            return
        feedback = None
        attempts = []
        for attempt in range(3):
            if attempt:
                self.reset_project(project, self.root / "test-baselines" / str(attempt + 1) / "rebuild-logs")
            new = []
            data = None
            try:
                data = self.ask_with_context("generate-base-tests", {"task": TEST_SPEC +
                    " You may request additional source/header ranges via read_files before returning tests.",
                    "analysis": self.analysis, "context": initial_context(project, self.evidence,
                    self.cfg["repair"]["context_max_bytes"]), "evidence": self.evidence,
                    "build_artifacts": artifact_summary(artifact_inventory(project)),
                    "feedback": feedback}, project, self.root / "test-generation" / str(attempt + 1))
                new = self.install_tests(data, "base-" + str(attempt + 1), require_base=True)
                results = [self.generated_test(t, project, self.root / "test-baselines" / str(attempt + 1), True) for t in new]
                self.tests.extend(new)
                save_json(self.root / "generated-tests" / "index.json", self.tests)
                save_json(self.root / "test-baselines" / str(attempt + 1) / "results.json", results)
                return
            except RepairError as exc:
                if exc.status in {"infrastructure_failed", "needs_build_change", "integrity_failed"}:
                    raise
                # Independent details never enter a repair prompt, even on test correction.
                feedback = failure_feedback("generate-base-tests", exc, attempts, data)
            except (KeyError, TypeError, ValueError) as exc:
                feedback = failure_feedback("generate-base-tests", exc, attempts, data)
        raise RepairError("contract_information_required", "Generated test baseline could not be established: " + json.dumps(feedback))

    def append_tests(self, entries, round_dir: Path):
        if entries is None or entries == []:
            return
        try:
            new = self.install_tests({"tests": entries}, "append-" + round_dir.name, allow_independent=False)
        except RepairError as exc:
            if exc.status not in {"model_output_invalid", "invalid_path"}:
                raise
            # The optional batch is atomic and has not entered the fixed test set.
            # Only pre-execution schema/path errors can be skipped here.
            warning = "Skipped invalid additional_tests batch; validating patch with fixed tests: " + str(exc)
            self.report["warnings"].append(warning)
            save_json(round_dir / "additional-tests-rejected.json", {
                "status": exc.status, "reason": str(exc), "tests": entries})
            return
        baseline = round_dir / "append-baseline" / "project"
        fresh_project(self.baseline, baseline)
        logs = round_dir / "append-baseline" / "logs"
        try:
            self.build(baseline, logs)
            results = [self.generated_test(t, baseline, logs, True) for t in new]
        except Exception:
            # Failed proposals are auditable, but must not become fixed holdouts/tests.
            Path(new[0]["directory"]).parent.rename(round_dir / "rejected-tests")
            raise
        self.tests.extend(new)
        save_json(self.root / "generated-tests" / "index.json", self.tests)
        save_json(logs / "test-results.json", results)

    def validate(self, project: Path, logs: Path, independent=False) -> dict:
        build = self.build(project, logs)
        before_sources = {p.relative_to(project).as_posix(): sha(p) for p in source_files(project)}
        existing = self.run_existing(project, build, logs)
        generated = []
        selected = [t for t in self.tests if (t["kind"] == "independent") == independent]
        for test in [t for t in selected if t["baseline"] == "pass"]:
            generated.append(self.generated_test(test, project, logs, False))
        poc = self.run_poc(project, build, logs, False)
        for test in [t for t in selected if t["baseline"] == "asan"]:
            generated.append(self.generated_test(test, project, logs, False))
        after_sources = {p.relative_to(project).as_posix(): sha(p) for p in source_files(project)}
        if before_sources != after_sources:
            raise RepairError("integrity_failed", "Validation modified source/header files")
        result = {"build": build, "existing": existing, "generated": generated, "poc": poc}
        save_json(logs / "validation.json", result)
        return result

    def repair(self, baseline_project: Path):
        feedback = None
        attempts = []
        previous = None
        seen = set()
        for number in range(1, self.cfg["repair"]["max_rounds"] + 1):
            self.event(f"repair-round-{number}")
            round_dir = self.root / "rounds" / f"{number:03d}"
            project = round_dir / "project"
            fresh_project(self.baseline, project)
            record = {"number": number, "status": "running"}
            data = None
            try:
                public_tests = [{k: v for k, v in t.items() if k != "directory"}
                                for t in self.tests if t["kind"] != "independent"]
                data = self.ask_with_context("repair", {
                    "task": "Return {diagnosis,impact_analysis,affected_files:[...],patch:'unified diff',"
                            "additional_tests:[]}. Explain evidence for any newly affected files. "
                            "Patch existing source/header files only, against original baseline. "
                            "Include additional regression/vulnerability tests if new impact requires them; "
                            "use the test schema below. Append public regression/vulnerability tests only, "
                            "never independent entries. Never remove or relax fixed tests. " +
                            patch_contract(self.cfg["repair"]["max_changed_lines"]),
                    "test_schema": APPEND_TEST_SPEC, "analysis": self.analysis, "evidence": self.evidence,
                    "context": initial_context(baseline_project, self.evidence,
                                               self.cfg["repair"]["context_max_bytes"]),
                    "public_fixed_tests": public_tests, "previous_patch": previous, "feedback": feedback},
                    baseline_project, round_dir / "model")
                if not data.get("diagnosis") or not data.get("impact_analysis"):
                    raise RepairError("model_output_invalid", "diagnosis and impact_analysis required")
                allowed = self.allowed_files(project, data.get("affected_files"))
                previous = data.get("patch")
                if not isinstance(previous, str):
                    raise RepairError("model_output_invalid", "patch must be a unified diff string")
                (round_dir / "patch.diff").write_text(previous, encoding="utf-8")
                files_before = inventory(project)
                changed = apply_patch(project, previous, allowed, self.cfg["repair"]["max_changed_lines"])
                files_after = inventory(project)
                actual = {p for p in files_before.keys() | files_after.keys() if files_before.get(p) != files_after.get(p)}
                if actual != set(changed):
                    raise RepairError("integrity_failed", "Unexpected file changes while applying patch")
                if "additional_tests" in data:
                    self.append_tests(data["additional_tests"], round_dir)
                result = self.validate(project, round_dir / "logs")
                record.update({"status": "iteration_passed", "changed_files": changed, "validation": result})
                self.report["rounds"].append(record)
                save_json(round_dir / "record.json", record)
                if not self.cfg["validation"]["independent_evaluation"]:
                    self.report.update({"status": "diagnostic_only", "candidate_patch": str(round_dir / "patch.diff")})
                    return
                self.event("independent-evaluation")
                final_project = self.root / "final" / "project"
                fresh_project(self.baseline, final_project)
                apply_patch(final_project, previous, allowed, self.cfg["repair"]["max_changed_lines"])
                try:
                    # Re-run public verification and then holdout tests in another clean project.
                    self.validate(final_project, self.root / "final" / "public-logs")
                    evaluation_project = self.root / "evaluation" / "project"
                    fresh_project(self.baseline, evaluation_project)
                    apply_patch(evaluation_project, previous, allowed, self.cfg["repair"]["max_changed_lines"])
                    evaluation = self.validate(evaluation_project, self.root / "evaluation" / "logs", independent=True)
                except RepairError as exc:
                    if exc.status in {"infrastructure_failed", "integrity_failed"}:
                        raise
                    self.report.update({"status": "independent_rejected", "error": str(exc)})
                    shutil.copy2(round_dir / "patch.diff", self.root / "final" / "patch.diff")
                    return
                shutil.copy2(round_dir / "patch.diff", self.root / "final" / "patch.diff")
                save_json(self.root / "final" / "candidate.json", {"allowed_files": sorted(allowed),
                          "patch_sha256": sha(self.root / "final" / "patch.diff"),
                          "fixed_inventory": fixed_inventory(self.immutable_paths())})
                self.report.update({"status": "validated_candidate", "changed_files": changed,
                                    "independent_result": evaluation})
                return
            except RepairError as exc:
                if exc.status in {"infrastructure_failed", "needs_build_change", "integrity_failed", "build_information_required",
                                  "test_information_required"}:
                    raise
                feedback = failure_feedback("repair", exc, attempts, data)
                record.update(feedback)
            except (KeyError, TypeError, ValueError, UnicodeError) as exc:
                feedback = failure_feedback("repair", exc, attempts, data)
                record.update(feedback)
            self.report["rounds"].append(record)
            save_json(round_dir / "record.json", record)
            if previous:
                marker = (previous, feedback["status"])
                if marker in seen:
                    self.report.update({"status": "rounds_exhausted", "error": "Repeated patch with same failure category"})
                    return
                seen.add(marker)
        self.report.update({"status": "rounds_exhausted", "error": feedback})

    def run(self) -> dict:
        try:
            self.prepare()
            self.event("baseline-build")
            project = self.root / "baseline-validation" / "project"
            removed = fresh_project(self.baseline, project)
            save_json(self.root / "baseline-validation" / "removed-artifacts.json", removed)
            build = self.build(project, self.root / "baseline-validation" / "logs")
            self.event("poc-adaptation-and-reproduction")
            poc_results = self.adapt(project, build)
            self.event("baseline-functional-tests")
            self.run_existing(project, build, self.root / "baseline-validation" / "logs")
            self.event("multi-file-impact-analysis")
            self.analyze(project, poc_results)
            self.event("generate-and-fix-tests")
            self.generate_base_tests(project)
            if not self.cfg["validation"]["generate_tests"] or not self.cfg["validation"]["independent_evaluation"]:
                self.report["status"] = "diagnostic_only"
            else:
                self.repair(project)
        except KeyboardInterrupt:
            self.report.update({"status": "interrupted", "error": "User interrupted; process group terminated"})
        except RepairError as exc:
            self.report.update({"status": exc.status, "error": str(exc)})
        except Exception as exc:
            self.report.update({"status": "infrastructure_failed", "error": f"{type(exc).__name__}: {exc}"})
        finally:
            self.finish()
        return self.report

    def finish(self):
        if self.fixed_start and fixed_inventory([Path(p) for p in self.fixed_start]) != self.fixed_start:
            self.report.update({"status": "integrity_failed", "error": "Baseline or input snapshot changed"})
        if inventory(Path(self.cfg["project"]["path"])) != self.original_inventory:
            self.report.update({"status": "integrity_failed", "error": "Original project changed during task; do not accept candidate"})
        self.report["seconds"] = round(time.monotonic() - self.started, 3)
        self.report["source_upload"] = sorted(set(self.report["source_upload"]))
        self.report["model_calls"] = self.model.calls if self.model else []
        secret = model_secret(self.cfg)
        report = redact_data(self.report, secret)
        save_json(self.root / "report.json", report)
        final = self.root / "final"
        final.mkdir(exist_ok=True)
        save_json(final / "report.json", report)
        body = html.escape(json.dumps(report, ensure_ascii=False, indent=2))
        status = html.escape(report["status"])
        rows = "".join(f'<tr><td>{r["number"]}</td><td>{html.escape(r["status"])}</td></tr>'
                       for r in report["rounds"])
        warnings = "".join(f"<li>{html.escape(w)}</li>" for w in report["warnings"])
        sources = "".join(f"<li>{html.escape(p)}</li>" for p in report.get("changed_files", []))
        patch_path = final / "patch.diff"
        patch_html = '<h2>候选补丁</h2><p><a href="patch.diff">下载 diff</a></p><pre>' + \
            html.escape(patch_path.read_text(errors="replace")) + '</pre>' if patch_path.exists() else ''
        (final / "report.html").write_text(
            '<!doctype html><meta charset="utf-8"><title>Repair report</title>'
            '<style>body{max-width:1100px;margin:30px auto;padding:20px;font:16px system-ui}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:16px}'
            'td,th{padding:8px 16px;border:1px solid #ddd}table{border-collapse:collapse}</style>'
            '<h1>漏洞修复审查报告</h1><p>通过既定测试不等于完整正确性证明。集成前请审查补丁。</p>'
            f'<h2>状态：{status}</h2><p>运行耗时：{report["seconds"]} 秒；模型调用：{len(report["model_calls"])} 次。</p>'
            f'<h2>修改文件</h2><ul>{sources}</ul><h2>修复轮次</h2>'
            f'<table><tr><th>轮次</th><th>结果</th></tr>{rows}</table>'
            f'<h2>验证限制</h2><ul>{warnings}</ul>{patch_html}'
            f'<details><summary>完整证据和运行记录</summary><pre>{body}</pre></details>', encoding="utf-8")
        if not self.cfg["output"]["keep_round_projects"]:
            for path in (self.root / "rounds").glob("*/project"):
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
        print(f"Result: {report['status']}\nReport: {final / 'report.html'}", flush=True)


def verify_run(root: Path) -> dict:
    root = root.resolve()
    cfg = json.loads((root / "config.json").read_text())
    candidate = json.loads((root / "final" / "candidate.json").read_text())
    if sha(root / "final" / "patch.diff") != candidate["patch_sha256"]:
        raise RepairError("integrity_failed", "Final patch hash changed")
    if fixed_inventory([Path(p) for p in candidate["fixed_inventory"]]) != candidate["fixed_inventory"]:
        raise RepairError("integrity_failed", "Baseline/input/adapter/tests changed since acceptance")
    # No model client and no API key required for verification.
    flow = object.__new__(Workflow)
    flow.cfg, flow.root, flow.runner = cfg, root, Runner(cfg)
    flow.baseline = root / "baseline" / "project"
    flow.source_catalog = {p.relative_to(flow.baseline).as_posix() for p in source_files(flow.baseline)}
    flow.poc = root / "inputs" / "poc" / Path(cfg["poc"]["path"]).name
    external_root = root / "inputs" / "external-tests"
    original_external = cfg["tests"]["external_path"]
    flow.external = None
    if original_external:
        # Resolve from saved snapshot, not a potentially removed original input.
        child = external_root / Path(original_external).name
        flow.external = child if child.is_file() else external_root
    flow.adapter = json.loads((root / "adapter" / "adapter.json").read_text())
    flow.tests = json.loads((root / "generated-tests" / "index.json").read_text())
    flow.report = {"warnings": []}
    flow.evidence = None
    directory = root / "verification" / uuid.uuid4().hex[:8]
    project = directory / "project"
    fresh_project(flow.baseline, project)
    patch = (root / "final" / "patch.diff").read_text()
    apply_patch(project, patch, set(candidate["allowed_files"]), cfg["repair"]["max_changed_lines"])
    public = flow.validate(project, directory / "public")
    independent_project = directory / "independent-project"
    fresh_project(flow.baseline, independent_project)
    apply_patch(independent_project, patch, set(candidate["allowed_files"]), cfg["repair"]["max_changed_lines"])
    independent = flow.validate(independent_project, directory / "independent", True)
    result = {"status": "validated_candidate", "public": public, "independent": independent}
    save_json(directory / "result.json", result)
    return result
