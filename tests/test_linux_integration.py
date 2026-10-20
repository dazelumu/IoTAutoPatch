"""Real subprocess/ASan/strace checks; no cloud API or system installation."""
from __future__ import annotations

import copy
import difflib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from repair_tool.config import load_config
from repair_tool.execution import Runner
from repair_tool.storage import inventory
from repair_tool.workflow import Workflow, verify_run

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux") or
        not all(shutil.which(t) for t in ("gcc", "make", "strace")),
        reason="Requires Linux, GCC, make and strace"),
]


HEADER = "#define IN_BOUNDS(i, n) ((i) <= (n))\nint read_at(const char *p, unsigned n, unsigned i);\n"
API = """#include "api.h"
int read_at(const char *p, unsigned n, unsigned i) {
    if (!IN_BOUNDS(i, n)) return -1;
    return (unsigned char)p[i];
}
"""
MAIN = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned n = strlen(argv[1]);
    char *p = malloc(n ? n : 1);
    if (!p) return 2;
    memcpy(p, argv[1], n);
    int result = read_at(p, n + 1, atoi(argv[2]));
    printf("%d\\n", result);
    free(p);
    return 0;
}
"""


def make_case(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for name, content in (("api.h", HEADER), ("api.c", API), ("main.c", MAIN)):
        (root / name).write_text(content)
    # Non-PIE makes GCC ASan reliable on hosts with very high mmap randomization.
    (root / "Makefile").write_text(
        "all: app\napp: main.c api.c api.h\n\t$(CC) $(CFLAGS) -fno-pie -no-pie main.c api.c $(LDFLAGS) -o app\n"
        "check: app\n\ttest \"$$('./app' AB 0)\" = 65\n")
    poc = tmp_path / "poc"
    poc.mkdir()
    (poc / "poc.py").write_text(
        "import subprocess,sys\nr=subprocess.run([sys.argv[1],'ABC','3'])\nsys.exit(r.returncode)\n")
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump({"project": {"path": "project"}, "poc": {"path": "poc/poc.py"},
        "model": {"base_url": "https://example.test/v1", "name": "fake"},
        "validation": {"baseline_runs": 2, "poc_runs": 2}}))
    return path, root


def generated_entry(ident, kind, baseline, value, index, expected):
    script = f"""import json,os,subprocess,sys
r=subprocess.run([sys.argv[1],{value!r},{str(index)!r}],capture_output=True,text=True)
print(r.stdout,end=''); print(r.stderr,end='',file=sys.stderr)
if r.returncode: sys.exit(r.returncode if r.returncode > 0 else 1)
assert r.stdout.strip()=={str(expected)!r}, (r.stdout,{str(expected)!r})
with open(os.environ['REPAIR_TEST_RESULT'],'w') as f:
    json.dump({{'cases':[{{'id':{ident!r},'passed':True}}]}},f)
"""
    return {"id": ident, "kind": kind, "baseline": baseline, "basis": "read_at returns a byte or -1 outside buffer",
            "expected_cases": 1, "command": ["python3", "{suite}/run.py", "{project}/app"],
            "files": [{"path": "run.py", "content": script}]}


def correct_patch():
    return "".join(difflib.unified_diff(HEADER.splitlines(True), HEADER.replace("<=", "<").splitlines(True),
                                      "a/api.h", "b/api.h")) + \
        "".join(difflib.unified_diff(MAIN.splitlines(True), MAIN.replace("n + 1,", "n,").splitlines(True),
                                    "a/main.c", "b/main.c"))


class FakeModel:
    def __init__(self, cfg, root):
        self.calls = []
        self.root = root
        self.cfg = cfg

    def ask(self, stage, payload, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "prompt.json").write_text(json.dumps(payload))
        self.calls.append({"stage": stage})
        if stage == "poc-adaptation":
            return {"files": [{"path": "note.txt", "content": "Adapter uses original PoC unchanged"}],
                    "command": ["python3", "{poc}", "{project}/app"]}
        if stage == "impact-analysis":
            return {"diagnosis": "Caller length and bound macro both admit out-of-bounds reads",
                    "affected_files": ["api.h", "main.c"], "contracts": "out-of-range returns -1",
                    "interfaces": ["read_at"], "callers": ["main"], "ownership_effects": "none",
                    "test_plan": "normal and boundary", "evidence": "ASan", "contract_uncertain": False}
        if stage == "generate-base-tests":
            return {"tests": [generated_entry("normal", "regression", "pass", "AB", 0, 65),
                              generated_entry("boundary", "vulnerability", "asan", "ABC", 3, -1),
                              generated_entry("holdout-normal", "independent", "pass", "XYZ", 1, 89),
                              generated_entry("holdout-boundary", "independent", "asan", "ABCD", 4, -1)]}
        if stage == "repair":
            # The independent test content must not enter repair payload.
            assert "holdout-normal" not in json.dumps(payload)
            assert "holdout-boundary" not in json.dumps(payload)
            return {"diagnosis": "Fix both lengths", "impact_analysis": "Preserve valid reads",
                    "affected_files": ["api.h", "main.c"], "patch": correct_patch(),
                    "additional_tests": [generated_entry("extra-normal", "regression", "pass", "Q", 0, 81)]}
        raise AssertionError(stage)


@pytest.mark.parametrize("inaccurate_headers", [False, True])
def test_real_multifile_repair_and_fresh_verify(tmp_path, monkeypatch, inaccurate_headers):
    if inaccurate_headers:
        raw_patch = re.sub(r"(@@ -\d+),\d+ \+\d+,\d+ @@", r"\1,99 +999,1 @@", correct_patch())
        monkeypatch.setattr(sys.modules[__name__], "correct_patch", lambda: raw_patch)
    path, root = make_case(tmp_path)
    before = inventory(root)
    monkeypatch.setenv("REPAIR_API_KEY", "not-sent-to-processes")
    flow = Workflow(load_config(path), model_factory=FakeModel)
    report = flow.run()
    assert report["status"] == "validated_candidate", report.get("error")
    assert report["changed_files"] == ["api.h", "main.c"]
    assert inventory(root) == before
    assert (flow.root / "final" / "project" / "api.c").read_text() == API
    if inaccurate_headers:
        assert (flow.root / "final" / "patch.diff").read_text() == raw_patch
    monkeypatch.delenv("REPAIR_API_KEY")
    assert verify_run(flow.root)["status"] == "validated_candidate"


def test_invalid_optional_batch_still_reaches_independent_evaluation(tmp_path, monkeypatch):
    class InvalidExtrasModel(FakeModel):
        def ask(self, stage, payload, directory):
            result = super().ask(stage, payload, directory)
            if stage == "repair":
                assert "Include all three kinds" not in payload["test_schema"]
                result["additional_tests"] = [generated_entry("normal", "regression", "pass", "AB", 0, 65),
                                              generated_entry("new-independent", "independent", "pass", "AB", 0, 65)]
            return result
    path, root = make_case(tmp_path)
    before = inventory(root)
    monkeypatch.setenv("REPAIR_API_KEY", "not-sent-to-processes")
    flow = Workflow(load_config(path), model_factory=InvalidExtrasModel)
    report = flow.run()
    assert report["status"] == "validated_candidate", report.get("error")
    assert len(report["rounds"]) == 1
    assert report["independent_result"]
    assert any("Skipped invalid additional_tests" in w for w in report["warnings"])
    assert len(flow.tests) == 4
    assert inventory(root) == before
    assert (flow.root / "rounds/001/additional-tests-rejected.json").exists()
    assert (flow.root / "rounds/001/logs/validation.json").exists()


def test_timeout_terminates_process_group(tmp_path):
    path, _ = make_case(tmp_path)
    runner = Runner(load_config(path))
    command = ["python3", "-c", "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)"]
    started = time.monotonic()
    result = runner.run(command, tmp_path, tmp_path / "timeout.log", 1)
    assert result["reason"] == "timeout" and not result["passed"]
    assert time.monotonic() - started < 5


def test_child_cannot_read_model_key(tmp_path, monkeypatch):
    path, _ = make_case(tmp_path)
    monkeypatch.setenv("REPAIR_API_KEY", "secret")
    result = Runner(load_config(path)).run(
        ["python3", "-c", "import os; assert 'REPAIR_API_KEY' not in os.environ"], tmp_path,
        tmp_path / "environment.log", 10)
    assert result["passed"]


def test_failed_poc_feedback_then_next_round(tmp_path, monkeypatch):
    path, root = make_case(tmp_path)
    before = inventory(root)
    class RetryingModel(FakeModel):
        repairs = 0
        def ask(self, stage, payload, directory):
            result = super().ask(stage, payload, directory)
            if stage == "repair":
                self.repairs += 1
                if self.repairs == 1:
                    # Only caller corrected: bound macro still reads one past the end.
                    result["patch"] = "".join(difflib.unified_diff(MAIN.splitlines(True),
                        MAIN.replace("n + 1,", "n,").splitlines(True), "a/main.c", "b/main.c"))
                    result["additional_tests"] = []
                else:
                    assert payload["feedback"]["status"] == "vulnerability_failed"
                    assert "AddressSanitizer" in payload["feedback"]["error"]
                    assert payload["previous_patch"]
            return result
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=RetryingModel)
    result = flow.run()
    assert result["status"] == "validated_candidate", result.get("error")
    assert len(result["rounds"]) == 2
    assert result["rounds"][0]["status"] == "vulnerability_failed"
    assert inventory(root) == before


def test_independent_reject_stops_without_feedback(tmp_path, monkeypatch):
    path, root = make_case(tmp_path)
    class OverfittingModel(FakeModel):
        repairs = 0
        def ask(self, stage, payload, directory):
            result = super().ask(stage, payload, directory)
            if stage == "repair":
                self.repairs += 1
                assert self.repairs == 1
                bad = MAIN.replace("n + 1,", "n,").replace('    printf(',
                    '    if (n == 3 && atoi(argv[2]) == 1) result = -1;\n    printf(')
                result["patch"] = "".join(difflib.unified_diff(HEADER.splitlines(True),
                    HEADER.replace("<=", "<").splitlines(True), "a/api.h", "b/api.h")) + \
                    "".join(difflib.unified_diff(MAIN.splitlines(True), bad.splitlines(True), "a/main.c", "b/main.c"))
            return result
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    before = inventory(root)
    flow = Workflow(load_config(path), model_factory=OverfittingModel)
    result = flow.run()
    assert result["status"] == "independent_rejected", result.get("error")
    assert flow.model.repairs == 1
    assert inventory(root) == before


def test_source_modification_during_execution_rejected(tmp_path, monkeypatch):
    path, root = make_case(tmp_path)
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=FakeModel)
    flow.prepare()
    from repair_tool.storage import fresh_project
    from repair_tool.config import RepairError
    project = flow.root / "scratch" / "project"
    fresh_project(flow.baseline, project)
    with pytest.raises(RepairError, match="tracked input"):
        flow.execute(["python3", "-c", "from pathlib import Path; Path('api.h').write_text('cheat')"],
                     project, flow.root / "scratch" / "execution.log", 10)
    assert inventory(root) == flow.original_inventory


@pytest.mark.skipif(not shutil.which("cmake") or not shutil.which("ctest"), reason="CMake and CTest unavailable")
def test_real_cmake_build_and_ctest_discovery(tmp_path, monkeypatch):
    path, root = make_case(tmp_path)
    (root / "Makefile").unlink()
    (root / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.16)\nproject(demo C)\n'
        'add_executable(app main.c api.c)\ntarget_compile_options(app PRIVATE -fno-pie)\n'
        'target_link_options(app PRIVATE -no-pie)\nenable_testing()\n'
        'add_test(NAME normal COMMAND app AB 0)\n')
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=FakeModel)
    flow.prepare()
    from repair_tool.storage import fresh_project
    project = flow.root / "scratch" / "project"
    fresh_project(flow.baseline, project)
    build = flow.build(project, flow.root / "scratch" / "logs")
    assert build["kind"] == "cmake"
    assert len(build["project_tests"]) == 1
    results = flow.run_existing(project, build, flow.root / "scratch" / "test-logs")
    assert results[0]["passed"] and results[0]["case_count"] == 1


def test_real_elf_symbols_link_only_and_stripped_tables(tmp_path):
    from repair_tool.execution import instrumented, artifact_inventory
    from repair_tool.elf import elf_evidence
    source = tmp_path / "tiny.c"
    source.write_text('const char *names="__asan_init __asan_report_load1";\n'
                      'int foo(const int *p) { return *p; }\n')
    plain = tmp_path / "plain.so"
    obj = tmp_path / "instrumented.o"
    shared = tmp_path / "instrumented.so"
    subprocess.run(["gcc", "-shared", "-fPIC", str(source), "-o", str(plain)], check=True)
    assert not instrumented(plain)
    with plain.open("ab") as out:
        out.write(b"__asan_init")
    assert not instrumented(plain)
    subprocess.run(["gcc", "-c", "-fPIC", "-fsanitize=address", str(source), "-o", str(obj)], check=True)
    assert instrumented(obj) and not elf_evidence(obj)["runtime_target"]
    # Deliberately omit ASan at final DSO link: UND symbols must suffice.
    subprocess.run(["gcc", "-shared", str(obj), "-o", str(shared)], check=True)
    info = elf_evidence(shared)
    assert info["asan"] and info["runtime_target"] and not info["asan_evidence"]["needed"]
    assert any(s["name"] == "__asan_init" and s["section"] == "SHN_UNDEF" for s in info["asan_evidence"]["symbols"])
    if shutil.which("strip"):
        subprocess.run(["strip", "--strip-all", str(shared)], check=True)
        assert instrumented(shared)
    # A sectionless DSO still has real dynamic symbols in DT_SYMTAB.
    data = bytearray(shared.read_bytes())
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HHH", data, 58, 0, 0, 0)
    shared.write_bytes(data)
    assert instrumented(shared)
    linked = tmp_path / "linked_only.so"
    subprocess.run(["gcc", "-shared", "-fPIC", str(source), "-Wl,--no-as-needed", "-lasan",
                    "-o", str(linked)], check=True)
    assert elf_evidence(linked)["asan_evidence"]["needed"]
    assert not elf_evidence(linked)["asan_evidence"]["symbols"]
    assert artifact_inventory(tmp_path)["instrumented.o"]["elf_type"] == "ET_REL"
    if shutil.which("ar"):
        archive = tmp_path / "libinstrumented.a"
        subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
        assert not artifact_inventory(tmp_path)[archive.name]["runtime_target"]


def test_real_shared_library_binding_rejects_old_loaded_library(tmp_path):
    from repair_tool.execution import artifact_inventory, binding_evidence
    path, _ = make_case(tmp_path)
    runner = Runner(load_config(path))
    project = tmp_path / "binding-project"
    project.mkdir()
    source = project / "library.c"
    source.write_text('int foo(const int *p) { return *p; }\n')
    fresh = project / "fresh.so"
    old = tmp_path / "old.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-fsanitize=address", str(source), "-o", str(fresh)], check=True)
    shutil.copy2(fresh, old)
    driver = project / "driver"
    driver_source = project / "driver.c"
    driver_source.write_text('#include <dlfcn.h>\n#include <fcntl.h>\n#include <unistd.h>\n'
        'int main(int argc,char **argv) {\n'
        ' if(argc>2) { int fd=open(argv[2],O_RDONLY); if(fd<0) return 2; close(fd); }\n'
        ' return dlopen(argv[1],RTLD_NOW) ? 0 : 3;\n}\n')
    # Linked runtime supplies the DSO's ASan references; source itself is uninstrumented.
    subprocess.run(["gcc", "-fno-pie", "-no-pie", str(driver_source), "-Wl,--no-as-needed",
                    "-lasan", "-ldl", "-o", str(driver)], check=True)
    artifacts = artifact_inventory(project)
    result = runner.run([str(driver), str(fresh), str(old)], project, tmp_path / "fresh.log", 15, trace=True)
    assert result["passed"]
    bound = binding_evidence(result, project, artifacts)
    assert bound["passed"] and "fresh.so" in bound["fresh_asan_targets"]
    assert any(b["kind"] == "load" and b["target"] == "fresh.so" for b in bound["process_bindings"])
    result = runner.run([str(driver), str(old)], project, tmp_path / "old.log", 15, trace=True)
    bound = binding_evidence(result, project, artifacts)
    assert not bound["passed"] and str(old) in bound["foreign_asan_targets"]


def test_compiler_adapter_retry_sends_compact_feedback_and_keeps_failure(tmp_path, monkeypatch):
    path, _ = make_case(tmp_path)
    class CompilerAdapterModel(FakeModel):
        attempts = 0
        def ask(self, stage, payload, directory):
            if stage != "poc-adaptation":
                return super().ask(stage, payload, directory)
            self.attempts += 1
            assert "sha256" not in json.dumps(payload["build"])
            if self.attempts == 1:
                return {"files": [{"path": "note.txt", "content": "invalid binding attempt"}],
                        "command": ["true", "{project}/app"]}
            assert "sha256" not in payload["feedback"]["error"]
            if self.attempts == 2:
                assert payload["feedback"]["status"] == "binding_failed"
                assert "log_excerpt" in json.loads(payload["feedback"]["error"])
                script = ("import subprocess,sys\n"
                          "subprocess.run(['cc','-x','c','-fsyntax-only',sys.argv[1]],check=True)\n")
                return {"files": [{"path": "launch.py", "content": script},
                                  {"path": "broken.c", "content": '#include "repair_missing_header.h"\n'}],
                        "command": ["python3", "{adapter}/launch.py", "{adapter}/broken.c"]}
            assert payload["feedback"]["status"] == "adapter_execution_failed"
            assert "repair_missing_header.h" in json.loads(payload["feedback"]["error"])["log_excerpt"]
            script = ("import pathlib,subprocess,sys\nroot=pathlib.Path(sys.argv[1])\n"
                "out=root/'.repair-poc'/'driver'\nout.parent.mkdir(exist_ok=True)\n"
                "subprocess.run(['cc','-g','-fsanitize=address','-fno-pie','-no-pie',"
                "str(root/'main.c'),str(root/'api.c'),'-o',str(out)],check=True)\n"
                "r=subprocess.run([sys.executable,sys.argv[2],str(out)])\n"
                "sys.exit(r.returncode if r.returncode >= 0 else 1)\n")
            return {"files": [{"path": "launch.py", "content": script}],
                    "command": ["python3", "{adapter}/launch.py", "{project}", "{poc}"]}
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=CompilerAdapterModel)
    flow.prepare()
    from repair_tool.storage import fresh_project
    project = flow.root / "scratch" / "project"
    fresh_project(flow.baseline, project)
    build = flow.build(project, flow.root / "scratch" / "logs")
    results = flow.adapt(project, build)
    assert ".repair-poc/driver" in results[0]["binding"]["fresh_asan_targets"]
    assert not results[0]["binding"]["unbound_sanitizer_pids"]
    failed = flow.root / "adaptation-attempts/1/logs/poc-results.json"
    assert not json.loads(failed.read_text())[0]["binding"]["passed"]
    failed_compile = flow.root / "adaptation-attempts/2/logs/poc-results.json"
    assert json.loads(failed_compile.read_text())[0]["binding"]["fresh_runtime_targets"] == []


@pytest.mark.parametrize("dirty_artifact", ["driver", "app"])
def test_adapter_retry_rebuilds_project_and_discards_failed_outputs(tmp_path, monkeypatch, dirty_artifact):
    path, _ = make_case(tmp_path)
    class DirtyRetryModel(FakeModel):
        attempts = 0
        def ask(self, stage, payload, directory):
            if stage != "poc-adaptation":
                return super().ask(stage, payload, directory)
            self.attempts += 1
            if self.attempts == 1:
                script = ("import pathlib,subprocess,sys\nroot=pathlib.Path(sys.argv[1])\n"
                          "out=root/'.repair-poc'/'driver'\nout.parent.mkdir(exist_ok=True)\n"
                          "subprocess.run(['cc','-g','-fsanitize=address','-fno-pie','-no-pie',"
                          "str(root/'main.c'),str(root/'api.c'),'-o',str(out)],check=True)\n")
                if dirty_artifact == "app":
                    script += "(root/'app').write_bytes(b'overwritten build output')\n"
                script += "sys.exit(1)\n"
                return {"files": [{"path": "launch.py", "content": script}],
                        "command": ["python3", "{adapter}/launch.py", "{project}"]}
            expected = "binding_failed" if dirty_artifact == "app" else "adapter_execution_failed"
            assert payload["feedback"]["status"] == expected
            assert not (project / ".repair-poc/driver").exists()
            assert artifact_inventory(project) == original_artifacts
            return super().ask(stage, payload, directory)
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=DirtyRetryModel)
    flow.prepare()
    from repair_tool.storage import fresh_project
    from repair_tool.execution import artifact_inventory
    project = flow.root / "scratch/project"
    fresh_project(flow.baseline, project)
    build = flow.build(project, flow.root / "scratch/logs")
    original_artifacts = build["artifacts"].copy()
    results = flow.adapt(project, build)
    assert results[0]["binding"]["passed"]
    assert build["artifacts"] == artifact_inventory(project)
    assert flow.model.attempts == 2


def test_runner_launch_failure_includes_log(tmp_path):
    path, _ = make_case(tmp_path)
    result = Runner(load_config(path)).run([str(tmp_path / "missing-launcher")], tmp_path,
                                           tmp_path / "launch.log", 10)
    assert result["reason"].startswith("launch_failed:") and not result["passed"]
    assert "missing-launcher" in Path(result["log"]).read_text()


def prepared_flow(tmp_path, monkeypatch, model_factory=FakeModel):
    path, _ = make_case(tmp_path)
    monkeypatch.setenv("REPAIR_API_KEY", "local-test")
    flow = Workflow(load_config(path), model_factory=model_factory)
    flow.prepare()
    from repair_tool.storage import fresh_project
    project = flow.root / "scratch/project"
    fresh_project(flow.baseline, project)
    build = flow.build(project, flow.root / "scratch/logs")
    return flow, project, build


def test_env_only_adapter_retry_sees_previous_script(tmp_path, monkeypatch):
    class EnvAdapter(FakeModel):
        def ask(self, stage, payload, directory):
            if stage != "poc-adaptation":
                return super().ask(stage, payload, directory)
            if payload["feedback"] is None:
                script = "raise RuntimeError('first-launch-failed')\n"
            else:
                previous = payload["feedback"]["previous_attempts"][-1]["output"]
                assert previous["files"][0]["content"] == "raise RuntimeError('first-launch-failed')\n"
                assert previous["command"] == ["python3", "{adapter}/launch.py"]
                script = ("import os,json,sys\n"
                          "args=json.loads(os.environ['REPAIR_POC_ARGS'])\n"
                          "os.execv(sys.executable,[sys.executable,os.environ['REPAIR_POC'],"
                          "os.path.join(os.environ['REPAIR_PROJECT'],'app'),*args])\n")
            return dict(files=[dict(path="launch.py", content=script)], command=["python3", "{adapter}/launch.py"])
    flow, project, build = prepared_flow(tmp_path, monkeypatch, EnvAdapter)
    assert flow.adapt(project, build)[0]["binding"]["passed"]


def test_generated_driver_uses_env_work_and_current_sources(tmp_path, monkeypatch):
    flow, project, _ = prepared_flow(tmp_path, monkeypatch)
    code = ("#include \"api.h\"\nint main(void) { return read_at(\"AB\", 2, 0) == 65 ? 0 : 1; }\n")
    script = """import os,json,subprocess
from pathlib import Path
project=Path(os.environ['REPAIR_PROJECT'])
suite=Path(os.environ['REPAIR_SUITE'])
out=Path(os.environ['REPAIR_WORK'])/'driver'
subprocess.run(['cc','-fsanitize=address','-g','-fno-omit-frame-pointer','-fno-pie','-no-pie',
               '-I'+str(project),str(suite/'driver.c'),str(project/'api.c'),'-o',str(out)],check=True)
subprocess.run([str(out)],check=True)
Path(os.environ['REPAIR_TEST_RESULT']).write_text(json.dumps({'cases':[{'id':'value','passed':True}]}))
"""
    test = dict(id="env-driver", kind="regression", baseline="pass", basis="read_at valid byte", expected_cases=1,
                command=["python3", "{suite}/run.py"], files=[dict(path="run.py", content=script), dict(path="driver.c", content=code)])
    entry = flow.install_tests({"tests": [test]}, "base")[0]
    result = flow.generated_test(entry, project, flow.root / "driver-logs", True)
    assert result["passed"] and result["binding"]["driver_provenance"]
    assert any("api.c" in p for r in result["binding"]["driver_provenance"] for p in r["inputs"])


def test_generated_pass_record_without_execution_fails_on_linux(tmp_path, monkeypatch):
    from repair_tool.config import RepairError
    flow, project, _ = prepared_flow(tmp_path, monkeypatch)
    script = ("import os\nfrom pathlib import Path\n"
              "Path(os.environ['REPAIR_TEST_RESULT']).write_text('{\"cases\":[{\"id\":\"fake\",\"passed\":true}]}')\n")
    test = dict(id="fake", kind="regression", baseline="pass", basis="fake assertion", expected_cases=1,
                command=["python3", "{suite}/run.py"], files=[dict(path="run.py", content=script)])
    entry = flow.install_tests({"tests": [test]}, "base")[0]
    with pytest.raises(RepairError, match="target binding failed"):
        flow.generated_test(entry, project, flow.root / "fake-logs", False)


def test_shell_syntax_preflight(tmp_path):
    from repair_tool.config import RepairError
    from repair_tool.workflow import write_model_files
    with pytest.raises(RepairError, match="Shell syntax in bad.sh"):
        write_model_files(tmp_path / "helpers", [dict(path="bad.sh", content="if then\n")])
    assert not (tmp_path / "helpers").exists()
