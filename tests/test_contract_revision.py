from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from elf_fixture import elf_bytes
from repair_tool.config import DEFAULTS, RepairError
from repair_tool.contracts import (ANALYSIS_CONTRACT, RUNTIME, STAGE_RUNTIME,
                                   analysis_contract_decision, contract_text, runtime_env)
from repair_tool.diagnostics import failure_feedback
from repair_tool.evidence import parse_asan, read_requested
from repair_tool.execution import artifact_inventory, expand, generated_binding
from repair_tool.patching import apply_patch
from repair_tool.workflow import APPEND_TEST_SPEC, TEST_SPEC, Workflow, write_model_files


@pytest.fixture
def flow(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_text("int value(void) { return 1; }\n")
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update(base_url="https://example.test/v1", name="test-model")
    cfg["project"]["path"] = str(project)
    cfg["poc"]["path"] = str(tmp_path / "poc" / "poc.c")
    cfg["output"]["directory"] = str(tmp_path / "results")
    workflow = Workflow(cfg)
    workflow.poc.parent.mkdir(parents=True)
    workflow.poc.write_text("int main(void) { return value(); }\n")
    workflow.evidence = {"type": "heap-buffer-overflow", "frames": [{"file": "a.c", "line": 1}]}
    return workflow, project


def entry(ident="normal", kind="regression", baseline="pass"):
    return dict(id=ident, kind=kind, baseline=baseline, basis="value API", expected_cases=1,
                files=[dict(path="run.py", content="pass\n")], command=["python3", "{suite}/run.py"])


def test_test_schemas_separate_base_and_repair_requirements():
    assert "Include all three kinds" in TEST_SPEC
    assert "Include all three kinds" not in APPEND_TEST_SPEC
    assert "independent coverage" not in APPEND_TEST_SPEC.lower()
    assert "never independent" in APPEND_TEST_SPEC
    assert "omit it" in APPEND_TEST_SPEC
    for schema in (TEST_SPEC, APPEND_TEST_SPEC):
        assert "SAME fixed script" in schema
        assert "On target exit 0 with no ASan" in schema
        assert "functional assertions" in schema


@pytest.mark.parametrize("entries", [
    [entry()], [entry("new-holdout", "independent", "pass")],
    [entry("new"), entry("new")], [entry("new"), None], {}, "bad",
    [dict(entry("new"), files=[dict(path="run.py", content="if :")])],
])
@pytest.mark.parametrize("fixed_failure", [False, True])
def test_invalid_optional_batch_keeps_patch_and_fixed_tests(flow, monkeypatch, entries, fixed_failure):
    from repair_tool.storage import snapshot
    workflow, project = flow
    (project / "a.c").write_bytes(b"int value(void) { return 1; }\n")
    snapshot(project, workflow.baseline)
    workflow.tests = [entry(), entry("holdout", "independent", "pass")]
    fixed_before = copy.deepcopy(workflow.tests)
    workflow.cfg["validation"]["independent_evaluation"] = False
    prompts, validations = [], []
    patch = "--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-int value(void) { return 1; }\n+int value(void) { return 2; }\n"
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            return dict(diagnosis="bounds", impact_analysis="preserve API", affected_files=["a.c"],
                        patch=patch, additional_tests=entries)
    workflow.model = Model()
    def validate(patched, logs, independent=False):
        assert "return 2" in (patched / "a.c").read_text()
        logs.mkdir(parents=True)
        validations.append(patched)
        if fixed_failure:
            raise RepairError("generated_test_failed", "fixed test failed")
        return {"validated": True}
    monkeypatch.setattr(workflow, "validate", validate)
    workflow.repair(project)
    assert workflow.report["status"] == ("rounds_exhausted" if fixed_failure else "diagnostic_only")
    assert len(validations) == len(prompts) == (2 if fixed_failure else 1)
    assert prompts[0]["test_schema"] == APPEND_TEST_SPEC
    assert "holdout" not in json.dumps(prompts[0])
    assert workflow.tests == fixed_before
    assert "Skipped invalid additional_tests" in workflow.report["warnings"][-1]
    rejected = workflow.root / "rounds/001/additional-tests-rejected.json"
    assert json.loads(rejected.read_text())["tests"] == entries
    assert not (workflow.root / "generated-tests/append-001").exists()
    assert not list(workflow.root.glob(".test-install-*"))
    if entries == [entry()]:
        assert "occupied IDs=" in workflow.report["warnings"][-1]
        assert "omit additional_tests" in workflow.report["warnings"][-1]


@pytest.mark.parametrize("status", ["generated_test_failed", "model_output_invalid", "integrity_failed", "infrastructure_failed"])
def test_valid_optional_batch_runtime_failure_is_not_skipped(flow, monkeypatch, status):
    from repair_tool.storage import snapshot
    workflow, project = flow
    snapshot(project, workflow.baseline)
    round_dir = workflow.root / "rounds/001"
    monkeypatch.setattr(workflow, "build", lambda *args: {})
    def generated(*args):
        raise RepairError(status, "runtime failure")
    monkeypatch.setattr(workflow, "generated_test", generated)
    with pytest.raises(RepairError) as caught:
        workflow.append_tests([entry("new")], round_dir)
    assert caught.value.status == status
    assert workflow.tests == [] and workflow.report["warnings"] == []
    assert (round_dir / "rejected-tests/new/test.json").exists()


@pytest.mark.parametrize("kind", ["adapter", "test"])
def test_runtime_documentation_and_injection_are_complete(tmp_path, kind):
    injected = runtime_env(kind, tmp_path, tmp_path / "poc.c", tmp_path / "helper",
                           work=tmp_path / "work", result=tmp_path / "result.json", args=["a b", "", "\\"])
    assert set(injected) == set(RUNTIME) | set(STAGE_RUNTIME[kind])
    assert all(name in contract_text(kind) for name in injected)
    assert json.loads(injected["REPAIR_POC_ARGS"]) == ["a b", "", "\\"]


@pytest.mark.parametrize("arg", ["{project_dir}", "--input={poc_args}", "{missing}/file"])
def test_unknown_path_placeholder_rejected(tmp_path, arg):
    with pytest.raises(RepairError, match="Unknown command placeholder"):
        expand(["python3", arg], tmp_path, tmp_path / "poc.c")


def test_native_inline_braces_preserved(tmp_path):
    code = 'project = 1; print(f"{project_dir}", {"value": project})'
    assert expand(["python3", "-c", code], tmp_path, tmp_path / "poc.c")[-1] == code
    assert expand(["bash", "-c", "echo {a,b}"], tmp_path, tmp_path / "poc.c")[-1] == "echo {a,b}"


def test_python_preflight_is_atomic_and_literal_hint_is_nonblocking(tmp_path):
    root = tmp_path / "helpers"
    with pytest.raises(RepairError, match=r"bad.py:1"):
        write_model_files(root, [dict(path="ok.py", content="pass"), dict(path="bad.py", content="if :")])
    assert not root.exists()
    write_model_files(root, [dict(path="ok.py", content='project = "x"\nprint(f"{project}")')])
    feedback = failure_feedback("adapter", RepairError("adapter_execution_failed", "failed"), [],
                                {"files": [dict(path="ok.py", content='print(f"{project}")')]})
    assert feedback["hints"] and (root / "ok.py").is_file()


def test_test_batch_install_rolls_back_and_can_retry(flow):
    workflow, _ = flow
    with pytest.raises(RepairError):
        workflow.install_tests({"tests": [entry(), None]}, "batch")
    assert not (workflow.root / "generated-tests/batch").exists()
    assert not list(workflow.root.glob(".test-install-*"))
    assert workflow.install_tests({"tests": [entry()]}, "batch")[0]["id"] == "normal"


def test_holdout_set_contract_and_repair_append_boundary(flow):
    workflow, _ = flow
    tests = [entry(), entry("vuln", "vulnerability", "asan"), entry("holdout", "independent", "pass")]
    with pytest.raises(RepairError, match="separate pass and asan"):
        workflow.install_tests({"tests": tests}, "base", require_base=True)
    assert not (workflow.root / "generated-tests/base").exists()
    tests.append(entry("holdout-crash", "independent", "asan"))
    assert len(workflow.install_tests({"tests": tests}, "base", require_base=True)) == 4
    with pytest.raises(RepairError, match="holdouts are fixed"):
        workflow.install_tests({"tests": [entry("new-holdout", "independent", "pass")]}, "append",
                               allow_independent=False)


@pytest.mark.parametrize("name", ["missing.c", ".repair-poc/driver.c", "added.c"])
def test_only_real_original_source_frames_count(flow, name):
    workflow, project = flow
    if name != "missing.c":
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int test;\n")
    evidence = parse_asan(f"ERROR: AddressSanitizer: heap-buffer-overflow\n #0 0x12 in test {name}:1\n",
                          project, workflow.source_catalog)
    assert "file" not in evidence["frames"][0]


def test_analysis_format_retry_retains_previous_output(flow):
    workflow, project = flow
    prompts = []
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            return {"affected_files": "a.c"} if len(prompts) == 1 else {"affected_files": ["a.c"]}
    workflow.model = Model()
    log = workflow.root / "asan.log"
    log.write_text("evidence")
    workflow.analyze(project, [{"evidence": workflow.evidence, "log": str(log)}])
    feedback = prompts[1]["feedback"]
    assert feedback["previous_attempts"][0]["output"]["affected_files"] == "a.c"
    assert feedback["stage"] == "impact-analysis"


def test_uncertain_contract_is_not_retried(flow):
    workflow, project = flow
    calls = []
    class Model:
        def ask(self, *args):
            calls.append(1)
            return {"contract_uncertain": True, "contracts": [], "affected_files": ["a.c"],
                    "reason": "missing specification"}
    workflow.model = Model()
    log = workflow.root / "asan.log"
    log.write_text("evidence")
    with pytest.raises(RepairError, match="missing specification") as caught:
        workflow.analyze(project, [{"evidence": workflow.evidence, "log": str(log)}])
    assert caught.value.status == "contract_information_required"
    assert len(calls) == 1


def complete_analysis(**changes):
    return {"diagnosis": "Pointer moves beyond the NUL terminator",
            "contracts": ["Do not read or write past NUL", "Secondary string branch has low confidence"],
            "affected_files": ["a.c"], "contract_uncertain": True, "reason": None, **changes}


@pytest.mark.parametrize("changes,expected", [
    ({}, "No nonempty reason"),
    ({"uncertainty_reason": "secondary string branch"}, "secondary string branch"),
    ({"reason": "  ", "contract_uncertainty_reason": "compatibility reason"}, "compatibility reason"),
    ({"reason": " primary ", "uncertainty_reason": "secondary"}, "primary"),
])
def test_usable_uncertain_analysis_continues_and_is_saved(flow, changes, expected):
    workflow, project = flow
    prompts = []
    data = complete_analysis(**changes)
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            return data
    workflow.model = Model()
    log = workflow.root / "asan.log"
    log.write_text("evidence")
    workflow.analyze(project, [{"evidence": workflow.evidence, "log": str(log)}])
    assert len(prompts) == 1
    assert prompts[0]["task"] == ANALYSIS_CONTRACT
    assert expected in workflow.report["warnings"][-1]
    assert workflow.analysis == data
    assert json.loads((workflow.root / "analysis.json").read_text()) == data


@pytest.mark.parametrize("changes,error", [
    ({"contracts": [], "test_plan": ["always present"]}, "Withdraw the flag"),
    ({"contracts": ["", "  ", None]}, "Withdraw the flag"),
    ({"diagnosis": " "}, "Withdraw the flag"),
    ({"affected_files": []}, "Withdraw the flag"),
    ({"contract_uncertain": "false"}, "must be a boolean"),
    ({"contract_uncertain": "true"}, "must be a boolean"),
    ({"contract_uncertain": None}, "must be a boolean"),
    ({"contract_uncertain": 1}, "must be a boolean"),
    ({"affected_files": ["../escape.c"]}, ""),
    ({"affected_files": ["missing.c"], "contracts": [], "reason": "missing contract"}, "Not an editable"),
])
def test_bad_analysis_retries_with_feedback_and_no_warning(flow, changes, error):
    workflow, project = flow
    prompts = []
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            return complete_analysis(**changes) if len(prompts) == 1 else complete_analysis(contract_uncertain=False)
    workflow.model = Model()
    log = workflow.root / "asan.log"
    log.write_text("evidence")
    workflow.analyze(project, [{"evidence": workflow.evidence, "log": str(log)}])
    assert len(prompts) == 2
    assert error in json.dumps(prompts[1]["feedback"])
    assert prompts[1]["feedback"]["category"] in {"model_output_invalid", "invalid_path", "patch_rejected"}
    assert workflow.report["warnings"] == []
    assert workflow.analysis["contract_uncertain"] is False


@pytest.mark.parametrize("data", [{}, {"contract_uncertain": False}])
def test_absent_or_false_uncertainty_preserves_existing_validation(data):
    assert analysis_contract_decision(data) == (None, None)


def test_contract_reason_uses_first_nonempty_string():
    assert analysis_contract_decision({"contract_uncertain": True, "reason": 42,
                                       "uncertainty_reason": " ",
                                       "contract_uncertainty_reason": " missing API behavior "}) == (
        "contract_information_required", "missing API behavior")


def test_unexplained_uncertainty_exhausts_bounded_retries(flow):
    workflow, project = flow
    calls = []
    class Model:
        def ask(self, stage, payload, directory):
            calls.append(payload)
            return complete_analysis(contracts=[])
    workflow.model = Model()
    log = workflow.root / "asan.log"
    log.write_text("evidence")
    with pytest.raises(RepairError) as caught:
        workflow.analyze(project, [{"evidence": workflow.evidence, "log": str(log)}])
    assert caught.value.status == "model_output_invalid"
    assert len(calls) == 3
    assert "Withdraw the flag" in calls[1]["feedback"]["error"]
    assert not (workflow.root / "analysis.json").exists()
    assert workflow.report["warnings"] == []


def test_feedback_has_two_recent_outputs_and_no_added_holdout_content():
    attempts = []
    data = {"command": ["python3", "{adapter}/launch.py"], "files": [dict(path="launch.py", content="pass")],
            "additional_tests": [dict(kind="independent", secret="holdout-details")]}
    for i in range(3):
        feedback = failure_feedback("repair", RepairError("patch_rejected", str(i)), attempts, data)
    assert len(feedback["previous_attempts"]) == 2
    assert "holdout-details" not in json.dumps(feedback)
    assert feedback["previous_attempts"][0]["output"]["files"] == data["files"]


def test_patch_diagnostic_names_hunk_and_difference(tmp_path):
    (tmp_path / "a.c").write_bytes(b"old\n")
    with pytest.raises(RepairError) as caught:
        apply_patch(tmp_path, "--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-wrong\n+new\n", {"a.c"}, 20)
    assert "a.c, hunk 1" in str(caught.value)
    assert "baseline='old\\n' vs patch='wrong\\n'" in str(caught.value)
    assert (tmp_path / "a.c").read_text() == "old\n"


@pytest.mark.parametrize("header", ["@@ -1 +1 @@", "@@ -1,10 +999,1 @@", "@@ -1,0 +0,0 @@"])
def test_hunk_counts_are_derived_from_nonempty_old_body(tmp_path, header):
    (tmp_path / "a.c").write_bytes(b"old\n")
    apply_patch(tmp_path, "--- a/a.c\n+++ b/a.c\n" + header + "\n-old\n+new\n+more\n", {"a.c"}, 20)
    assert (tmp_path / "a.c").read_text() == "new\nmore\n"


def test_context_limits_are_explicit(flow):
    workflow, project = flow
    for requests in [["a.c"] * 21, [dict(file="a.c", start_line=2, end_line=1)]]:
        with pytest.raises(ValueError):
            read_requested(project, requests, 10000, workflow.poc.parent)


def test_pass_json_without_target_is_rejected(flow, monkeypatch):
    workflow, project = flow
    test = workflow.install_tests({"tests": [entry()]}, "base")[0]
    def execute(command, project, log, timeout, extra_env=None, trace=False):
        assert trace
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("no target executed")
        Path(extra_env["REPAIR_TEST_RESULT"]).write_text('{"cases":[{"id":"one","passed":true}]}')
        trace_path = log.with_suffix(".trace")
        trace_path.write_text('100 execve("/usr/bin/python3", ["python3"], []) = 0\n')
        return dict(command=command, passed=True, log=str(log), trace=str(trace_path), returncode=0, reason=None)
    monkeypatch.setattr(workflow, "execute", execute)
    with pytest.raises(RepairError, match="target binding failed"):
        workflow.generated_test(test, project, workflow.root / "logs", False)
    assert not json.loads((workflow.root / "logs/normal.json").read_text())["passed"]


@pytest.mark.parametrize("compiler_reads", [True, False])
def test_compiled_driver_needs_compiler_input_not_launcher_read(flow, monkeypatch, compiler_reads):
    workflow, project = flow
    work = workflow.root / "work"
    work.mkdir()
    compiler = workflow.root / "cc"
    compiler.write_text("compiler")
    launcher = workflow.root / "launcher"
    launcher.write_text("launcher")
    monkeypatch.setattr("repair_tool.execution.shutil.which", lambda name: str(compiler))
    driver = work / "driver"
    driver.write_bytes(elf_bytes())
    source = (project / "a.c").as_posix()
    trace = (f'10 execve("{compiler.as_posix()}", ["cc"], []) = 0\n' +
             (f'10 openat(AT_FDCWD, "{source}", O_RDONLY) = 3<{source}>\n' if compiler_reads else "") +
             f'10 openat(AT_FDCWD, "{driver.as_posix()}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4<{driver.as_posix()}>\n' +
             '10 +++ exited with 0 +++\n' +
             f'20 execve("{launcher.as_posix()}", ["python3"], []) = 0\n' +
             f'20 openat(AT_FDCWD, "{source}", O_RDONLY) = 3<{source}>\n' +
             f'20 execve("{driver.as_posix()}", ["driver"], []) = 0\n')
    trace_path = workflow.root / "trace"
    trace_path.write_text(trace)
    binding = generated_binding(dict(trace=str(trace_path)), project, artifact_inventory(project), work,
                                workflow.source_catalog)
    assert binding["passed"] is compiler_reads


def test_json_diagnostic_has_location_and_sanitized_excerpt(flow, monkeypatch):
    from repair_tool.model import ModelClient
    workflow, _ = flow
    monkeypatch.setenv("REPAIR_API_KEY", "sensitive-key")
    client = ModelClient(workflow.cfg, workflow.root)
    monkeypatch.setattr(client, "receive", lambda *args: {
        "choices": [{"finish_reason": "stop",
                     "message": {"content": '{"x":"sensitive-key\\q"}'}}]})
    with pytest.raises(RepairError) as caught:
        client.ask("repair", {}, workflow.root / "request")
    detail = json.loads(str(caught.value))
    assert detail["line"] == 1 and detail["column"] > 0
    assert "strict JSON" in detail["rule"] and "sensitive-key" not in str(caught.value)


def test_test_generation_retry_resets_project_and_retains_scripts(flow, monkeypatch):
    from repair_tool.storage import snapshot, fresh_project
    workflow, original = flow
    snapshot(original, workflow.baseline)
    project = workflow.root / "scratch/project"
    fresh_project(workflow.baseline, project)
    tests = [entry(), entry("vuln", "vulnerability", "asan"), entry("holdout", "independent", "pass"),
             entry("holdout-crash", "independent", "asan")]
    prompts, builds, executions = [], [], []
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            if len(prompts) == 2:
                assert not (project / "failed-output").exists()
                assert payload["feedback"]["previous_attempts"][-1]["output"]["tests"][0]["files"] == tests[0]["files"]
            return {"tests": tests}
    def build(project, logs):
        builds.append(project)
        return {}
    def generated(test, project, logs, baseline):
        executions.append(test["id"])
        if len(executions) == 1:
            (project / "failed-output").write_text("residue")
            raise RepairError("generated_test_failed", "first attempt")
        return {"passed": True}
    workflow.model = Model()
    monkeypatch.setattr(workflow, "build", build)
    monkeypatch.setattr(workflow, "generated_test", generated)
    workflow.generate_base_tests(project)
    assert len(prompts) == 2 and len(builds) == 1 and len(workflow.tests) == 4


def test_adapter_can_read_adjacent_poc_context(flow, monkeypatch):
    workflow, project = flow
    (workflow.poc.parent / "payload.txt").write_text("documented input")
    prompts = []
    class Model:
        def ask(self, stage, payload, directory):
            prompts.append(payload)
            if len(prompts) == 1:
                return {"read_files": ["inputs/poc/payload.txt"]}
            assert payload["requested_context"]["inputs/poc/payload.txt"]["text"] == "1: documented input"
            return dict(files=[dict(path="launch.py", content="pass")], command=["python3", "{adapter}/launch.py"])
    workflow.model = Model()
    monkeypatch.setattr(workflow, "run_poc", lambda *args: [{"passed": True}])
    workflow.adapt(project, {"kind": "make", "artifacts": {}, "commands": []})
    assert len(prompts) == 2 and "inputs/poc/payload.txt" in workflow.report["source_upload"]


def test_bad_context_request_is_available_in_retry_feedback(flow):
    workflow, project = flow
    class Model:
        def ask(self, *args):
            return {"read_files": "a.c"}
    workflow.model = Model()
    with pytest.raises(RepairError) as caught:
        workflow.ask_with_context("impact-analysis", {}, project, workflow.root / "calls")
    feedback = failure_feedback("impact-analysis", caught.value, [])
    assert feedback["previous_attempts"][0]["output"]["read_files"] == "a.c"
