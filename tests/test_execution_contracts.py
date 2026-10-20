from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from repair_tool.config import DEFAULTS, RepairError
from repair_tool.execution import discover_project_tests, expand
from repair_tool.model import ModelClient
from repair_tool.workflow import Workflow, check_helper_references, write_model_files


@pytest.fixture
def flow(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_text("int a(void) { return 0; }\n")
    cfg = copy.deepcopy(DEFAULTS)
    cfg["project"]["path"] = str(project)
    cfg["poc"]["path"] = str(tmp_path / "original" / "poc.c")
    cfg["output"]["directory"] = str(tmp_path / "results")
    cfg["model"].update(base_url="https://example.test/v1", name="test-model")
    workflow = Workflow(cfg)
    workflow.poc.parent.mkdir(parents=True)
    workflow.poc.write_text("original poc\n")
    workflow.evidence = {"type": "heap-buffer-overflow"}
    return workflow, project


def entry():
    return {"id": "sample", "kind": "regression", "baseline": "pass", "basis": "API contract",
            "expected_cases": 1, "files": [{"path": "run.py", "content": "pass\n"}],
            "command": ["python3", "{suite}/run.py"]}


@pytest.mark.parametrize("argument", ["{poc}/payload", "--input={poc}\\payload", "{suite}/run.py",
                                     "{tests}/run.py", "{adapter}/run.py"])
def test_shared_expansion_rejects_invalid_paths_and_missing_context(tmp_path, argument):
    with pytest.raises(RepairError) as caught:
        expand(["python3", argument], tmp_path, tmp_path / "poc.c")
    assert caught.value.status == "preparation_failed"


def test_expansion_does_not_reinterpret_braces_in_input_paths(tmp_path):
    project = tmp_path / "{poc}"
    poc = tmp_path / "{suite}" / "poc.c"
    assert expand(["python3", "{project}", "{poc}", "{poc_dir}"], project, poc) == [
        "python3", str(project), str(poc), str(poc.parent)]
    # JSON/shell brace syntax in argv is not a controller placeholder.
    assert expand(["python3", "-c", 'print({"value": 1})'], project, poc)[2] == 'print({"value": 1})'


def test_external_test_file_cannot_be_used_as_directory(tmp_path):
    tests = tmp_path / "external.py"
    tests.write_text("pass")
    with pytest.raises(RepairError, match="external test file"):
        expand(["python3", "{tests}/other.py"], tmp_path, tmp_path / "poc.c", tests)


@pytest.mark.parametrize("files", [[None], [{"path": "ok.py"}],
                                  [{"path": "../escape.py", "content": "pass"}],
                                  [{"path": "ok.py", "content": "pass"}, None],
                                  [{"path": "helper", "content": "pass"},
                                   {"path": "helper/run.py", "content": "pass"}]])
def test_malformed_helper_batch_is_rejected_without_partial_writes(tmp_path, files):
    with pytest.raises(RepairError) as caught:
        write_model_files(tmp_path / "helpers", files)
    assert caught.value.status == "model_output_invalid"
    assert not (tmp_path / "helpers").exists()


@pytest.mark.parametrize("bad_entry", [None, "text", ["test"]])
def test_non_object_test_entry_is_model_output_error(flow, bad_entry):
    workflow, _ = flow
    with pytest.raises(RepairError) as caught:
        workflow.install_tests({"tests": [bad_entry]}, "base")
    assert caught.value.status == "model_output_invalid"


@pytest.mark.parametrize("argument", ["{poc}/payload", "--script={suite}/missing.py",
                                     "{suite}\\missing.py", "{adapter}/run.py", "{tests}"])
def test_generated_command_is_rejected_during_installation(flow, argument):
    workflow, _ = flow
    test = entry()
    test["command"] = ["python3", argument]
    with pytest.raises(RepairError) as caught:
        workflow.install_tests({"tests": [test]}, "base")
    assert caught.value.status == "model_output_invalid"
    assert not (workflow.root / "generated-tests/base/sample/test.json").exists()


def test_helper_preflight_allows_output_operands_and_shell_code(tmp_path):
    (tmp_path / "driver.c").write_text("int main(void) { return 0; }\n")
    check_helper_references(["cc", "{suite}/driver.c", "-o", "{suite}/driver"], "{suite}", tmp_path)
    check_helper_references(["cc", "{suite}/driver.c", "-o{suite}/driver"], "{suite}", tmp_path)
    check_helper_references(["bash", "-c", "cc {suite}/driver.c -o {suite}/driver && {suite}/driver"],
                            "{suite}", tmp_path)


@pytest.mark.parametrize("data", [None, [], {"cases": None}, {"cases": {}}, {"cases": [None]},
                                  {"cases": [{"id": [], "passed": True}]},
                                  {"cases": [{"id": "", "passed": True}]},
                                  {"cases": [{"id": "one", "passed": False}]},
                                  {"cases": []},
                                  {"cases": [{"id": "one", "passed": True},
                                             {"id": "one", "passed": True}]}])
def test_invalid_test_result_is_failed_and_persisted_with_log(flow, monkeypatch, data):
    workflow, project = flow
    test = workflow.install_tests({"tests": [entry()]}, "base")[0]
    def execute(command, project, log, timeout, extra_env=None, trace=False):
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("test launcher reported success\n")
        Path(extra_env["REPAIR_TEST_RESULT"]).write_text(json.dumps(data))
        return {"command": command, "passed": True, "log": str(log), "returncode": 0, "reason": None}
    monkeypatch.setattr(workflow, "execute", execute)
    with pytest.raises(RepairError) as caught:
        workflow.generated_test(test, project, workflow.root / "logs", baseline=False)
    assert caught.value.status == "generated_test_failed"
    diagnostic = json.loads(str(caught.value))
    assert diagnostic["log_excerpt"] == "test launcher reported success\n"
    saved = json.loads((workflow.root / "logs/sample.json").read_text())
    assert saved["passed"] is False and saved["reason"] == "Missing/invalid test result contract"


@pytest.mark.parametrize("response", [None, [], {"choices": [None]}, {"choices": ["text"]},
                                      {"choices": [{"message": None}]},
                                      {"choices": [{"message": {"content": None}}]},
                                      {"choices": [{"message": {"content": []}}]}])
def test_malformed_response_has_explicit_error_and_preserved_response(flow, monkeypatch, response):
    workflow, _ = flow
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    client = ModelClient(workflow.cfg, workflow.root)
    monkeypatch.setattr(client, "receive", lambda *args: response)
    directory = workflow.root / "model"
    with pytest.raises(RepairError) as caught:
        client.ask("test", {}, directory)
    assert caught.value.status == ("infrastructure_failed" if not isinstance(response, dict)
                                   else "model_output_invalid")
    assert json.loads((directory / "response.json").read_text()) == response


@pytest.mark.parametrize("chunk", [None, [], {"choices": None}, {"choices": [None]},
                                   {"choices": [{"delta": None}]},
                                   {"choices": [{"delta": {"content": []}}]}])
def test_malformed_stream_chunk_is_provider_failure(flow, monkeypatch, chunk):
    workflow, _ = flow
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    workflow.cfg["model"]["stream"] = True
    client = ModelClient(workflow.cfg, workflow.root)
    class Opener:
        def open(self, *args, **kwargs):
            return io.BytesIO(("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode())
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(RepairError) as caught:
        client.ask("test", {}, workflow.root / "stream")
    assert caught.value.status == "infrastructure_failed"
    assert (workflow.root / "stream/partial-response.json").exists()


@pytest.mark.parametrize("content,passed", [("ctest: runtime loader failed", False), ("[]", True),
                                          ('{"tests":null}', True),
                                          ('{"tests":[{"name":"one","properties":[null]}]}', True)])
def test_ctest_discovery_failure_preserves_diagnostics(flow, content, passed):
    workflow, project = flow
    class Runner:
        def run(self, command, cwd, log, timeout):
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(content)
            return {"passed": passed, "log": str(log), "returncode": 0 if passed else 1}
    with pytest.raises(RepairError) as caught:
        discover_project_tests(project, "cmake", Runner(), workflow.cfg, workflow.poc, workflow.root / "logs")
    assert caught.value.status == "test_information_required"
    assert json.loads(str(caught.value))["log_excerpt"] == content


@pytest.mark.parametrize("content,ctest", [("collected 0 items\n", False),
                                         ("0% tests passed, 1 tests failed out of 1\n", True)])
def test_existing_suite_audit_records_controller_failure(flow, monkeypatch, content, ctest):
    workflow, project = flow
    build = {"project_tests": [{"id": "existing", "command": ["test"], "count": 1, "ctest": ctest}]}
    def execute(command, project, log, timeout):
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(content)
        return {"passed": True, "log": str(log), "returncode": 0, "reason": None}
    monkeypatch.setattr(workflow, "execute", execute)
    with pytest.raises(RepairError) as caught:
        workflow.run_existing(project, build, workflow.root / "logs")
    assert caught.value.status == "functional_failed"
    saved = json.loads((workflow.root / "logs/existing-0.json").read_text())
    assert not saved["passed"] and saved["reason"]
