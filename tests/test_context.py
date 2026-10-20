import copy
import json
import pytest

from repair_tool.config import DEFAULTS, RepairError
from repair_tool.evidence import read_requested
from repair_tool.model import ModelClient
from repair_tool.storage import inventory
from repair_tool.workflow import Workflow


@pytest.fixture
def flow(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_text("int read_at(const char *p) { return p[1]; }\n")
    cfg = copy.deepcopy(DEFAULTS)
    cfg["model"].update({"base_url": "https://example.test/v1", "name": "test-model"})
    cfg["project"]["path"] = str(project)
    cfg["poc"]["path"] = str(tmp_path / "original-poc" / "poc.c")
    cfg["output"]["directory"] = str(tmp_path / "results")
    workflow = Workflow(cfg)
    workflow.poc.parent.mkdir(parents=True)
    workflow.poc.write_text('int main(void) {\n    return read_at("x");\n}\n')
    return workflow, project


def responses(flow, monkeypatch, outputs):
    """Use real response parsing and context orchestration without a provider call."""
    monkeypatch.setenv("REPAIR_API_KEY", "test-secret")
    flow.model = ModelClient(flow.cfg, flow.root)
    prompts = []
    answers = iter(outputs)

    def receive(request, *args):
        prompts.append(json.loads(request.data)["messages"][1]["content"])
        return {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(next(answers))}}]}

    monkeypatch.setattr(flow.model, "receive", receive)
    return prompts


@pytest.mark.parametrize("key", ["read_files", "read_files_needed"])
@pytest.mark.parametrize("still_uncertain", [False, True])
def test_analysis_reads_poc_before_deciding_contract(flow, monkeypatch, key, still_uncertain):
    workflow, project = flow
    before = inventory(workflow.poc.parent)
    final = {"affected_files": ["a.c"], "contract_uncertain": still_uncertain,
             "reason": "The documented contract is still missing" if still_uncertain else None}
    prompts = responses(workflow, monkeypatch, [
        {"needs_build_change": None, "contract_uncertain": True, "reason": "Need to read poc.c",
         key: [{"file": "inputs/poc/poc.c", "start_line": 2, "end_line": 2}]}, final])
    log = workflow.root / "asan.log"
    log.write_text("ASan evidence")
    result = [{"evidence": {"frames": [{"file": "a.c", "line": 1}]}, "log": str(log)}]
    if still_uncertain:
        with pytest.raises(RepairError) as caught:
            workflow.analyze(project, result)
        assert caught.value.status == "contract_information_required"
        assert "still missing" in str(caught.value)
    else:
        workflow.analyze(project, result)
        assert json.loads((workflow.root / "analysis.json").read_text()) == final
    assert len(prompts) == 2
    second = json.loads(prompts[1])
    assert second["poc_file"] == "inputs/poc/poc.c"
    assert second["requested_context"]["inputs/poc/poc.c"]["text"] == '2:     return read_at("x");'
    assert "inputs/poc/poc.c" in workflow.report["source_upload"]
    assert inventory(workflow.poc.parent) == before


@pytest.mark.parametrize("value", [None, []])
def test_empty_optional_context_requests_are_final(flow, monkeypatch, value):
    workflow, project = flow
    final = {"diagnosis": "done", "read_files": value, "read_files_needed": value}
    prompts = responses(workflow, monkeypatch, [final])
    assert workflow.ask_with_context("test", {}, project, workflow.root / "calls") == final
    assert len(prompts) == 1


def test_both_context_keys_are_read_and_accumulated(flow, monkeypatch):
    workflow, project = flow
    prompts = responses(workflow, monkeypatch, [
        {"read_files": ["a.c"], "read_files_needed": ["inputs/poc/poc.c"]},
        {"read_files_needed": [{"file": "a.c", "start_line": 1, "end_line": 1}]},
        {"diagnosis": "done"}])
    assert workflow.ask_with_context("test", {}, project, workflow.root / "calls") == {"diagnosis": "done"}
    for prompt in prompts[1:]:
        assert set(json.loads(prompt)["requested_context"]) == {"a.c", "inputs/poc/poc.c"}


@pytest.mark.parametrize("key", ["read_files", "read_files_needed"])
def test_malformed_context_requests_rejected(flow, monkeypatch, key):
    workflow, project = flow
    responses(workflow, monkeypatch, [{key: "a.c"}])
    with pytest.raises(RepairError) as caught:
        workflow.ask_with_context("test", {}, project, workflow.root / "calls")
    assert caught.value.status == "model_output_invalid"


@pytest.mark.parametrize("key", ["read_files", "read_files_needed"])
def test_context_request_batches_remain_bounded(flow, monkeypatch, key):
    workflow, project = flow
    prompts = responses(workflow, monkeypatch, [{key: ["inputs/poc/poc.c"]}] * 4)
    with pytest.raises(RepairError, match="Maximum additional-context batches"):
        workflow.ask_with_context("test", {}, project, workflow.root / "calls")
    assert len(prompts) == 4


def test_poc_context_shares_budget(flow, monkeypatch):
    workflow, project = flow
    workflow.cfg["repair"]["context_max_bytes"] = 2
    prompts = responses(workflow, monkeypatch, [{"read_files_needed": ["inputs/poc/poc.c"]},
                                              {"contract_uncertain": True}])
    workflow.ask_with_context("test", {}, project, workflow.root / "calls")
    assert "Context budget exceeded" in json.loads(prompts[1])["requested_context"]["inputs/poc/poc.c"]["error"]


@pytest.mark.parametrize("relative", ["inputs/poc/../secret.txt", "inputs/poc/../../report.json",
                                     "inputs/poc/missing.c", "inputs/external-tests/test.c",
                                     "inputs/poc/.git/config"])
def test_poc_context_cannot_escape_snapshot(flow, relative):
    workflow, project = flow
    with pytest.raises((RepairError, ValueError)):
        read_requested(project, [relative], 1000, workflow.poc.parent)


def test_poc_binary_and_malformed_entries_rejected(flow):
    workflow, project = flow
    (workflow.poc.parent / "payload.bin").write_bytes(b"\x00\x01payload")
    for request in ["inputs/poc/payload.bin", {}, {"file": 1}, 1]:
        with pytest.raises(ValueError):
            read_requested(project, [request], 1000, workflow.poc.parent)


def test_poc_python_context_supported(flow):
    workflow, project = flow
    (workflow.poc.parent / "poc.py").write_text("print('trigger')\n")
    assert read_requested(project, ["inputs/poc/poc.py"], 1000, workflow.poc.parent) == {
        "inputs/poc/poc.py": {"text": "1: print('trigger')"}}
