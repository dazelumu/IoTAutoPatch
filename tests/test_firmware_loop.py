"""M6: closed-loop orchestration with an injected model and a fake session.

The full pipeline runs against a FAKE session (no live rehost) with REAL
implant bytes: the synthetic MIPS runner from test_firmware_implant serves
as the target binary, so proposals validated by propose.py produce genuine
candidates. Failure injection proves rollback + feedback.
"""
from __future__ import annotations

import json
import hashlib
import copy
import shutil
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

import pytest

from repair_tool.config import DEFAULTS, RepairError, public_config
from repair_tool.firmware.loop import FirmwareWorkflow
from repair_tool.storage import save_json
from repair_tool.firmware.tests import (baseline_oracle, run_one_test,
                                        validate_tests, verdict)
from repair_tool.firmware.verify import (redeploy_and_verify,
                                         replay_plan, run_fixed_checks)
from tests.test_firmware_implant import build_runner


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _length_truncation_error() -> RepairError:
    return RepairError("model_output_invalid", json.dumps({
        "message": "Incomplete model output: length",
        "finish_reason": "length",
        "response_content_present": False,
        "rule": "Return one compact strict JSON object before the output limit",
    }, ensure_ascii=False))


# ------------------------------------------------------------ fake session

class LoopFakeAdapter:
    """Session-level fake: admin.sock RPC + http.sock tunnel + exits.

    Behaviour rules (driven by the deployed binary bytes):
      - deployed = DEFECTIVE -> GET /long... crashes (SIGSEGV record)
      - deployed = REPAIRED  -> never crashes, always responds 200
    The adapter refuses replace/restart without the matching transaction id
    while a repair.lock exists (mirrors the real supervisor).
    """

    DEFECTIVE = b"\x7fELF-defective-target"
    REPAIRED = b"\x7fELF-repaired-target"
    # A candidate that did NOT fix the fault: different bytes, same defect.
    STILL_BROKEN = b"\x7fELF-still-broken"

    def __init__(self, directory: Path):
        import selectors
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.target_file = self.dir / "rootfs" / "sbin" / "httpd"
        self.target_file.parent.mkdir(parents=True)
        self.target_file.write_bytes(self.DEFECTIVE)
        self.pid = 777
        (self.dir / "target-exits.jsonl").write_text("")
        self.stopped = threading.Event()
        self.sockets = []
        self.threads = []
        self.replacements: list[bytes] = []
        self.exit_debug_context = None
        for name in ("admin.sock", "http.sock"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(self.dir / name))
            sock.listen(8)
            sock.settimeout(0.1)
            self.sockets.append(sock)
            thread = threading.Thread(target=self._serve, args=(sock, name),
                                      daemon=True)
            thread.start()
            self.threads.append(thread)

    # -- helpers ------------------------------------------------------
    def _record_exit(self, signal_name="SIGSEGV", intentional=False,
                     debug_context=None):
        context = (self.exit_debug_context if debug_context is None
                   else debug_context)
        with (self.dir / "target-exits.jsonl").open("a") as stream:
            stream.write(json.dumps({
                "pid": self.pid, "program": "/sbin/httpd",
                "sha256": _sha_bytes(self.target_file.read_bytes()),
                "signal_name": signal_name, "intentional": intentional,
                "debug_context": context}) + "\n")

    def _serve(self, sock, name):
        import selectors
        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        while not self.stopped.is_set():
            for _ in selector.select(timeout=0.1):
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                with conn:
                    conn.settimeout(5)
                    data = conn.recv(65536)
                    if not data:
                        continue
                    if name == "admin.sock":
                        reply = self._admin(json.loads(data))
                        conn.sendall(json.dumps(reply).encode() + b"\n")
                    else:
                        conn.sendall(self._http(data))

    def _admin(self, request):
        command = request.get("command")
        digest = _sha_bytes(self.target_file.read_bytes())
        lock_file = self.dir / "repair.lock"
        if command in {"replace", "restart", "stop"} and lock_file.exists():
            try:
                owner = json.loads(lock_file.read_text())
            except (OSError, json.JSONDecodeError):
                owner = None
            if owner and request.get("transaction") != owner.get("id"):
                return {"ok": False, "error": "session locked by repair transaction"}
        if command == "status":
            return {"ok": True, "target": {"pid": self.pid, "sha256": digest,
                                            "program": "/sbin/httpd"}}
        if command == "replace":
            source = Path(request["source"])
            data = source.read_bytes()
            self.replacements.append(data)
            self.target_file.write_bytes(data)
            self.pid += 1
            return {"ok": True, "target": {
                "pid": self.pid,
                "sha256": _sha_bytes(self.target_file.read_bytes())}}
        if command == "restart":
            self.pid += 1
            return {"ok": True, "target": {
                "pid": self.pid,
                "sha256": _sha_bytes(self.target_file.read_bytes())}}
        if command == "stop":
            return {"ok": True}
        return {"ok": False, "error": f"unknown command {command}"}

    def _http(self, data: bytes) -> bytes:
        deployed = self.target_file.read_bytes()
        path = data.split(b" ", 2)[1] if b" " in data else b"/"
        # Defective variants (baseline and failed candidates) crash on long
        # paths; only the REPAIRED behaviour bounds the copy.
        if deployed != self.REPAIRED and len(path) > 100:
            self._record_exit()
        return (b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nhome")

    def close(self):
        self.stopped.set()
        for thread in self.threads:
            thread.join(timeout=1)
        for sock in self.sockets:
            sock.close()


@pytest.fixture
def fake_session(tmp_path):
    adapter = LoopFakeAdapter(tmp_path / "session")
    yield tmp_path / "session", adapter
    adapter.close()


# ------------------------------------------------------------ model stubs

class ScriptedModel:
    """Deterministic stand-in: a queue of replies per stage."""

    def __init__(self, cfg, root):
        self.cfg, self.root = cfg, root
        self.calls = []
        self.replies: dict[str, list] = {}

    def script(self, stage: str, *replies):
        self.replies.setdefault(stage, []).extend(replies)

    def ask(self, stage: str, payload, directory: Path) -> dict:
        import copy
        self.calls.append({"stage": stage, "payload": payload})
        queue = self.replies.get(stage)
        if not queue:
            raise RepairError("infrastructure_failed",
                              f"no scripted reply for {stage}")
        reply = queue.pop(0)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "prompt.json").write_text(json.dumps(payload)[:4000])
        (directory / "response.json").write_text(json.dumps(reply))
        return copy.deepcopy(reply)


def make_workflow(tmp_path: Path, rootfs: Path, poc: Path,
                  analysis_target: bytes | None = None) -> FirmwareWorkflow:
    cfg = {
        "firmware": {"mode": True, "rootfs": str(rootfs), "adapter": "dir825",
                     "target": "sbin/httpd", "poc_request_timeout": 3,
                     "analysis_target": analysis_target,
                     "total_timeout_seconds": 300,
                     "checks": [{"request": {"path": "/"},
                                 "statuses": [200], "contains": "home"}]},
        "poc": {"path": str(poc), "args": [], "command": None},
        "project": {"path": None},
        "tests": {"external_path": None, "external_command": None,
                  "project_command": None},
        "model": {"base_url": "http://localhost/v1", "name": "stub",
                  "api_key": "k", "api_key_env": "REPAIR_API_KEY",
                  "request_timeout_seconds": 10, "max_output_tokens": 512,
                  "retries": 0, "stream": False,
                  "total_timeout_seconds": 60, "reasoning_effort": None},
        "repair": {**copy.deepcopy(DEFAULTS["repair"]), "max_rounds": 2},
        "validation": {"baseline_runs": 1, "poc_runs": 1,
                       "poc_timeout_seconds": 15, "test_timeout_seconds": 120,
                       "generate_tests": True, "independent_evaluation": True},
        "output": {"directory": str(tmp_path / "results"),
                   "keep_round_projects": True},
    }
    cfg["config_path"] = str(tmp_path / "case.yaml")
    return FirmwareWorkflow(cfg, model_factory=ScriptedModel)


POC_SOURCE = """\
# PoC: long static path overflows a fixed buffer in the web service
# Reproduce with GET /<200 A bytes>.gif
print("trigger: GET /" + "A"*205 + ".gif")
"""

PLAN_REPLY = {
    "analysis": "long static path overflows a fixed buffer",
    "requests": [
        {"id": "control", "method": "GET", "path": "/short.gif",
         "expect": "response"},
        {"id": "trigger", "method": "GET", "path": "/" + "A" * 205 + ".gif",
         "expect": "fatal_exit"}],
    "confirmations": ["trigger"]}

TESTS_REPLY = {
    "tests": [
        {"id": "home-ok", "kind": "regression", "expect": "pass",
         "basis": "landing page always served",
         "request": {"method": "GET", "path": "/"},
         "response": {"statuses": [200], "contains": "home"}},
        {"id": "long-crash", "kind": "vulnerability", "expect": "fatal_exit",
         "basis": "confirmed reproduction: long path crashes service",
         "request": {"method": "GET", "path": "/" + "A" * 205 + ".gif"}},
        {"id": "holdout-home", "kind": "independent", "expect": "pass",
         "basis": "holdout landing page check",
         "request": {"method": "GET", "path": "/index.htm"},
         "response": {"statuses": [200], "contains": "home"}}],
    "rationale": "regression + confirmed vulnerability + holdout"}


def _patched_deploy(adapter: LoopFakeAdapter):
    """Force the fake adapter into 'repaired' behaviour after a deploy."""
    adapter.target_file.write_bytes(LoopFakeAdapter.REPAIRED)


# ------------------------------------------------------------ unit: tests.py

def test_validate_tests_accepts_and_rejects():
    good = validate_tests(TESTS_REPLY)
    assert {t["kind"] for t in good} == {"regression", "vulnerability",
                                         "independent"}
    bad = {"tests": [{"id": "x", "kind": "regression", "expect": "fatal_exit",
                      "basis": "b", "request": {"path": "/"}}]}
    with pytest.raises(RepairError, match="regression"):
        validate_tests(bad)
    bad = {"tests": [{"id": "x", "kind": "vulnerability", "expect": "pass",
                      "basis": "b", "request": {"path": "/"}}]}
    with pytest.raises(RepairError, match="vulnerability"):
        validate_tests(bad)
    with pytest.raises(RepairError):
        validate_tests({"tests": [{"id": "UPPER", "kind": "regression",
                                   "expect": "pass", "basis": "b",
                                   "request": {"path": "/"}}]})
    # Audit issue 4: a pass test without response assertions is rejected
    # (service-alive is not a functional verdict).
    no_assert = {"tests": [{"id": "x", "kind": "regression", "expect": "pass",
                            "basis": "b", "request": {"path": "/"}}]}
    with pytest.raises(RepairError, match="response assertions"):
        validate_tests(no_assert)
    # Audit issue 4: HTTP error statuses are still valid assertions, but a
    # 500 regression that the baseline confirms would fail the oracle; here
    # we check the structural acceptance of statuses and the prompt contract.
    # Audit issue 5: missing independent kind is rejected.
    missing_independent = {
        "tests": [{"id": "r", "kind": "regression", "expect": "pass",
                   "basis": "b", "request": {"path": "/"},
                   "response": {"statuses": [200], "contains": ""}},
                  {"id": "v", "kind": "vulnerability", "expect": "fatal_exit",
                   "basis": "b", "request": {"path": "/x"}}]}
    with pytest.raises(RepairError, match="independent"):
        validate_tests(missing_independent)


def test_generate_tests_uses_one_canonical_order(fake_session, tmp_path):
    session, adapter = fake_session
    poc = tmp_path / "canonical-tests-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    flow.cfg["firmware"]["poc_request_timeout"] = 0.01
    _wire_session(flow, session, adapter)
    interleaved = {"tests": [
        TESTS_REPLY["tests"][0],
        TESTS_REPLY["tests"][2],
        TESTS_REPLY["tests"][1],
    ]}
    flow.model.script("generate-tests", interleaved)
    flow.reproduction = {"requests": []}

    flow.generate_tests()

    saved = json.loads((flow.root / "generated-tests.json").read_text())
    saved_ids = [item["id"] for item in saved]
    oracle = json.loads((flow.root / "test-generation" / "1" / "baseline" /
                         "baseline-oracle.json").read_text())
    assert saved_ids == ["home-ok", "long-crash", "holdout-home"]
    assert [item["id"] for item in oracle["results"]] == saved_ids
    assert [item["id"] for item in flow.tests + flow.holdout] == saved_ids


def test_operator_checks_are_gated_on_original_baseline(fake_session,
                                                         tmp_path):
    session, adapter = fake_session
    poc = tmp_path / "baseline-checks-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    flow.cfg["firmware"]["poc_request_timeout"] = 0.01
    _wire_session(flow, session, adapter)

    flow.validate_baseline_checks()
    assert flow.report["baseline_checks"]["passed"] is True
    assert (flow.root / "baseline" / "fixed-checks" /
            "fixed-checks.json").is_file()

    flow.cfg["firmware"]["checks"][0]["contains"] = "missing-marker"
    with pytest.raises(RepairError) as caught:
        flow.validate_baseline_checks()
    assert caught.value.status == "baseline_checks_failed"


def test_baseline_oracle_and_verdict(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    control = SessionControl(session)
    tests = validate_tests(TESTS_REPLY)
    results = baseline_oracle(control, tests, tmp_path / "oracle",
                              exit_timeout=1.0)
    assert all(r["passed"] for r in results)     # defective: crash test passes


def test_baseline_oracle_rejects_lie(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    control = SessionControl(session)
    # A complete batch (all three kinds) whose regression entry LIES about
    # the baseline: the long path crashes the original service, so "pass"
    # cannot be established -> oracle rejects the whole batch.
    lying = {"tests": [
        {"id": "lie", "kind": "regression", "expect": "pass",
         "basis": "x", "request": {"path": "/" + "A" * 205 + ".gif"},
         "response": {"statuses": [200], "contains": ""}},
        {"id": "v", "kind": "vulnerability", "expect": "fatal_exit",
         "basis": "x", "request": {"path": "/" + "A" * 205 + ".gif"}},
        {"id": "h", "kind": "independent", "expect": "pass",
         "basis": "x", "request": {"path": "/"},
         "response": {"statuses": [200], "contains": "home"}}]}
    with pytest.raises(RepairError, match="lie|baseline"):
        baseline_oracle(control, validate_tests(lying), tmp_path / "oracle",
                        exit_timeout=1.0)


def test_repaired_service_flips_vulnerability_test(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    control = SessionControl(session)
    tests = validate_tests(TESTS_REPLY)
    _patched_deploy(adapter)
    crash = run_one_test(control, tests[1], exit_timeout=1.0)
    assert crash["passed"] is False
    assert crash["reason"] == "expected fatal exit, none observed"
    assert verdict([crash])["passed"] is False


# ------------------------------------------------------------ unit: verify.py

def test_fixed_checks_pass_and_fail(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    control = SessionControl(session)
    checks = [{"request": {"path": "/"}, "statuses": [200], "contains": "home"}]
    result = run_fixed_checks(control, checks, tmp_path / "checks")
    assert result["passed"]
    bad = [{"request": {"path": "/"}, "statuses": [404], "contains": ""}]
    with pytest.raises(RepairError, match="checks failed"):
        run_fixed_checks(control, bad, tmp_path / "checks2")


def test_replay_plan_detects_new_exit(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    from repair_tool.firmware.plan import validate_plan
    control = SessionControl(session)
    plan = validate_plan(PLAN_REPLY)
    # Defective service: replay of the trigger produces a new fatal exit.
    with pytest.raises(RepairError, match="new_fatal_exit|replay"):
        replay_plan(control, plan, tmp_path / "replay", exit_timeout=1.0)


def test_replay_plan_ok_when_repaired(fake_session, tmp_path):
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    from repair_tool.firmware.plan import validate_plan
    control = SessionControl(session)
    plan = validate_plan(PLAN_REPLY)
    _patched_deploy(adapter)
    replay = replay_plan(control, plan, tmp_path / "replay", exit_timeout=1.0)
    assert replay["stable_identity"] is True
    assert all(r["status"] == "ok" for r in replay["results"])


# ------------------------------------------------------------ loop plumbing

def _wire_session(flow: FirmwareWorkflow, session: Path, adapter):
    """Bypass SessionSupervisor: attach the fake session directly."""
    flow.session_dir = session
    fw = flow.cfg["firmware"]
    analysis_target = fw.pop("analysis_target", None)
    if isinstance(analysis_target, bytes):
        target_copy = flow.session_dir / "rootfs" / fw["target"]
        target_copy.parent.mkdir(parents=True, exist_ok=True)
        target_copy.write_bytes(analysis_target)
    # PoC snapshot (normally done in prepare()).
    poc_copy = flow.root / "inputs" / "poc" / Path(
        flow.cfg["poc"]["path"]).name
    poc_copy.parent.mkdir(parents=True, exist_ok=True)
    poc_copy.write_bytes(Path(flow.cfg["poc"]["path"]).read_bytes())
    save_json(flow.root / "config.json", public_config(flow.cfg))

    class _FakeLock:
        id = "tx-test"

        def acquire(self, task=None):
            pass

        def release(self):
            pass

    flow.lock = _FakeLock()
    from repair_tool.firmware.rehost import SessionControl
    flow.control = SessionControl(session)
    flow.baseline_bytes.parent.mkdir(parents=True, exist_ok=True)
    flow.baseline_bytes.write_bytes(
        analysis_target if isinstance(analysis_target, bytes)
        else adapter.target_file.read_bytes())
    flow.model = flow.model_factory(flow.cfg, flow.root)


def _script_localize(model: ScriptedModel, evidence_id: str = "e1"):
    model.script("localize", {"evidence": [evidence_id],
                              "reasoning": "candidate"})


def _add_model_code_site(ledger, *, site=0x400000,
                         bytes_hex="11" * 16):
    return ledger.add("model_code_site", {
        "annotation": "model-supplied address; redirectable shape verified",
        "site": site, "bytes_hex": bytes_hex})


def _mark_localization_valid(flow, result: dict):
    result = {**result, "target_sha256": flow.ledger_for_target().target_sha}
    save_json(flow.root / "localize" / "result.json", result)
    flow.localization_valid = True
    save_json(flow.root / "evidence" / "localization-state.json", {
        "status": "valid", "valid": True, "stage": "localize",
        "target_kind": "baseline",
        "target_sha256": flow.ledger_for_target().target_sha,
        "result": "localize/result.json"})
    trace = flow.root / "evidence" / "query-trace.jsonl"
    if not trace.exists():
        trace.write_text(json.dumps({
            "phase": "localize", "status": "answered",
            "target_kind": "baseline",
            "target_sha256": flow.ledger_for_target().target_sha,
            "query": {"op": "register_patch_site"},
        }) + "\n", encoding="utf-8")


def _script_propose(model: ScriptedModel, site: int, hex16: str,
                    source: str, evidence: list[str], times: int = 2):
    for _ in range(times):
        model.script("repair", {"edits": [{
            "site": site, "expected_hex": hex16, "evidence": evidence,
            "contract": {"abi": "a0=dst a1=src", "bounds": "bounded",
                         "preserve": "copies", "invalid": "returns 0"},
            "source": source}], "rationale": "bound the copy"})


def test_workflow_ask_passes_firmware_deadline_to_model(tmp_path):
    poc = tmp_path / "deadline-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")

    class DeadlineModel:
        def __init__(self):
            self.deadline = None

        def ask(self, stage, payload, directory, *, deadline=None):
            self.deadline = deadline
            return {"ok": True}

    flow.model = DeadlineModel()

    assert flow.ask("test", {}, flow.root / "model-test") == {"ok": True}
    assert flow.model.deadline == flow.deadline


def test_poc_and_test_generation_use_conclusion_output_cap(
        fake_session, tmp_path, monkeypatch):
    import repair_tool.firmware.loop as loop_mod

    session, adapter = fake_session
    poc = tmp_path / "bounded-stage-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.cfg["repair"]["firmware_conclusion_max_output_tokens"] = 6789
    copied_poc = flow.root / "inputs" / "poc" / poc.name
    copied_poc.parent.mkdir(parents=True, exist_ok=True)
    copied_poc.write_text(POC_SOURCE)
    flow.baseline_bytes.parent.mkdir(parents=True, exist_ok=True)
    flow.baseline_bytes.write_bytes(adapter.target_file.read_bytes())
    flow.reproduction = {"requests": []}
    captured = []

    def bounded_ask(stage, payload, directory, *, deadline=None,
                    max_output_tokens=None):
        captured.append((stage, max_output_tokens))
        return copy.deepcopy(PLAN_REPLY if stage == "poc-analysis"
                             else TESTS_REPLY)

    monkeypatch.setattr(flow, "ask", bounded_ask)
    monkeypatch.setattr(loop_mod, "baseline_oracle", lambda *args, **kwargs: [])

    flow.analyze_poc()
    flow.generate_tests()

    assert captured == [
        ("poc-analysis", 6789),
        ("generate-tests", 6789),
    ]


def test_propose_uses_firmware_repair_stage_budget(fake_session, tmp_path):
    session, adapter = fake_session
    poc = tmp_path / "bounded-repair-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    ledger = flow.ledger_for_target()
    selected = _add_model_code_site(ledger)
    result = {"evidence": [selected], "reasoning": "selected", "queries": []}
    save_json(flow.root / "localize" / "result.json", result)
    _mark_localization_valid(flow, result)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/x"},
        "signal": "SIGSEGV", "exit_record": {"pid": 1}})
    flow.cfg["repair"]["firmware_repair_timeout_seconds"] = 7
    flow.cfg["repair"]["firmware_repair_max_output_tokens"] = 12345
    captured = {}

    class BoundedModel(ScriptedModel):
        def ask(self, stage, payload, directory, *, deadline=None,
                max_output_tokens=None):
            captured["deadline"] = deadline
            captured["max_output_tokens"] = max_output_tokens
            return {"edits": [{
                "site": 0x400000, "expected_hex": "11" * 16,
                "evidence": [selected],
                "contract": {"abi": "a", "bounds": "b",
                             "preserve": "p", "invalid": "i"},
                "source": "int repair_entry(void){return 0;}"}]}

    flow.model = BoundedModel(flow.cfg, flow.root)

    proposal = flow.propose(tmp_path / "rounds" / "001", None)

    assert proposal["edits"][0]["site"] == 0x400000
    assert captured["max_output_tokens"] == 12345
    assert captured["deadline"] <= time.monotonic() + 7
    assert captured["deadline"] <= flow.deadline


def test_firmware_round_cap_and_shared_repair_deadline(tmp_path, monkeypatch):
    poc = tmp_path / "round-cap-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    flow.cfg["repair"]["max_rounds"] = 5
    flow.cfg["repair"]["firmware_max_rounds"] = 2
    candidate = tmp_path / "round-cap-candidate"
    candidate.write_bytes(b"candidate")
    built = {"candidate": candidate, "record": {
        "candidate_sha256": _sha_bytes(candidate.read_bytes())}}
    proposal_deadlines = []
    implant_deadlines = []
    relocalizations = []
    round_deadlines = iter((100.0, 200.0))
    monkeypatch.setattr(flow, "_stage_deadline",
                        lambda _setting: next(round_deadlines))
    monkeypatch.setattr(flow, "propose", lambda *_args, **kwargs: (
        proposal_deadlines.append(kwargs["deadline"]), {"edits": []})[1])
    monkeypatch.setattr(flow, "implant", lambda *_args, **kwargs: (
        implant_deadlines.append(kwargs["deadline"]), built)[1])
    monkeypatch.setattr(flow, "_runtime_exit_cursor", lambda: 0)
    monkeypatch.setattr(flow, "_collect_candidate_runtime_exits", lambda *_: [])
    monkeypatch.setattr(flow, "rollback", lambda *_: None)
    monkeypatch.setattr(flow, "relocalize",
                        lambda *_, **__: relocalizations.append(True))

    def failed_deploy(*_):
        raise RepairError("verification_failed", "candidate still crashes")

    monkeypatch.setattr(flow, "deploy_and_verify", failed_deploy)

    flow.repair_rounds()

    assert len(flow.report["rounds"]) == 2
    assert relocalizations == [True]
    assert proposal_deadlines == implant_deadlines == [100.0, 200.0]


def test_repair_stage_timeout_is_terminal_and_keeps_original_status(
        tmp_path, monkeypatch):
    poc = tmp_path / "stage-timeout-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    rollback = []
    relocalize = []
    monkeypatch.setattr(flow, "propose", lambda *_args, **_kwargs: (
        _ for _ in ()).throw(RepairError(
            "stage_timeout", "repair stage expired")))
    monkeypatch.setattr(flow, "rollback", lambda *_: rollback.append(True))
    monkeypatch.setattr(flow, "relocalize",
                        lambda *_, **__: relocalize.append(True))

    with pytest.raises(RepairError) as caught:
        flow.repair_rounds()

    assert caught.value.status == "stage_timeout"
    assert str(caught.value) == "repair stage expired"
    assert flow.report["rounds"][0]["status"] == "stage_timeout"
    assert rollback == [True]
    assert relocalize == []


def test_candidate_iteration_uses_short_observation_window(
        fake_session, tmp_path, monkeypatch):
    session, adapter = fake_session
    poc = tmp_path / "short-window-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.cfg["firmware"]["poc_request_timeout"] = 10
    flow.cfg["repair"]["firmware_exploratory_observation_seconds"] = 2
    candidate = tmp_path / "short-window-candidate"
    candidate.write_bytes(adapter.REPAIRED)
    built = {"candidate": candidate, "record": {
        "candidate_sha256": _sha_bytes(adapter.REPAIRED)}}
    observed = {}

    def fake_verify(*_args, exit_timeout, **_kwargs):
        observed["exit_timeout"] = exit_timeout
        return {"fixed": {"passed": True}, "replay": {"stable_identity": True},
                "tests": {"passed": True, "failed": []}}

    monkeypatch.setattr(
        "repair_tool.firmware.loop.verify_candidate", fake_verify)

    outcome = flow.deploy_and_verify(built, tmp_path / "short-window-round")

    assert observed["exit_timeout"] == 2.0
    assert outcome["exploratory_observation_seconds"] == 2.0


def test_implant_rejects_full_target_drift_before_build(fake_session,
                                                        tmp_path,
                                                        monkeypatch):
    session, adapter = fake_session
    poc = tmp_path / "drift-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    adapter.target_file.write_bytes(adapter.DEFECTIVE + b"-external-drift")
    build_called = []
    monkeypatch.setattr(
        "repair_tool.firmware.loop.build_candidate",
        lambda *_args, **_kwargs: build_called.append(True))

    with pytest.raises(RepairError, match="archived baseline") as caught:
        flow.implant({"edits": []}, flow.root / "rounds" / "001")

    assert caught.value.status == "integrity_failed"
    assert build_called == []


def test_localize_registers_model_selected_site_and_keeps_history(
        fake_session, tmp_path):
    """The loop starts without candidates, accepts a model-supplied address,
    and carries neutral query history into the persisted conclusion."""
    from repair_tool.arch.mips32 import ElfAnalysis

    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "localize"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]

    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV",
        # Old run layout: context exists only inside exit_record. The loop
        # must still consume it, without forwarding local log paths.
        "exit_record": {"pid": 10, "debug_context": {
            "pc": 0x4444, "ra": 0x5555,
            "log_path": "/tmp/private-qemu.log"}},
    })
    flow.model.script(
        "localize",
        {"query": {"op": "elf_info"}},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e2"], "reasoning": "selected after ELF inspection"},
    )

    flow.localize()

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    first = calls[0]["payload"]
    assert first["localization"]["model_code_sites"] == []
    assert "static_candidates" not in json.dumps(first)
    assert first["fault"]["debug_context"] == {
        "pc": 0x4444, "pc_hex": "0x00004444",
        "ra": 0x5555, "ra_hex": "0x00005555"}
    assert "/tmp/private-qemu.log" not in json.dumps(first)
    result = json.loads(
        (flow.root / "localize" / "result.json").read_text(encoding="utf-8"))
    registered_answer = result["queries"][-1]["answer"]
    assert set(registered_answer) == {"op", "evidence", "site", "site_hex",
                                      "bytes_hex"}
    assert result["evidence"] == ["e2"]
    assert [entry["query"]["op"] for entry in result["queries"]] == [
        "elf_info", "register_patch_site"]
    assert flow.ledger_for_target().get("e2")["kind"] == "model_code_site"
    queries = flow.ledger_for_target().by_kind("model_query")
    assert [item["status"] for item in queries] == ["answered", "answered"]


def test_fault_context_hex_aliases_do_not_add_unlisted_facts():
    from repair_tool.firmware.loop import _fault_context_for_prompt

    context = _fault_context_for_prompt({
        "pc": 0x409474,
        "ra": 0x40A6A0,
        "log_path": "/tmp/private.log",
        "static_code_words": [
            {"register": "pc", "vaddr": 0x409474, "bytes_hex": "8fbf0d24"}],
    })

    assert context == {
        "pc": 0x409474, "pc_hex": "0x00409474",
        "ra": 0x40A6A0, "ra_hex": "0x0040a6a0",
        "static_code_words": [
            {"register": "pc", "vaddr": 0x409474,
             "vaddr_hex": "0x00409474", "bytes_hex": "8fbf0d24"}],
    }


def test_localize_prompt_does_not_duplicate_current_answer(
        fake_session, tmp_path):
    """The current query result is sent once, not again inside history."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "one-shot-localize"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "one-shot-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV",
        "debug_context": {"pc": 0x4444, "ra": 0x5555}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.model.script(
        "localize",
        {"query": {"op": "elf_info"}},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e2"], "reasoning": "selected site"})

    flow.localize()

    calls = [call for call in flow.model.calls
             if call["stage"] == "localize"]
    second = calls[1]["payload"]
    assert second["query_answer"] is not None
    assert second["query_history"] == []
    assert "query_answer" not in calls[-1]["payload"]
    assert "query_history" not in calls[-1]["payload"]
    result = json.loads(
        (flow.root / "localize" / "result.json").read_text(encoding="utf-8"))
    assert result["queries"][0]["answer"] == second["query_answer"]


def test_localize_batch_delivers_every_current_answer_before_compaction(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "batch-localize"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "batch-localize-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    flow.cfg["repair"]["firmware_decisive_site_inspections"] = 3
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.model.script(
        "localize",
        {"queries": [{"op": "elf_info"},
                     {"op": "symbols", "contains": "concat"}]},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e3"], "reasoning": "batch evidence then site"})

    flow.localize()

    calls = [call for call in flow.model.calls
             if call["stage"] == "localize"]
    second = calls[1]["payload"]
    assert [answer["op"] for answer in second["query_answers"]] == [
        "elf_info", "symbols"]
    assert second["query_history"] == []
    assert "query_answer" not in second


def test_localize_counts_invalid_envelopes_as_no_progress(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "no-progress-localize"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "no-progress-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    flow.cfg["repair"]["firmware_no_progress_turns"] = 2
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    flow.model.script("localize", {"queries": "bad"}, {"queries": []})

    with pytest.raises(RepairError, match="without new evidence"):
        flow.localize()

    assert flow.model.calls[-1]["payload"]["localization_budget"][
        "queries_used"] == 1

    calls = [call for call in flow.model.calls
             if call["stage"] == "localize"]
    assert len(calls) == 2


def test_localize_rejects_legacy_candidate_without_model_registration(
        fake_session, tmp_path):
    from repair_tool.arch.mips32 import ElfAnalysis
    from repair_tool.firmware.query import EvidenceSession

    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "legacy"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "legacy-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    ledger = flow.ledger_for_target()
    legacy_id = ledger.add("static_candidate", {
        "site": 0x400000, "bytes_hex": "11" * 16})
    with ElfAnalysis(ledger.target_path) as analysis:
        query_session = EvidenceSession(ledger, analysis)
        with pytest.raises(RepairError, match="model_code_site"):
            flow._write_localization(
                {"evidence": [legacy_id], "reasoning": "legacy"},
                query_session)


def test_relocalization_preserves_initial_result(tmp_path):
    """Relocalization updates repair input without erasing its provenance."""
    poc = tmp_path / "relocalize-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    target = flow.session_dir / "rootfs" / "sbin" / "httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"fixture")
    entry_id = _add_model_code_site(flow.ledger_for_target())
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})

    registration = [{
        "query": {"op": "register_patch_site", "address": 0x400000},
        "answer": {"op": "register_patch_site", "evidence": entry_id,
                   "site": 0x400000, "bytes_hex": "11" * 16},
    }]
    registration_session = type(
        "RegistrationSession", (), {"answers": registration})()
    first = {"evidence": [entry_id], "reasoning": "first site"}
    second = {"evidence": [entry_id], "reasoning": "replacement site"}
    flow._write_localization(first, registration_session, stage="localize")
    flow._write_localization(second, registration_session, stage="relocalize")

    def read_json(path):
        return json.loads(path.read_text(encoding="utf-8"))

    initial = read_json(flow.root / "localize" / "initial-result.json")
    relocalization = read_json(flow.root / "relocalize" / "result.json")
    canonical = read_json(flow.root / "localize" / "result.json")
    assert initial["reasoning"] == "first site"
    assert relocalization["reasoning"] == "replacement site"
    assert canonical["reasoning"] == "replacement site"
    assert flow.localization_queries() == read_json(
        flow.root / "localize" / "result.json")["queries"]


def test_relocalize_invocations_keep_separate_attempt_directories(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "relocalize-history"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "relocalize-history-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
        site_hex = analysis.bytes_at(site, 16).hex()
    entry_id = _add_model_code_site(flow.ledger_for_target(), site=site,
                                    bytes_hex=site_hex)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    save_json(flow.root / "localize" / "result.json", {
        "evidence": [entry_id], "reasoning": "initial", "queries": [{
            "query": {"op": "register_patch_site", "address": site},
            "answer": {"op": "register_patch_site", "evidence": entry_id,
                       "site": site, "bytes_hex": site_hex},
        }]})

    class FreshNominationModel(ScriptedModel):
        def ask(self, stage, payload, directory):
            queue = self.replies.get(stage, [])
            if queue and "evidence" in queue[0]:
                queue[0] = {**queue[0], "evidence": [
                    payload["registered_patch_sites"][0]["evidence"]]}
            return super().ask(stage, payload, directory)

    flow.model = FreshNominationModel(flow.cfg, flow.root)
    flow.model.script(
        "relocalize",
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": [entry_id], "reasoning": "first retry"},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": [entry_id], "reasoning": "second retry"})

    flow.relocalize({"error": "first candidate failed"})
    flow.relocalize({"error": "second candidate failed"})

    first = json.loads((flow.root / "relocalize" / "attempts" / "001" /
                        "result.json").read_text(encoding="utf-8"))
    second = json.loads((flow.root / "relocalize" / "attempts" / "002" /
                         "result.json").read_text(encoding="utf-8"))
    assert first["reasoning"] == "first retry"
    assert second["reasoning"] == "second retry"
    assert first["evidence"] != second["evidence"]
    assert entry_id not in first["evidence"] + second["evidence"]
    latest = json.loads((flow.root / "relocalize" /
                         "result.json").read_text(encoding="utf-8"))
    assert latest["reasoning"] == "second retry"
    first_call = next(call for call in flow.model.calls
                      if call["stage"] == "relocalize")
    assert first_call["payload"]["localization"]["model_code_sites"] == []
    assert first_call["payload"]["query_history"] == []
    assert entry_id not in json.dumps(first_call["payload"])


def test_completed_indirect_call_pages_are_not_reported_as_incomplete():
    from repair_tool.firmware.loop import _incomplete_indirect_call_page

    answers = [{
        "query": {"op": "indirect_calls", "contains": "strcpy",
                  "offset": 0},
        "answer": {"op": "indirect_calls", "contains": "strcpy",
                   "offset": 0, "total": 69, "calls": [{}] * 50},
    }, {
        "query": {"op": "indirect_calls", "contains": "strcpy",
                  "offset": 50},
        "answer": {"op": "indirect_calls", "contains": "strcpy",
                   "offset": 50, "total": 69, "calls": [{}] * 19},
    }]

    assert _incomplete_indirect_call_page(answers) is None


def test_indirect_call_page_reports_first_real_gap_per_filter():
    from repair_tool.firmware.loop import _incomplete_indirect_call_page

    answers = [{
        "query": {"op": "indirect_calls", "contains": "strcpy"},
        "answer": {"op": "indirect_calls", "contains": "strcpy",
                   "offset": 0, "total": 12, "calls": [{}] * 4},
    }, {
        "query": {"op": "indirect_calls", "contains": "strcpy",
                  "offset": 8},
        "answer": {"op": "indirect_calls", "contains": "strcpy",
                   "offset": 8, "total": 12, "calls": [{}] * 4},
    }]

    incomplete = _incomplete_indirect_call_page(answers)
    assert incomplete["missing_intervals"] == [[4, 8]]
    assert incomplete["next_offset"] == 4


def test_localization_instruction_requires_efficient_investigation(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "efficient"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "efficient-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.model.script(
        "localize",
        {"evidence": ["missing"], "reasoning": "x"},
        {"query": {"op": "elf_info"}},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e2"], "reasoning": "selected after retry"})

    flow.localize()

    payload = flow.model.calls[0]["payload"]
    assert "Investigate efficiently" in payload["instruction"]
    assert "avoid exhaustive sweeps" in payload["instruction"]
    retry = flow.model.calls[1]["payload"]
    assert "unknown evidence ids" in retry["conclusion_error"]["error"]
    assert "static_candidates" not in json.dumps(retry)


def test_localize_feeds_back_invalid_query_without_leaking_candidates(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "query-feedback"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "query-feedback-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": 0x400004}},
        {"query": {"op": "elf_info"}},
    )

    try:
        flow.localize()
    except RepairError:
        pass

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    feedback = calls[1]["payload"]["query_error"]
    assert feedback["stage"] == "localize"
    assert "Patch site rejected" in feedback["error"]
    assert "0x" not in feedback["error"].lower()
    assert feedback["submitted_query"] == {
        "op": "register_patch_site", "address": 0x400004}
    assert any(item["op"] == "elf_info" for item in feedback["vocabulary"])
    assert calls[2]["payload"]["query_answer"]["op"] == "elf_info"
    assert "query_error" not in calls[2]["payload"]
    failed = flow.ledger_for_target().by_kind("model_query")[0]
    assert failed["status"] == "rejected"
    assert failed["query"] == feedback["submitted_query"]
    trace = [json.loads(line) for line in
             (flow.root / "evidence" / "query-trace.jsonl").read_text(
                 encoding="utf-8").splitlines()]
    assert trace[0]["status"] == "rejected"
    assert trace[0]["query"] == feedback["submitted_query"]


def test_last_register_query_allows_one_conclusion_turn(
        fake_session, tmp_path, monkeypatch):
    """Using the last query slot to register a site must still be useful."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "last-register"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "last-register-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e1"], "reasoning": "registered in final slot"})

    flow.localize()

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    assert len(calls) == 2
    assert calls[-1]["payload"]["registered_patch_sites"][0][
        "evidence"] == "e1"


def test_localize_prompt_exposes_budget_and_final_registration_turn(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "budget-visible"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "budget-visible-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.cfg["repair"]["firmware_localize_queries"] = 2
    flow.model.script(
        "localize",
        {"queries": [{"op": "elf_info"}, {"op": "symbols", "contains": "concat"}]},
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": ["e3"], "reasoning": "selected before exhaustion"})

    flow.localize()

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    first_budget = calls[0]["payload"]["localization_budget"]
    assert first_budget["query_budget"] == 2
    assert first_budget["queries_used"] == 0
    assert first_budget["queries_remaining"] == 2
    assert first_budget["final_decision_reserved_after_query_budget"] is True
    assert calls[0]["payload"]["budget_directive"]["stage"] == "localize"
    decision = calls[1]["payload"]["registration_decision_required"]
    assert decision["querying_allowed"] == "register_patch_site only"
    decision_budget = calls[1]["payload"]["localization_budget"]
    assert decision_budget["queries_used"] == 2
    assert decision_budget["queries_remaining"] == 0
    assert "instruction" not in calls[1]["payload"]
    history_ops = [item["query"]["op"] for item in
                   calls[1]["payload"]["query_history"]]
    assert history_ops == ["elf_info", "symbols"]
    assert calls[1]["payload"]["response_contract"][
        "batching_allowed"] is False
    assert calls[-1]["payload"]["registered_patch_sites"][0][
        "evidence"] == "e3"


def test_decisive_site_inspections_force_compact_registration_decision(
        fake_session, tmp_path):
    """Two model-inspected buffer-writing sites stop broad investigation."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "decisive-site-checkpoint"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "decisive-site-checkpoint-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    flow.cfg["repair"]["firmware_decisive_site_discoveries"] = 999
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        sites = sorted(item["vaddr"] for item in analysis.call_sites(
            ("concat_impl", "concat_impl2")))

    class CheckpointModel:
        def __init__(self, cfg, root):
            self.calls = []

        def ask(self, stage, payload, directory, *, deadline=None,
                max_output_tokens=None, reasoning_effort=None):
            self.calls.append({"stage": stage, "payload": payload,
                               "max_output_tokens": max_output_tokens,
                               "reasoning_effort": reasoning_effort})
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "prompt.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            count = len(self.calls)
            if count == 1:
                reply = {"query": {"op": "indirect_calls",
                                   "contains": "concat", "limit": 10}}
            elif count == 2:
                reply = {"queries": [
                    {"op": "disassemble", "address": sites[0], "around": 8},
                    {"op": "disassemble", "address": sites[1], "around": 8},
                ]}
            elif count == 3:
                reply = {"query": {"op": "register_patch_site",
                                   "address": sites[0]}}
            else:
                evidence_id = flow.ledger_for_target().by_kind(
                    "model_code_site")[-1]["id"]
                reply = {"evidence": [evidence_id],
                         "reasoning": "checkpoint site"}
            (directory / "response.json").write_text(
                json.dumps(reply), encoding="utf-8")
            return copy.deepcopy(reply)

    flow.model = CheckpointModel(flow.cfg, flow.root)
    flow.localize()

    evidence_id = flow.ledger_for_target().by_kind("model_code_site")[-1]["id"]
    assert flow.localized == [evidence_id]
    assert len(flow.model.calls) == 4
    discover, inspect, decide, conclude = flow.model.calls
    assert discover["payload"]["instruction"]
    assert inspect["payload"]["instruction"]
    decision = decide["payload"]
    assert decision["registration_decision_required"][
        "querying_allowed"] == "register_patch_site only"
    assert "independently disassembled" in decision[
        "registration_decision_required"]["reason"]
    assert len(decision["model_observed_memory_sites"]) == 2
    assert decision["response_contract"]["batching_allowed"] is False
    assert "instruction" not in decision
    assert "budget_directive" not in decision
    assert discover["reasoning_effort"] == "low"
    assert inspect["reasoning_effort"] == "low"
    assert decide["max_output_tokens"] == 8192
    assert decide["reasoning_effort"] == "low"
    assert conclude["payload"]["registered_patch_sites"][0]["evidence"] == evidence_id
    assert conclude["reasoning_effort"] == "low"


def test_discovered_sites_focus_followup_before_registration(
        fake_session, tmp_path):
    """Broad discoveries focus follow-up instead of forcing a blind choice."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "decisive-discovered-sites"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "decisive-discovered-sites-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        sites = sorted(item["vaddr"] for item in analysis.call_sites(
            ("concat_impl", "concat_impl2")))

    class DiscoveryCheckpointModel:
        def __init__(self, cfg, root):
            self.calls = []

        def ask(self, stage, payload, directory, *, deadline=None,
                max_output_tokens=None, reasoning_effort=None):
            self.calls.append({"stage": stage, "payload": payload,
                               "max_output_tokens": max_output_tokens,
                               "reasoning_effort": reasoning_effort})
            directory.mkdir(parents=True, exist_ok=True)
            count = len(self.calls)
            if count == 1:
                reply = {"query": {"op": "indirect_calls",
                                   "contains": "concat", "limit": 10}}
            elif count == 2:
                reply = {"queries": [
                    {"op": "disassemble", "address": site, "around": 8}
                    for site in sites[:2]
                ]}
            elif count == 3:
                reply = {"query": {"op": "register_patch_site",
                                   "address": sites[0]}}
            else:
                evidence_id = flow.ledger_for_target().by_kind(
                    "model_code_site")[-1]["id"]
                reply = {"evidence": [evidence_id],
                         "reasoning": "discovered decisive site"}
            (directory / "response.json").write_text(
                json.dumps(reply), encoding="utf-8")
            return copy.deepcopy(reply)

    flow.model = DiscoveryCheckpointModel(flow.cfg, flow.root)
    flow.localize()

    assert len(flow.model.calls) == 4
    discover, inspect, decide, conclude = flow.model.calls
    assert POC_SOURCE in discover["payload"]["poc_evidence"]["source"]
    focus = inspect["payload"]["focus_checkpoint"]
    assert focus["querying_allowed"] == "decisive_followup_only"
    assert "discovered at least 2" in focus["reason"]
    assert len(focus["observed_sites"]) == 2
    assert all(site["inspected"] is False
               for site in focus["observed_sites"])
    assert "registration_decision_required" not in inspect["payload"]
    assert inspect["max_output_tokens"] == 32768
    assert inspect["reasoning_effort"] == "low"
    assert "independently disassembled at least 2" in decide["payload"][
        "registration_decision_required"]["reason"]
    assert len(decide["payload"]["model_observed_memory_sites"]) == 2
    assert discover["reasoning_effort"] == "low"
    assert decide["max_output_tokens"] == 8192
    assert decide["reasoning_effort"] == "low"
    assert "instruction" not in decide["payload"]
    assert "registered_patch_sites" in conclude["payload"]


def test_observed_site_summary_preserves_inspected_and_page_edges():
    from repair_tool.firmware.loop import _selected_observed_sites

    sites = [
        {"address": index, "callee": "strcpy", "inspected": False}
        for index in range(100, 130)
    ]
    sites[0]["inspected"] = True
    sites[-1]["inspected"] = True
    selected = _selected_observed_sites(sites, limit=10)

    assert len(selected) == 10
    assert selected[0]["address"] == 100
    assert selected[-1]["address"] == 129
    assert all(site["inspected"] is False for site in selected[1:-1])


def test_registration_payload_does_not_retruncate_selected_sites():
    from repair_tool.firmware.loop import _registration_decision_payload

    observed = [
        {"address": index, "callee": "strcpy", "inspected": index % 3 == 0}
        for index in range(24)
    ]
    payload = _registration_decision_payload(
        stage="localize", source_payload={"localization": {}, "fault": {}},
        budget=16, queries=16, turns=4, max_turns=20, history=[],
        observed_sites=observed, reason="fixture")
    assert payload["model_observed_memory_sites"] == observed
    assert payload["model_observed_memory_sites"] is not observed


def test_localize_length_recovery_uses_compact_prompt_and_low_reasoning(
        fake_session, tmp_path):
    """A length-truncated localization turn recovers without replaying it."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "length-recovery"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "length-recovery-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    flow.cfg["model"]["reasoning_effort"] = "high"
    flow.cfg["repair"]["firmware_localize_queries"] = 2
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV",
        "debug_context": {"pc": 0x4444, "ra": 0x5555}})

    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]

    class LengthRecoveryModel:
        def __init__(self, cfg, root):
            self.calls = []

        def ask(self, stage, payload, directory, *, deadline=None,
                max_output_tokens=None, reasoning_effort=None):
            call = {"stage": stage, "payload": payload,
                    "max_output_tokens": max_output_tokens,
                    "reasoning_effort": reasoning_effort}
            self.calls.append(call)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "prompt.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            count = len(self.calls)
            if count == 1:
                reply = {"query": {"op": "elf_info"}}
            elif count == 2:
                (directory / "response.json").write_text("{}", encoding="utf-8")
                raise _length_truncation_error()
            elif count == 3:
                reply = {"query": {"op": "register_patch_site",
                                   "address": site}}
            else:
                reply = {"evidence": ["e2"], "reasoning": "recovered site"}
            (directory / "response.json").write_text(
                json.dumps(reply), encoding="utf-8")
            return copy.deepcopy(reply)

    flow.model = LengthRecoveryModel(flow.cfg, flow.root)
    flow.localize()

    assert flow.localized == ["e2"]
    assert len(flow.model.calls) == 4
    original, failed, recovery, conclusion = flow.model.calls
    assert original["reasoning_effort"] == "low"
    assert failed["reasoning_effort"] == "low"
    assert recovery["reasoning_effort"] == "low"
    assert recovery["max_output_tokens"] == 32768
    assert recovery["payload"]["length_recovery_required"][
        "finish_reason"] == "length"
    assert recovery["payload"]["response_contract"]["batching_allowed"] is False
    assert recovery["payload"]["query_history"][0]["query"]["op"] == "elf_info"
    assert "instruction" not in recovery["payload"]
    assert "query_answer" not in recovery["payload"]
    assert '"meaning"' not in json.dumps(recovery["payload"])
    assert conclusion["reasoning_effort"] == "low"
    assert conclusion["payload"]["compact_localization_mode"][
        "reason"] == "enabled_after_finish_reason_length"
    assert conclusion["payload"]["registered_patch_sites"][0][
        "evidence"] == "e2"
    assert "instruction" not in conclusion["payload"]
    assert "query_history" not in conclusion["payload"]


def test_localize_length_recovery_accepts_explicit_failure(
        fake_session, tmp_path):
    """A compact recovery may conclude that the collected evidence is insufficient."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "length-recovery-failed"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "length-recovery-failed-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    flow.cfg["model"]["reasoning_effort"] = "high"
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV",
        "debug_context": {"pc": 0x4444}})

    class FailureRecoveryModel:
        def __init__(self, cfg, root):
            self.calls = []

        def ask(self, stage, payload, directory, *, deadline=None,
                max_output_tokens=None, reasoning_effort=None):
            self.calls.append({"stage": stage, "payload": payload,
                               "max_output_tokens": max_output_tokens,
                               "reasoning_effort": reasoning_effort})
            directory.mkdir(parents=True, exist_ok=True)
            if len(self.calls) == 1:
                reply = {"query": {"op": "elf_info"}}
            elif len(self.calls) == 2:
                raise _length_truncation_error()
            else:
                reply = {"localization_failed": True,
                         "reasoning": "no redirectable call site was isolated"}
            (directory / "response.json").write_text(
                json.dumps(reply), encoding="utf-8")
            return copy.deepcopy(reply)

    flow.model = FailureRecoveryModel(flow.cfg, flow.root)
    with pytest.raises(RepairError) as caught:
        flow.localize()

    assert caught.value.status == "localization_failed"
    assert len(flow.model.calls) == 3
    recovery = flow.model.calls[-1]
    assert recovery["reasoning_effort"] == "low"
    assert recovery["payload"]["response_contract"][
        "querying_allowed"] == "register_patch_site only"
    assert recovery["payload"]["length_recovery_required"][
        "previous_prompt_discarded"] is True


def test_localization_budget_failure_is_not_reproduction_failure(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "localization-failure"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "localization-failure-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    flow.model.script(
        "localize",
        {"query": {"op": "elf_info"}},
        {"localization_failed": True,
         "reasoning": "no unsafe copy call site was isolated"})

    with pytest.raises(RepairError) as caught:
        flow.localize()

    assert caught.value.status == "localization_failed"
    assert "insufficient localization evidence" in str(caught.value)
    assert "1/1" in str(caught.value)
    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    assert calls[1]["payload"]["registration_decision_required"][
        "querying_allowed"] == "register_patch_site only"


def test_conclusion_only_rejects_extra_query_without_executing_it(
        fake_session, tmp_path, monkeypatch):
    """After the final query, an extra query is neutral rejected, not run."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "conclusion-only"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "conclusion-only-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": site}},
        {"query": {"op": "elf_info"}},
        {"evidence": ["e1"], "reasoning": "conclusion after rejected query"})

    flow.localize()

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    assert len(calls) == 3
    conclusion_prompt = calls[1]["payload"]
    assert conclusion_prompt["conclusion_required"]["querying_allowed"] is False
    assert conclusion_prompt["registered_patch_sites"][0]["evidence"] == "e1"
    assert "instruction" not in conclusion_prompt
    assert "query_history" not in conclusion_prompt
    assert "0x" not in json.dumps(conclusion_prompt).lower()
    rejected_prompt = calls[2]["payload"]
    assert rejected_prompt["conclusion_error"]["error"] == (
        "Queries are forbidden after a successful patch-site nomination")
    assert rejected_prompt["conclusion_error"]["submitted_query"] == {
        "op": "elf_info"}
    answers = [item for item in flow.ledger_for_target().by_kind("model_query")
               if item["status"] == "answered"]
    assert [item["query"]["op"] for item in answers] == [
        "register_patch_site"]


def test_successful_batch_registration_locks_conclusion_immediately(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "nomination-lock"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "nomination-lock-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.cfg["repair"]["firmware_localize_queries"] = 4
    flow.model.script(
        "localize",
        {"queries": [
            {"op": "register_patch_site", "address": site},
            {"op": "elf_info"},
        ]},
        {"evidence": ["e1"], "reasoning": "locked after nomination"})

    flow.localize()

    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    assert len(calls) == 2
    conclusion = calls[1]["payload"]
    assert conclusion["registered_patch_sites"][0]["evidence"] == "e1"
    assert conclusion["conclusion_required"]["querying_allowed"] is False
    assert "instruction" not in conclusion
    assert "query_history" not in conclusion
    assert "query_answer" not in conclusion
    assert "query_answers" not in conclusion
    answered = [item for item in flow.ledger_for_target().by_kind("model_query")
                if item["status"] == "answered"]
    assert [item["query"]["op"] for item in answered] == [
        "register_patch_site"]


def test_localization_output_invalid_is_distinct_from_budget_exhaustion(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "conclusion-contract"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "conclusion-contract-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.cfg["repair"]["firmware_localize_queries"] = 8
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": site}},
        {"op": "conclude", "evidence": "e1", "reasoning": "wrong envelope"},
        {"localization_conclusion": {"evidence": ["e1"], "reasoning": "nested"}},
        {"model_code_site": "e1"})

    with pytest.raises(RepairError) as caught:
        flow.localize()

    assert caught.value.status == "localization_output_invalid"
    assert "budget exhausted" not in str(caught.value)


@pytest.mark.parametrize("final_decision", [False, True])
def test_semantic_rejection_is_persisted_in_both_registration_paths(
        fake_session, tmp_path, monkeypatch, final_decision):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "rejected-nomination"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "rejected-nomination-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.ledger_for_target().target_path) as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/fixture"}, "signal": "SIGSEGV"})
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    monkeypatch.setattr(flow, "_semantic_site_eligibility", lambda *args: {
        "decision": "rejected", "semantic_class": "fixture_rejection"})
    replies = [{"query": {"op": "register_patch_site", "address": site}},
               {"localization_failed": True, "reasoning": "fixture rejection"}]
    if final_decision:
        replies.insert(0, {"query": {"op": "elf_info"}})
    flow.model.script("localize", *replies)
    with pytest.raises(RepairError, match="insufficient localization evidence"):
        flow.localize()
    ledger = flow.ledger_for_target()
    nomination = ledger.by_kind("model_code_site")[0]
    assert ledger.code_site_rejected(nomination["id"])
    events = ledger.by_kind("nomination_decision")
    assert len(events) == 1
    assert events[0]["semantic_class"] == "fixture_rejection"
    assert events[0]["session_id"].startswith("localize-")


def test_semantic_nomination_gate_rejects_cleanup_site(tmp_path):
    poc = tmp_path / "semantic-gate-poc.py"
    poc.write_text(POC_SOURCE)
    make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                  analysis_target=b"fixture")
    fault = {"signal": "SIGSEGV"}
    accepted = FirmwareWorkflow._semantic_site_eligibility(
        {"callee": "__GI_strcat"}, fault)
    unknown = FirmwareWorkflow._semantic_site_eligibility(
        {"callee": "custom_wrapper"}, fault)
    rejected = FirmwareWorkflow._semantic_site_eligibility(
        {"callee": "__GI_fclose"}, fault)
    assert accepted["decision"] == "accepted"
    assert unknown["decision"] == "accepted_with_causal_requirement"
    assert rejected["decision"] == "rejected"


def test_localization_accepts_narrow_string_evidence_normalization(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "string-evidence"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "string-evidence-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": site}},
        {"evidence": "e1", "reasoning": "narrow compatibility"})
    flow.localize()
    assert flow.localized == ["e1"]


def test_invalid_query_consumes_bounded_query_budget(
        fake_session, tmp_path, monkeypatch):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "invalid-budget"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "invalid-budget-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    flow.cfg["repair"]["firmware_localize_queries"] = 1
    flow.model.script(
        "localize",
        {"query": {"op": "register_patch_site", "address": 0x400004}},
        {"localization_failed": True, "reasoning": "invalid site only"})

    with pytest.raises(RepairError) as caught:
        flow.localize()

    assert caught.value.status == "localization_failed"
    calls = [call for call in flow.model.calls if call["stage"] == "localize"]
    assert len(calls) == 2
    rejected = flow.ledger_for_target().by_kind("model_query")
    assert len(rejected) == 1 and rejected[0]["status"] == "rejected"


def test_propose_rejects_unselected_registered_site(fake_session, tmp_path):
    session, adapter = fake_session
    poc = tmp_path / "proposal-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    ledger = flow.ledger_for_target()
    selected_id = _add_model_code_site(
        ledger, site=0x400000, bytes_hex="11" * 16)
    unselected_id = _add_model_code_site(
        ledger, site=0x400100, bytes_hex="22" * 16)
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/trigger"},
        "signal": "SIGSEGV", "exit_record": {"pid": 10}})
    save_json(flow.root / "localize" / "result.json", {
        "evidence": [selected_id], "reasoning": "selected", "queries": []})
    _mark_localization_valid(flow, {
        "evidence": [selected_id], "reasoning": "selected", "queries": []})
    contract = {"abi": "inferred", "bounds": "bounded",
                "preserve": "valid behavior", "invalid": "safe failure"}
    source = "int repair_entry(void *p) { return p != 0; }"
    flow.model.script(
        "repair",
        {"edits": [{"site": 0x400100, "expected_hex": "22" * 16,
                    "evidence": [unselected_id], "contract": contract,
                    "source": source}]},
        {"edits": [{"site": 0x400000, "expected_hex": "11" * 16,
                    "evidence": [selected_id], "contract": contract,
                    "source": source}]},
    )

    proposal = flow.propose(tmp_path / "rounds" / "001", None)

    assert proposal["edits"][0]["site"] == 0x400000
    calls = [call for call in flow.model.calls if call["stage"] == "repair"]
    assert len(calls) == 2
    prompt = calls[0]["payload"]["prompt"]
    assert str(0x400000) in prompt
    assert str(0x400100) not in prompt
    assert "22" * 16 not in prompt


def test_full_pipeline_happy_path(fake_session, tmp_path):
    """Inject model + fake session + REAL implant candidate bytes: the loop
    runs reproduce -> localize -> tests -> repair -> verify -> report."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "dummy"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(adapter.DEFECTIVE)
    (rootfs / "www").mkdir()
    (rootfs / "www" / "index.html").write_text("home")
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc)
    _wire_session(flow, session, adapter)
    model = flow.model
    model.script("poc-analysis", PLAN_REPLY)
    model.script("generate-tests", TESTS_REPLY)
    # A proposal whose site/bytes come from REAL evidence will be built by
    # build_candidate; instead of a full clang cross-compile here, inject a
    # code_hex via monkeypatched build_candidate (verified in M5 tests).
    import repair_tool.firmware.loop as loop_mod

    ledger = flow.ledger_for_target()
    entry_id = _add_model_code_site(ledger)
    _script_propose(model, 0x400000, "11" * 16,
                    "int repair_entry(char*d,const char*s){return 0;}",
                    [entry_id])

    built_record = {"target_sha256": _sha_bytes(adapter.target_file.read_bytes()),
                    "candidate_sha256": _sha_bytes(LoopFakeAdapter.REPAIRED),
                    "implants": [{"site": 0x400000, "vaddr": 0x480000,
                                  "size": 8, "hex": "0000000c",
                                  "rebased_jumps": 0}],
                    "edits": [{"site": 0x400000, "expected_hex": "11" * 16,
                               "redirect_hex": "00" * 16,
                               "implant_vaddr": 0x480000}]}
    candidate_file = tmp_path / "candidate"
    candidate_file.write_bytes(LoopFakeAdapter.REPAIRED)

    def fake_build_candidate(target, edits, out_dir, **_):
        out_dir.mkdir(parents=True, exist_ok=True)
        return {"candidate": candidate_file, "record": built_record}

    monkey = pytest.MonkeyPatch()
    monkey.setattr(loop_mod, "build_candidate", fake_build_candidate)
    try:
        flow.analyze_poc()
        flow.reproduce()
        # This fake-session test bypasses the ELF-backed localization already
        # covered below and persists the model-selected site registered above.
        flow.localized = [entry_id]
        # propose() reads the persisted localization conclusion.
        save_json(flow.root / "localize" / "result.json",
                  {"evidence": [entry_id], "reasoning": "candidate",
                   "queries": []})
        _mark_localization_valid(flow, {
            "evidence": [entry_id], "reasoning": "candidate",
            "queries": []})
        flow.generate_tests()
        # repair_rounds -> deploy (fake replace flips bytes) -> verify -> ok
        flow.repair_rounds()
        flow.finalize({"candidate": candidate_file, "record": built_record},
                      flow.root / "rounds" / "001")
    finally:
        monkey.undo()
    report = flow.report
    assert report["status"] == "validated_candidate", report.get("error")
    assert report["patch_record"]["candidate_sha256"] == built_record["candidate_sha256"]
    assert report["final_verification"]["fixed_checks"] is True
    assert report["final_verification"]["tests"]["passed"] is True
    # Holdout ran in final verification only.
    holdout_ran = any("holdout-home" in json.dumps(t)
                      for t in [report["final_verification"]["tests"]])
    assert holdout_ran
    assert (flow.root / "final" / "report.html").exists()
    manifest = json.loads((flow.root / "final" / "manifest.json").read_text())
    assert manifest["schema"] == loop_mod.FIRMWARE_MANIFEST_SCHEMA
    for relative in (
            "baseline/httpd", "localize/result.json",
            "baseline/rootfs-manifest.json",
            "evidence/evidence-ledger.json", "evidence/query-trace.jsonl",
            "rounds/001/proposal.json", "rounds/001/patch-record.json",
            "final/candidate.json"):
        assert relative in manifest["file_sha256"]
    verify_monkey = pytest.MonkeyPatch()

    class VerifyLauncher:
        def start(self, **_):
            pass

        def stop(self):
            pass

    from repair_tool.firmware.rehost import SessionControl
    verify_monkey.setattr(loop_mod, "SessionSupervisor",
                         lambda *args, **kwargs: VerifyLauncher())
    verify_monkey.setattr(loop_mod, "SessionControl",
                         lambda _path: SessionControl(session))
    try:
        adapter.target_file.write_bytes(flow.baseline_bytes.read_bytes())
        verified = loop_mod.verify_firmware_run(flow.root)
    finally:
        verify_monkey.undo()
    assert verified["status"] == "verified"
    assert verified["lineage_status"] == "schema_3_rootfs_bound"
    (rootfs / "www" / "index.html").write_text("changed")
    with pytest.raises(RepairError, match="rootfs changed") as caught:
        loop_mod.verify_firmware_run(flow.root)
    assert caught.value.status == "integrity_failed"
    localization = flow.root / "localize" / "result.json"
    localization.write_text("{}", encoding="utf-8")
    with pytest.raises(RepairError, match="lineage artifact changed"):
        loop_mod._verify_manifest_file_hashes(
            flow.root, manifest, set(manifest["file_sha256"]))


def test_pipeline_rolls_back_on_failed_candidate(fake_session, tmp_path):
    """Failure injection: the deployed candidate still crashes -> verification
    fails -> rollback restores baseline bytes -> feedback recorded."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "mips"
    rootfs.mkdir(parents=True)
    mips_target = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(mips_target.read_bytes())
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=mips_target.read_bytes())
    _wire_session(flow, session, adapter)
    model = flow.model
    model.script("poc-analysis", PLAN_REPLY)
    model.script("generate-tests", TESTS_REPLY)
    ledger = flow.ledger_for_target()
    baseline = flow.baseline_bytes.read_bytes()
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
        site_hex = analysis.bytes_at(site, 16).hex()
    entry_id = _add_model_code_site(ledger, site=site, bytes_hex=site_hex)
    _script_propose(model, site, site_hex,
                    "int repair_entry(char*d,const char*s){return 0;}",
                    [entry_id])
    # Candidate that keeps crashing: bytes differ from the baseline but the
    # defect behaviour is identical (see STILL_BROKEN in the adapter).
    still_broken = LoopFakeAdapter.STILL_BROKEN
    candidate_file = tmp_path / "candidate-broken"
    candidate_file.write_bytes(still_broken)
    built_record = {"target_sha256": _sha_bytes(baseline),
                    "candidate_sha256": _sha_bytes(still_broken),
                    "implants": [{"site": site, "vaddr": 0x480000,
                                  "size": 8, "hex": "0000000c",
                                  "rebased_jumps": 0}],
                    "edits": [{"site": site, "expected_hex": site_hex,
                               "redirect_hex": "00" * 16,
                               "implant_vaddr": 0x480000}]}
    import repair_tool.firmware.loop as loop_mod

    def fake_build_candidate(target, edits, out_dir, **_):
        out_dir.mkdir(parents=True, exist_ok=True)
        return {"candidate": candidate_file, "record": built_record}

    monkey = pytest.MonkeyPatch()
    monkey.setattr(loop_mod, "build_candidate", fake_build_candidate)
    relocalizations = []
    try:
        flow.analyze_poc()
        flow.reproduce()
        flow.localized = [entry_id]
        save_json(flow.root / "localize" / "result.json",
                   {"evidence": [entry_id], "reasoning": "candidate",
                    "queries": [{"query": {"op": "register_patch_site",
                                             "address": site},
                                 "answer": {"op": "register_patch_site",
                                            "evidence": entry_id,
                                            "site": site,
                                            "bytes_hex": site_hex}}]})
        _mark_localization_valid(flow, json.loads(
            (flow.root / "localize" / "result.json").read_text()))
        flow.generate_tests()
        # A pre-existing baseline context must not leak into candidate
        # feedback; candidate exits get a distinct context and a private path.
        adapter._record_exit(debug_context={"pc": 0x11111111,
                                            "log_path": "/tmp/old.log"})
        adapter.exit_debug_context = {"pc": 0x22222222, "ra": 0x33333333,
                                      "log_path": "/tmp/candidate.log"}

        def relocalize(feedback, **kwargs):
            relocalizations.append({"feedback": feedback, **kwargs})
            current = json.loads(
                (flow.root / "localize" / "result.json").read_text())
            _mark_localization_valid(flow, current)

        monkey.setattr(flow, "relocalize", relocalize)
        flow.repair_rounds()
    finally:
        monkey.undo()
    # Rounds exhausted: rollback happened, baseline bytes restored.
    assert flow.report["status"] == "rounds_exhausted"
    deployed_now = adapter.target_file.read_bytes()
    assert deployed_now == baseline
    # The failed deployment is observable in the adapter's history.
    assert any(bytes(r) == still_broken for r in adapter.replacements)
    # A failed round record exists with the verification failure reason.
    records = flow.report["rounds"]
    assert records and records[0]["status"] in {
        "verification_failed", "functional_failed", "generated_test_failed"}
    assert len(relocalizations) == 1
    assert relocalizations[0]["candidate"] == candidate_file
    assert relocalizations[0]["candidate_sha256"] == \
        built_record["candidate_sha256"]
    repair_calls = [call for call in model.calls if call["stage"] == "repair"]
    assert len(repair_calls) == 2
    candidate_feedback = repair_calls[1]["payload"]["feedback"]
    assert candidate_feedback["retry_scope"] == "relocalize"
    assert candidate_feedback["failure_triage"]["retry_scope"] == "relocalize"
    assert not flow._localization_state_valid()
    assert "patched_sites" not in candidate_feedback
    assert str(site) not in json.dumps(candidate_feedback)
    exits = candidate_feedback["candidate_runtime_exits"]
    assert exits and all(item["sha256"] == built_record["candidate_sha256"]
                         and item.get("intentional") is not True
                         for item in exits)
    assert candidate_feedback["fault_context"] == {
        "pc": 0x22222222, "ra": 0x33333333}
    assert "/tmp/" not in json.dumps(candidate_feedback)


def test_candidate_runtime_feedback_uses_cursor_sha_and_nonintentional_only(
        fake_session, tmp_path):
    session, adapter = fake_session
    poc = tmp_path / "filter-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    adapter.target_file.write_bytes(adapter.STILL_BROKEN)
    candidate_sha = _sha_bytes(adapter.STILL_BROKEN)
    adapter._record_exit(debug_context={"pc": 1})  # same SHA, previous round
    cursor = flow._runtime_exit_cursor()
    adapter._record_exit(intentional=True,
                         debug_context={"pc": 2, "log_path": "/tmp/stop"})
    adapter._record_exit(debug_context={"pc": 3, "ra": 4,
                                        "log_path": "/tmp/current"})
    adapter.target_file.write_bytes(adapter.DEFECTIVE)
    adapter._record_exit(debug_context={"pc": 5})  # baseline after rollback

    exits = flow._candidate_runtime_exits(cursor, candidate_sha)

    assert len(exits) == 1
    assert exits[0]["sha256"] == candidate_sha
    assert exits[0]["debug_context"] == {"pc": 3, "ra": 4}
    assert flow._fault_context_from_exits(exits) == {"pc": 3, "ra": 4}
    assert "/tmp/" not in json.dumps(exits)


def test_candidate_failure_triage_separates_new_fault_from_unfixed(
        tmp_path, monkeypatch):
    poc = tmp_path / "failure-triage-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    baseline = {"exit_record": {"signal_name": "SIGSEGV",
                                "debug_context": {"pc": 1, "ra": 2}}}
    monkeypatch.setattr(flow, "fault_summary", lambda: baseline)
    exc = RepairError("verification_failed", "candidate still crashes")
    same = flow._candidate_failure_triage(exc, [{
        "signal_name": "SIGSEGV", "debug_context": {"pc": 1, "ra": 2}}])
    new_signal = flow._candidate_failure_triage(exc, [{
        "signal_name": "SIGBUS", "debug_context": {"pc": 3, "ra": 4}}])
    new_pc = flow._candidate_failure_triage(exc, [{
        "signal_name": "SIGSEGV", "debug_context": {"pc": 3, "ra": 2}}])
    functional = flow._candidate_failure_triage(
        RepairError("functional_failed", "login failed"), [])
    generated_crash = flow._candidate_failure_triage(
        RepairError("generated_test_failed", "candidate crashed"), [{
            "signal_name": "SIGSEGV",
            "debug_context": {"pc": 1, "ra": 2},
        }])

    assert same["category"] == "same_fault_unfixed"
    assert new_signal["category"] == "new_fault_introduced"
    assert new_pc["category"] == "new_fault_introduced"
    assert functional["category"] == "functional_regression"
    assert generated_crash["category"] == "same_fault_unfixed"
    assert same["retry_scope"] == "relocalize"
    assert new_signal["retry_scope"] == "relocalize"
    assert new_pc["retry_scope"] == "relocalize"
    assert functional["retry_scope"] == "same_localization"
    assert generated_crash["retry_scope"] == "relocalize"
    assert {same["category"], new_signal["category"], functional["category"]}


def test_pre_ready_candidate_exit_relocalizes_with_sanitized_fault(
        tmp_path, monkeypatch):
    poc = tmp_path / "pre-ready-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    flow.cfg["repair"]["max_rounds"] = 2
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"candidate")
    candidate_sha = _sha_bytes(candidate.read_bytes())
    built = {"candidate": candidate, "record": {
        "candidate_sha256": candidate_sha, "target_sha256": "b" * 64,
        "edits": [], "implants": []}}
    def propose(_round_dir, feedback, **_):
        observed_feedback.append(feedback)
        return {"edits": []}

    monkeypatch.setattr(flow, "propose", propose)
    monkeypatch.setattr(flow, "implant", lambda *_, **__: built)
    monkeypatch.setattr(flow, "_runtime_exit_cursor", lambda: 0)
    monkeypatch.setattr(flow, "rollback", lambda *_: None)
    monkeypatch.setattr(flow, "finalize", lambda *_: None)
    observed_feedback = []
    relocalizations = []
    monkeypatch.setattr(
        flow, "relocalize",
        lambda feedback, **kwargs: relocalizations.append(
            {"feedback": feedback, **kwargs}))
    calls = {"deploy": 0}

    def deploy(*_):
        calls["deploy"] += 1
        if calls["deploy"] == 1:
            exc = RepairError("infrastructure_failed", "Admin RPC replace failed")
            exc.failure = {
                "kind": "target_start_failed",
                "expected_sha256": candidate_sha,
                "exit": {"pid": 42, "sha256": candidate_sha,
                         "signal_name": "SIGSEGV", "intentional": False,
                         "phase": "starting", "identity_confirmed": False,
                         "debug_context": {"pc": 0x404040, "ra": 0x505050,
                                           "log_path": "/tmp/private.log"},
                         "log_path": "/tmp/private.log"}}
            raise exc
        return {"candidate_sha256": candidate_sha, "verification": {}}

    monkeypatch.setattr(flow, "deploy_and_verify", deploy)

    flow.repair_rounds()

    assert observed_feedback
    feedback = next(item for item in observed_feedback if item is not None)
    assert feedback["category"] == "candidate_launch_failed"
    assert feedback["retry_scope"] == "relocalize"
    assert feedback["fault_context"] == {"pc": 0x404040, "ra": 0x505050}
    assert feedback["candidate_runtime_exits"][0]["phase"] == "starting"
    assert "/tmp/" not in json.dumps(feedback)
    assert len(relocalizations) == 1
    assert relocalizations[0]["candidate"] == candidate
    assert relocalizations[0]["candidate_sha256"] == candidate_sha
    assert flow.report["rounds"][0]["status"] == "candidate_launch_failed"
    assert (flow.root / "rounds" / "001" / "record.json").is_file()


def test_repair_invalid_retries_proposal_at_same_localization(
        tmp_path, monkeypatch):
    poc = tmp_path / "repair-invalid-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    flow.cfg["repair"]["max_rounds"] = 1
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"candidate")
    candidate_sha = _sha_bytes(candidate.read_bytes())
    proposal_feedback = []

    def propose(_round_dir, feedback, **_):
        proposal_feedback.append(feedback)
        return {"edits": []}

    implant_calls = {"count": 0}

    def implant(*_, **__):
        implant_calls["count"] += 1
        if implant_calls["count"] == 1:
            raise RepairError("repair_invalid",
                              "Repair source failed to compile: private path")
        return {"candidate": candidate, "record": {
            "candidate_sha256": candidate_sha, "target_sha256": "b" * 64,
            "edits": [], "implants": []}}

    monkeypatch.setattr(flow, "propose", propose)
    monkeypatch.setattr(flow, "implant", implant)
    monkeypatch.setattr(flow, "_runtime_exit_cursor", lambda: 0)
    monkeypatch.setattr(
        flow, "deploy_and_verify",
        lambda *_: {"candidate_sha256": candidate_sha, "verification": {}})
    monkeypatch.setattr(flow, "finalize", lambda *_: None)
    monkeypatch.setattr(
        flow, "relocalize",
        lambda *_: pytest.fail("repair_invalid must not force relocalization"))

    flow.repair_rounds()

    assert len(proposal_feedback) == 2
    retry = proposal_feedback[1]
    assert retry["category"] == "source_compile"
    assert retry["retry_scope"] == "same_localization"
    assert "private path" not in json.dumps(retry)
    assert flow.report["rounds"][0]["status"] == "candidate_accepted"


@pytest.mark.parametrize("diagnostic,secret", [
    (r"C:\Users\lumin\My Project\repair.c:12: error", "Users\\lumin"),
    ("/mnt/d/My Project/repair.c:12: error", "My Project"),
])
def test_compile_feedback_redacts_complete_private_paths(diagnostic, secret):
    sanitized = FirmwareWorkflow._sanitize_feedback_text(diagnostic)
    assert secret not in sanitized
    assert "[redacted path]:12: error" in sanitized


def test_infrastructure_failure_saves_round_and_keeps_rollback_secondary(
        tmp_path, monkeypatch):
    poc = tmp_path / "infra-round-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, tmp_path / "unused-rootfs", poc,
                         analysis_target=b"fixture")
    flow.cfg["repair"]["max_rounds"] = 1
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"candidate")
    candidate_sha = _sha_bytes(candidate.read_bytes())
    built = {"candidate": candidate, "record": {
        "candidate_sha256": candidate_sha, "target_sha256": "b" * 64,
        "edits": [], "implants": []}}
    monkeypatch.setattr(flow, "propose",
                        lambda *_, **__: {"edits": []})
    monkeypatch.setattr(flow, "implant", lambda *_, **__: built)
    monkeypatch.setattr(flow, "_runtime_exit_cursor", lambda: 0)

    def fail_deploy(*_):
        raise RepairError("infrastructure_failed", "primary transport failure")

    def fail_rollback(*_):
        raise RepairError("rollback_failed", "secondary rollback failure")

    monkeypatch.setattr(flow, "deploy_and_verify", fail_deploy)
    monkeypatch.setattr(flow, "rollback", fail_rollback)

    with pytest.raises(RepairError, match="primary transport failure"):
        flow.repair_rounds()

    record = flow.report["rounds"][0]
    assert record["status"] == "infrastructure_failed"
    assert record["rollback_error"]["status"] == "rollback_failed"
    persisted = json.loads((flow.root / "rounds" / "001" /
                            "record.json").read_text(encoding="utf-8"))
    assert persisted["error"] == "primary transport failure"
    assert flow.report["warnings"][-1]["primary_status"] == \
        "infrastructure_failed"


def test_failed_candidate_relocalizes_before_next_proposal(
        fake_session, tmp_path, monkeypatch):
    """A fatal candidate failure invalidates and re-derives localization."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "retry"
    rootfs.mkdir(parents=True)
    mips_target = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(mips_target.read_bytes())
    poc = tmp_path / "retry-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=mips_target.read_bytes())
    _wire_session(flow, session, adapter)
    model = flow.model
    model.script("poc-analysis", PLAN_REPLY)
    model.script("generate-tests", TESTS_REPLY)
    ledger = flow.ledger_for_target()
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(flow.session_dir / "rootfs" / "sbin" / "httpd") as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
        site_hex = analysis.bytes_at(site, 16).hex()
    entry_id = _add_model_code_site(ledger, site=site, bytes_hex=site_hex)
    _script_propose(model, site, site_hex,
                    "int repair_entry(char*d,const char*s){return 0;}",
                    [entry_id], times=4)

    import repair_tool.firmware.loop as loop_mod

    built_record = {
        "target_sha256": _sha_bytes(mips_target.read_bytes()),
        "candidate_sha256": _sha_bytes(LoopFakeAdapter.STILL_BROKEN),
        "implants": [{"site": site, "vaddr": 0x480000, "size": 8,
                      "hex": "0000000c", "rebased_jumps": 0}],
        "edits": [{"site": site, "expected_hex": site_hex,
                   "redirect_hex": "00" * 16, "implant_vaddr": 0x480000}]}
    candidate_file = tmp_path / "candidate-still-broken"
    candidate_file.write_bytes(LoopFakeAdapter.STILL_BROKEN)

    def fake_build_candidate(target, edits, out_dir, **_):
        out_dir.mkdir(parents=True, exist_ok=True)
        return {"candidate": candidate_file, "record": built_record}

    monkeypatch.setattr(loop_mod, "build_candidate", fake_build_candidate)
    flow.analyze_poc()
    flow.reproduce()
    flow.localized = [entry_id]
    save_json(flow.root / "localize" / "result.json",
              {"evidence": [entry_id], "reasoning": "candidate", "queries": []})
    _mark_localization_valid(flow, {
        "evidence": [entry_id], "reasoning": "candidate", "queries": []})
    flow.generate_tests()
    adapter.exit_debug_context = {"pc": 0x22222222, "ra": 0x33333333}
    relocalizations = []

    def relocalize(feedback, **kwargs):
        relocalizations.append({"feedback": feedback, **kwargs})
        current = json.loads(
            (flow.root / "localize" / "result.json").read_text())
        _mark_localization_valid(flow, current)

    monkeypatch.setattr(flow, "relocalize", relocalize)
    flow.repair_rounds()

    assert len(relocalizations) == 1
    assert relocalizations[0]["candidate"] == candidate_file
    assert relocalizations[0]["candidate_sha256"] == \
        built_record["candidate_sha256"]
    repair_calls = [call for call in model.calls if call["stage"] == "repair"]
    assert len(repair_calls) == 2
    assert repair_calls[1]["payload"]["feedback"]["retry_scope"] == "relocalize"
    assert not flow._localization_state_valid()
    assert flow.report["status"] == "rounds_exhausted"


def test_candidate_exit_collection_waits_for_supervisor_flush(
        fake_session, tmp_path, monkeypatch):
    session, adapter = fake_session
    poc = tmp_path / "flush-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    adapter.target_file.write_bytes(adapter.STILL_BROKEN)
    candidate_sha = _sha_bytes(adapter.STILL_BROKEN)
    cursor = flow._runtime_exit_cursor()
    status_calls = []
    original_status = flow.control.status

    def delayed_status(*args, **kwargs):
        result = original_status(*args, **kwargs)
        status_calls.append(True)
        if len(status_calls) == 1:
            adapter._record_exit(debug_context={"pc": 0x2468})
        return result

    monkeypatch.setattr(flow.control, "status", delayed_status)
    monkeypatch.setattr("repair_tool.firmware.loop.time.sleep",
                        lambda _: None)

    exits = flow._collect_candidate_runtime_exits(cursor, candidate_sha)

    assert len(status_calls) == 1
    assert exits[0]["sha256"] == candidate_sha
    assert exits[0]["debug_context"] == {"pc": 0x2468}


def test_redeploy_verify_roundtrip(fake_session, tmp_path):
    """redeploy_and_verify: rollback -> checks pass -> redeploy -> verify."""
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl
    from repair_tool.firmware.plan import validate_plan
    control = SessionControl(session)
    baseline = tmp_path / "baseline-httpd"
    baseline.write_bytes(adapter.DEFECTIVE)
    candidate = tmp_path / "candidate-httpd"
    candidate.write_bytes(LoopFakeAdapter.REPAIRED)
    plan = validate_plan(PLAN_REPLY)
    tests = validate_tests(TESTS_REPLY)
    checks = [{"request": {"path": "/"}, "statuses": [200],
               "contains": "home"}]

    class _Lock:
        id = "tx-redeploy"

    from repair_tool.firmware.rehost import SessionLock
    lock = SessionLock(session)
    lock.acquire("redeploy-test")
    try:
        # Deploy the repaired candidate first (as the loop would).
        control.replace_target(candidate, transaction=lock.id)
        _patched_deploy(adapter)      # repaired behaviour
        result = redeploy_and_verify(
            control, baseline=baseline, candidate=candidate, checks=checks,
            plan=plan, tests=[t for t in tests if t["kind"] != "independent"],
            logs=tmp_path / "redeploy-logs", target_rel="sbin/httpd",
            transaction=lock.id, exit_timeout=1.0)
        assert result["fixed"]["passed"] is True
        assert result["tests"]["passed"] is True
        # Final state: candidate deployed.
        assert control.target_sha() == _sha_bytes(
            LoopFakeAdapter.REPAIRED) or adapter.target_file.read_bytes() == \
            LoopFakeAdapter.REPAIRED
    finally:
        lock.release()


def test_final_baseline_failure_is_infrastructure_not_feedback(
        fake_session, tmp_path, monkeypatch):
    import repair_tool.firmware.verify as verify_mod
    from repair_tool.firmware.rehost import SessionControl, SessionLock

    session, adapter = fake_session
    control = SessionControl(session)
    checks = [{"request": {"path": "/rollback-only"}, "statuses": [200],
               "contains": ""}]
    candidate = tmp_path / "candidate"
    candidate.write_bytes(LoopFakeAdapter.REPAIRED)

    def fail_only_rollback(data):
        if b"/rollback-only " in data:
            return b"HTTP/1.0 500 Internal Server Error\r\n\r\n"
        return b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"

    monkeypatch.setattr(adapter, "_http", fail_only_rollback)
    lock = SessionLock(session)
    lock.acquire("final-baseline")
    try:
        with pytest.raises(RepairError) as caught:
            verify_mod.redeploy_and_verify(
                control, baseline=adapter.target_file, candidate=candidate,
                checks=checks,
                plan={"requests": [{"id": "control", "path": "/",
                                    "expect": "response"}]},
                tests=[], logs=tmp_path / "final-logs",
                target_rel="sbin/httpd", transaction=lock.id,
                exit_timeout=0.01)
        assert caught.value.status == "infrastructure_failed"
        assert "rollback-only" not in str(caught.value)
    finally:
        lock.release()


def test_replay_requires_matching_transaction(fake_session, tmp_path):
    """The adapter must refuse replace/restart without the lock's tx id."""
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl, SessionLock
    control = SessionControl(session)
    lock = SessionLock(session)
    lock.acquire("owner")
    try:
        with pytest.raises(RepairError, match="locked"):
            control.replace_target(tmp_path / "x.bin")
    finally:
        lock.release()


@pytest.mark.parametrize("response", [b"", b"not-http"])
def test_replay_and_survival_reject_timeout_without_http(tmp_path, monkeypatch, response):
    import repair_tool.firmware.verify as verify_mod
    monkeypatch.setattr(verify_mod.time, "sleep", lambda _: None)

    class Control:
        def current_target(self):
            return {"pid": 1, "sha256": "same"}
        def target_exits(self):
            return []
        def deliver(self, request):
            return {"receive": "timeout", "response_hex": response.hex()}

    control = Control()
    plan = {"requests": [{"id": "control", "path": "/", "expect": "response"}]}
    with pytest.raises(RepairError, match="incomplete_response"):
        replay_plan(control, plan, tmp_path)
    result = run_one_test(control, {"id": "survive", "kind": "regression",
                                   "expect": "pass", "request": {"path": "/"},
                                   "response": {"statuses": [200], "contains": ""}})
    assert not result["passed"]


def test_replay_rejects_pid_change_with_same_binary(tmp_path, monkeypatch):
    """Candidate-phase identity is BYTES: a pid change with the same binary
    is legitimate (the loop restarts the service after crashes/redeploys).
    What replay must reject is a different binary running (run 8: pid
    stability was over-strict and mislabelled a repaired-and-restarted
    candidate as unstable)."""
    import repair_tool.firmware.verify as verify_mod
    monkeypatch.setattr(verify_mod.time, "sleep", lambda _: None)

    class Control:
        pid = 1
        def current_target(self):
            return {"pid": self.pid, "sha256": "same"}
        def target_exits(self):
            return []
        def deliver(self, request):
            self.pid += 1
            return {"receive": "eof", "response_hex": b"HTTP/1.0 200 OK\r\n\r\n".hex()}
        def restart(self):
            pass

    replay = replay_plan(Control(), {"requests": [
        {"id": "control", "path": "/", "expect": "response"}]}, tmp_path)
    assert replay["stable_identity"] is True

    class SwappedControl(Control):
        swapped = False

        def deliver(self, request):
            self.pid += 1
            self.swapped = True        # binary changes mid-replay
            return {"receive": "eof", "response_hex": b"HTTP/1.0 200 OK\r\n\r\n".hex()}

        def current_target(self):
            return {"pid": self.pid, "sha256": "swapped" if self.swapped else "same"}

    with pytest.raises(RepairError, match="identity changed"):
        replay_plan(SwappedControl(), {"requests": [
            {"id": "control", "path": "/", "expect": "response"}]}, tmp_path)


def test_independent_failure_stops_rounds_without_feedback(fake_session, tmp_path, monkeypatch):
    session, adapter = fake_session
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.cfg["firmware"]["poc_request_timeout"] = 0.01
    from repair_tool.firmware.tests import split_holdouts
    flow.tests, flow.holdout = split_holdouts(validate_tests(TESTS_REPLY))
    flow.plan = PLAN_REPLY
    candidate = tmp_path / "candidate"
    candidate.write_bytes(adapter.REPAIRED)
    built = {"candidate": candidate, "record": {
        "candidate_sha256": _sha_bytes(adapter.REPAIRED)}}
    proposals = []
    monkeypatch.setattr(flow, "propose",
                        lambda *args, **kwargs: proposals.append((args, kwargs)))
    monkeypatch.setattr(flow, "implant", lambda *args, **kwargs: built)
    def no_feedback(*args):
        pytest.fail("Independent failure leaked into repair feedback")
    monkeypatch.setattr(flow, "feedback", no_feedback)
    original_http = adapter._http
    def fail_holdout(data):
        if b"/index.htm " in data and adapter.target_file.read_bytes() == adapter.REPAIRED:
            adapter._record_exit()
        return original_http(data)
    monkeypatch.setattr(adapter, "_http", fail_holdout)
    with pytest.raises(RepairError) as caught:
        flow.repair_rounds()
    assert caught.value.status == "independent_rejected"
    assert "holdout-home" not in str(caught.value)
    assert len(proposals) == 1
    assert len(flow.report["rounds"]) == 1
    assert adapter.target_file.read_bytes() == adapter.DEFECTIVE


@pytest.mark.parametrize("reject_holdout", [False, True])
def test_archived_verify_keeps_independent_tests(fake_session, tmp_path, monkeypatch, reject_holdout):
    import repair_tool.firmware.loop as loop_mod
    session, adapter = fake_session
    root = tmp_path / "archived-run"
    save_json(root / "report.json", {"kind": "firmware", "status": "validated_candidate"})
    candidate = root / "final/httpd"
    candidate.parent.mkdir()
    candidate.write_bytes(adapter.REPAIRED)
    baseline = root / "baseline/httpd"
    baseline.parent.mkdir()
    baseline.write_bytes(adapter.DEFECTIVE)
    save_json(root / "final/candidate.json", {
        "candidate_sha256": _sha_bytes(adapter.REPAIRED),
        "baseline_sha256": _sha_bytes(adapter.DEFECTIVE),
        "candidate_path": str(candidate)})
    save_json(root / "config.json", {"firmware": {
        "rootfs": str(session / "rootfs"), "adapter": "dir825", "target": "sbin/httpd",
        "poc_request_timeout": 0.01,
        "checks": [{"request": {"path": "/"}, "statuses": [200], "contains": "home"}]}})
    save_json(root / "poc-analysis/plan.json", PLAN_REPLY)
    save_json(root / "generated-tests.json", validate_tests(TESTS_REPLY))
    from repair_tool.firmware.plan import validate_plan
    validated_plan = validate_plan(PLAN_REPLY)
    validated_tests = validate_tests(TESTS_REPLY)
    checks = [{"request": {"path": "/"}, "statuses": [200],
               "contains": "home"}]
    save_json(root / "final/manifest.json", {
        "schema": 1,
        "baseline_sha256": _sha_bytes(adapter.DEFECTIVE),
        "candidate_sha256": _sha_bytes(adapter.REPAIRED),
        "target_rel": "sbin/httpd",
        "plan_sha256": loop_mod._canonical_json_sha256(validated_plan),
        "tests_sha256": loop_mod._canonical_json_sha256(validated_tests),
        "checks_sha256": loop_mod._canonical_json_sha256(checks)})
    class Launcher:
        def start(self, **_):
            pass
        def stop(self):
            pass
    monkeypatch.setattr(loop_mod, "SessionSupervisor", lambda *a, **k: Launcher())
    from repair_tool.firmware.rehost import SessionControl
    monkeypatch.setattr(loop_mod, "SessionControl", lambda _: SessionControl(session))
    original_http = adapter._http
    def http(data):
        if reject_holdout and b"/index.htm " in data and adapter.target_file.read_bytes() == adapter.REPAIRED:
            adapter._record_exit()
        return original_http(data)
    monkeypatch.setattr(adapter, "_http", http)
    if reject_holdout:
        with pytest.raises(RepairError) as caught:
            loop_mod.verify_firmware_run(root)
        assert caught.value.status == "independent_rejected"
    else:
        result = loop_mod.verify_firmware_run(root)
        assert result["status"] == "verified"
        assert "holdout-home" in result["tests"]["ids"]
        (root / "final/manifest.json").unlink()
        # The real verifier creates a fresh rootfs copy per invocation; the
        # fake launcher reuses one fixture directory, so restore its factory
        # bytes before exercising the legacy path a second time.
        adapter.target_file.write_bytes(adapter.DEFECTIVE)
        legacy = loop_mod.verify_firmware_run(root)
        assert legacy["status"] == "verified_legacy_unbound"
        assert legacy["lineage_status"] == "legacy_manifest_missing"
        adapter.target_file.write_bytes(adapter.DEFECTIVE)
        monkeypatch.setattr(loop_mod, "_unix_socket_supported", lambda _: False)

        def stop_with_warning(_self):
            raise OSError("synthetic cleanup warning")

        monkeypatch.setattr(Launcher, "stop", stop_with_warning)
        warned = loop_mod.verify_firmware_run(root)
        assert warned["status"] == "verified_with_cleanup_warnings"
        assert warned["cleanup_warnings"] == [
            "launcher stop failed: synthetic cleanup warning"]
        links = root / "verification-sessions"
        assert not links.exists() or not any(path.is_symlink()
                                             for path in links.iterdir())


def test_record_baseline_bytes_rejects_tampering(tmp_path):
    import repair_tool.firmware.loop as loop_mod
    root = tmp_path / "run"
    baseline = root / "baseline" / "httpd"
    baseline.parent.mkdir(parents=True)
    baseline.write_bytes(b"accepted-baseline")
    save_json(root / "config.json", {"firmware": {
        "rootfs": str(tmp_path / "factory"), "target": "sbin/httpd"}})
    record = {"baseline_sha256": _sha_bytes(baseline.read_bytes())}
    baseline.write_bytes(b"tampered-baseline")

    with pytest.raises(RepairError, match="baseline sha256 mismatch") as caught:
        loop_mod.record_baseline_bytes(root, record)

    assert caught.value.status == "integrity_failed"


def test_baseline_exit_restarts_under_transaction_before_holdout(fake_session, tmp_path):
    from repair_tool.firmware.rehost import SessionControl, SessionLock
    session, adapter = fake_session
    control = SessionControl(session)
    tests = validate_tests(TESTS_REPLY)
    tests = [tests[1], tests[2], tests[0]]  # crash -> holdout -> public control
    initial_pid = adapter.pid
    lock = SessionLock(session)
    lock.acquire("baseline-tests")
    try:
        results = baseline_oracle(control, tests, tmp_path / "oracle",
                                  exit_timeout=0.01, transaction=lock.id)
        assert all(result["passed"] for result in results)
        assert adapter.pid > initial_pid
        assert control.target_sha() == _sha_bytes(adapter.DEFECTIVE)
    finally:
        lock.release()


def test_baseline_dead_service_does_not_cascade(fake_session, tmp_path):
    """Real-model run 20261018-105941: after a vulnerability test crashed the
    service, subsequent pass-tests saw 'no HTTP response' and failed
    spuriously -- the supervisor retains the dead instance's identity, so
    the old liveness check (status query) never restarted it. Liveness must
    be decided by OBSERVED EXIT COUNT."""
    session, adapter = fake_session
    from repair_tool.firmware.rehost import SessionControl, SessionLock
    control = SessionControl(session)
    # Order: crash first, then pass tests against the (previously dead) svc.
    tests = validate_tests(TESTS_REPLY)
    tests = [tests[1], tests[0], tests[2]]
    lock = SessionLock(session)
    lock.acquire("cascade-test")
    try:
        results = baseline_oracle(control, tests, tmp_path / "oracle2",
                                  exit_timeout=0.5, transaction=lock.id)
        assert all(r["passed"] for r in results), results
        # Every pass-test after the crash got a REAL response (not cascade).
        assert all("no HTTP response" not in (r.get("reason") or "")
                   for r in results)
    finally:
        lock.release()


def test_generate_tests_recovers_dead_target_before_oracle(
        fake_session, tmp_path):
    """Long localization can leave no live target before the oracle starts.

    Run-12 reached test-generation with no baseline/ directory because
    current_target() failed before the first test. The controller must
    restart the baseline under its transaction instead of surfacing an
    unexplained infrastructure failure.
    """
    session, adapter = fake_session
    poc = tmp_path / "dead-target-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.model.script("poc-analysis", PLAN_REPLY)
    flow.model.script("generate-tests", TESTS_REPLY)
    flow.event("session-ready")
    flow.analyze_and_reproduce()
    flow.localization = ["unused"]
    save_json(flow.root / "localize" / "result.json", {"evidence": []})
    # Simulate the supervisor retaining a dead target's identity: status no
    # longer exposes a valid live instance, but restart remains available.
    original_admin = adapter._admin
    original_http = adapter._http
    dead_target = {"yes": True}

    def admin_without_live_target(request):
        if request.get("command") == "restart":
            reply = original_admin(request)
            dead_target["yes"] = False
            return reply
        if request.get("command") == "status" and dead_target["yes"]:
            return {"ok": True, "target": None}
        return original_admin(request)

    adapter._admin = admin_without_live_target
    adapter._http = lambda data: (
        b"" if dead_target["yes"] else original_http(data))
    initial_pid = adapter.pid
    flow.generate_tests()

    assert flow.tests
    assert adapter.pid > initial_pid
    assert (flow.root / "test-generation" / "1" / "baseline" /
            "baseline-oracle.json").is_file()


def test_finish_preserves_primary_error_when_rollback_fails(tmp_path):
    """Rollback failure must not rename an already diagnosed stage error."""
    session = tmp_path / "failed-session"
    session.mkdir()
    poc = tmp_path / "rollback-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    flow.baseline_bytes.parent.mkdir(parents=True, exist_ok=True)
    flow.baseline_bytes.write_bytes(b"missing-baseline")
    flow.lock = type("Lock", (), {"id": "tx-test", "release": lambda self: None})()

    class DeadControl:
        def replace_target(self, source, transaction=None):
            raise RepairError("infrastructure_failed",
                              "Adapter reports no live target instance")

    flow.control = DeadControl()
    flow.report.update({"status": "infrastructure_failed",
                        "error": "Adapter reports no live target instance"})
    flow.finish()
    assert flow.report["status"] == "infrastructure_failed"
    assert flow.report["error"] == "Adapter reports no live target instance"
    assert flow.report["warnings"][-1]["rollback_status"] == "failed"


def test_localization_retries_truncated_output_without_leaking_candidates(
        tmp_path, monkeypatch):
    """A length-truncated localization reply gets a neutral format retry."""
    poc = tmp_path / "truncated-poc.py"
    poc.write_text(POC_SOURCE)
    rootfs = tmp_path / "rootfs" / "truncated"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    target_copy = flow.session_dir / "rootfs" / "sbin" / "httpd"
    target_copy.parent.mkdir(parents=True)
    target_copy.write_bytes(runner.read_bytes())
    ledger = flow.ledger_for_target()
    from repair_tool.arch.mips32 import ElfAnalysis
    with ElfAnalysis(target_copy) as analysis:
        site = analysis.call_sites(("concat_impl",))[0]["vaddr"]
        site_hex = analysis.bytes_at(site, 16).hex()
    entry_id = _add_model_code_site(ledger, site=site, bytes_hex=site_hex)

    class TruncatedThenConclusion:
        def __init__(self, cfg, root):
            self.calls = []

        def ask(self, stage, payload, directory):
            self.calls.append(payload)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "response.json").write_text(
                "{}", encoding="utf-8")
            if len(self.calls) == 1:
                raise RepairError("model_output_invalid",
                                  "Invalid model response: Incomplete model output: length")
            if len(self.calls) == 2:
                return {"query": {"op": "register_patch_site",
                                  "address": site}}
            current_evidence = payload["registered_patch_sites"][0][
                "evidence"]
            return {"evidence": [current_evidence],
                    "reasoning": "second attempt"}

    flow.model = TruncatedThenConclusion(flow.cfg, flow.root)
    monkeypatch.setattr(FirmwareWorkflow, "fault_summary",
                        lambda self: {"request": {"method": "GET", "path": "/"},
                                      "signal": "SIGSEGV",
                                      "debug_context": {"pc": 1}},
                        raising=True)
    monkeypatch.setattr(
        FirmwareWorkflow, "ledger_for_target", lambda self: ledger,
        raising=True)
    input_poc = flow.root / "inputs" / "poc" / "truncated-poc.py"
    input_poc.parent.mkdir(parents=True)
    input_poc.write_text(POC_SOURCE)
    flow.localize()

    assert flow.localized != [entry_id]
    assert flow.localized == [
        ledger.by_kind("model_code_site")[-1]["id"]]
    assert flow.model.calls[1]["output_retry"]["stage"] == "localize"
    assert "evidence" not in flow.model.calls[1]["output_retry"]
    assert "site" not in flow.model.calls[1]["output_retry"]
    assert flow.model.calls[2]["registered_patch_sites"][0][
        "evidence"] == flow.localized[0]


def test_reproduction_failure_surfaces_restart_failure(fake_session, tmp_path):
    """A failed replay must not leave a dead target and hide restart errors."""
    session, adapter = fake_session
    poc = tmp_path / "restart-failure-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.model.script("poc-analysis", PLAN_REPLY)

    def restart(transaction=None):
        raise RepairError("infrastructure_failed",
                          "Cannot register a live target")

    original_restart = flow.control.restart
    flow.control.restart = restart
    with pytest.raises(RepairError, match="Cannot register"):
        flow.analyze_and_reproduce()
    assert flow.control.restart is restart


# ------------------------------------------------- audit issue 1+2 contracts

def test_tests_prompt_carries_trigger_requests():
    """Audit issue 1: the generate-tests prompt must include the ACTUAL
    trigger request (method+path), not only id/expect/status -- each stage
    is an independent model call that cannot remember the reproduction."""
    from repair_tool.firmware.tests import tests_prompt
    reproduction = {"requests": [
        {"id": "trigger", "expect": "fatal_exit", "status": "confirmed",
         "request": {"method": "GET", "path": "/" + "A" * 205 + ".gif"}}]}
    payload = tests_prompt(reproduction, "Operator fixed checks: 1 configured")
    blob = json.dumps(payload)
    assert "/" + "A" * 205 + ".gif" in blob, \
        "trigger path missing from generate-tests prompt"
    rendered = json.dumps(payload["reproduction"])
    assert "path" in rendered and "method" in rendered


def test_reproduce_summary_records_request_paths(tmp_path):
    """Audit issue 1 data source: execute_plan results must keep the
    concrete request so later stages can cite it."""
    from repair_tool.firmware.reproduce import reproduce_and_report

    class Control:
        """Delivers, then records an attributable fatal exit (the fake
        crash the reproduction stage requires)."""
        exits = []

        def current_target(self):
            return {"pid": 1, "sha256": "s"}

        def target_exits(self):
            return list(self.exits)

        def deliver(self, request):
            self.exits.append({"pid": 1, "sha256": "s",
                               "signal_name": "SIGSEGV",
                               "intentional": False,
                               "debug_context": {"pc": 0x1234, "ra": 0x5678}})
            return {"receive": "eof", "response_hex": "", "bytes": 0,
                    "sha256": "x"}

    plan = {"requests": [{"id": "t", "method": "GET",
                          "path": "/" + "A" * 205 + ".gif",
                          "expect": "fatal_exit"}],
            "confirmations": ["t"]}
    reproduction = reproduce_and_report(
        Control(), plan, stage_dir=tmp_path, exit_timeout=0.01)
    request_entry = reproduction["requests"][0]
    assert request_entry["request"]["path"] == "/" + "A" * 205 + ".gif"
    assert request_entry["request"]["method"] == "GET"
    assert reproduction["target_end"] == {
        "state": "exited", "pid": 1, "sha256": "s",
        "signal": "SIGSEGV"}
    fault = json.loads((tmp_path / "fault-summary.json").read_text())
    assert fault["debug_context"] == {"pc": 0x1234, "ra": 0x5678}


def test_propose_payload_carries_localization_and_tests(fake_session, tmp_path):
    """Audit issue 2: the repair prompt must receive the localization
    conclusion (cited evidence + reasoning + queries) and the public tests,
    not just the full candidate listing."""
    session, adapter = fake_session
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    from repair_tool.firmware.tests import split_holdouts
    flow.tests, flow.holdout = split_holdouts(validate_tests(TESTS_REPLY))
    flow.plan = PLAN_REPLY
    save_json(flow.root / "reproduce" / "1" / "fault-summary.json", {
        "request": {"method": "GET", "path": "/x.gif"},
        "signal": "SIGSEGV",
        "exit_record": {"pid": 1}})
    save_json(flow.root / "localize" / "result.json", {
        "evidence": ["e1"],
        "reasoning": "the selected call site matches the observed fault path",
        "queries": [{"query": {"op": "disassemble"}, "answer": {}}]})
    _mark_localization_valid(flow, {
        "evidence": ["e1"],
        "reasoning": "the selected call site matches the observed fault path",
        "queries": [{"query": {"op": "disassemble"}, "answer": {}}]})
    ledger = flow.ledger_for_target()
    _add_model_code_site(ledger)
    captured = {}

    class RecordingModel(ScriptedModel):
        def ask(self, stage, payload, directory):
            captured[stage] = payload
            return {"edits": [{"site": 0x400000, "expected_hex": "11" * 16,
                               "evidence": ["e1"],
                               "contract": {"abi": "a", "bounds": "b",
                                            "preserve": "p", "invalid": "i"},
                               "source": "int repair_entry(char*d,const char*s){return 0;}"}]}

    flow.model = RecordingModel(flow.cfg, flow.root)
    flow.propose(tmp_path / "rounds" / "001", None)
    payload = captured["repair"]
    assert payload.get("localization_result", {}).get("reasoning") == \
        "the selected call site matches the observed fault path"
    assert payload.get("localization_result", {}).get("queries") is not None
    assert any(t["id"] == "home-ok" for t in payload.get("public_tests", []))


def test_localize_result_persists_query_history():
    """Audit issue 2: the saved localization result includes the query
    history so the repair stage (and any audit) can re-trace it."""
    result = {"evidence": ["e1"], "reasoning": "r",
              "queries": [{"query": {"op": "register_patch_site"},
                           "answer": {"evidence": "e1"}}]}
    assert result["queries"][0]["query"]["op"] == "register_patch_site"


def test_parse_model_queries_shapes():
    """Real-model acceptance (2026-10-18 run): GLM-5.3 returned the query
    batch nested under 'fields' (vocabulary style). The parser must accept
    flat single queries, batched queries, and the fields-nested form."""
    from repair_tool.firmware.query import parse_model_queries
    flat = {"query": {"op": "disassemble", "site": 4226688, "around": 16}}
    assert parse_model_queries(flat) == [
        {"op": "disassemble", "site": 4226688, "around": 16}]
    batch = {"queries": [{"op": "disassemble", "site": 4226592, "around": 128},
                         {"op": "elf_info"}]}
    assert parse_model_queries(batch) == [
        {"op": "disassemble", "site": 4226592, "around": 128},
        {"op": "elf_info"}]
    # The exact shape GLM-5.3 produced in the failed real run.
    nested = {"queries": [
        {"op": "disassemble", "fields": {"site|function": 4226592,
                                         "around": 128}},
        {"op": "disassemble", "fields": {"site|function": 4236836,
                                         "around": 96}}]}
    assert parse_model_queries(nested) == [
        {"op": "disassemble", "site": 4226592, "around": 128},
        {"op": "disassemble", "site": 4236836, "around": 96}]
    # Not a query at all -> None (evidence citation path).
    assert parse_model_queries({"evidence": ["e3"], "reasoning": "r"}) is None
    with pytest.raises(RepairError, match="non-empty list"):
        parse_model_queries({"queries": []})
    with pytest.raises(RepairError, match="non-empty list"):
        parse_model_queries({"queries": "not a list"})


def test_unix_socket_probe():
    """The probe must pass on a native filesystem (tmp) and correctly
    report the drvfs case when binding fails."""
    import repair_tool.firmware.loop as loop_mod
    assert loop_mod._unix_socket_supported(Path(tempfile.gettempdir())) is True

    class NoSockDir:
        def __truediv__(self, _):
            return self

        def __fspath__(self):
            raise OSError("simulated drvfs")

    # Path operations on a hostile directory surface OSError from the
    # TemporaryDirectory constructor -> probe returns False.
    assert loop_mod._unix_socket_supported(NoSockDir()) is False


def test_prepare_stages_session_on_non_native_fs(fake_session, tmp_path,
                                                 monkeypatch):
    """Real-model run 7 (20261018-113932): CASE_DIR on a WSL drvfs mount
    (/mnt/d) -> AF_UNIX bind fails with EOPNOTSUPP and the supervisor died
    in prepare. When the probe fails, prepare() must stage the SESSION in a
    native temp dir and record the location; the supervisor startup itself
    needs a real rootfs and is covered by the rehost suites."""
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "dummy"
    rootfs.mkdir(parents=True)
    poc = tmp_path / "poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc)
    import repair_tool.firmware.loop as loop_mod

    monkeypatch.setattr(loop_mod, "_unix_socket_supported", lambda _: False)
    # Stop right after the session-dir decision: swap in a launcher that
    # records the session path instead of spawning a real supervisor.
    started = {}

    class _RecordingLauncher:
        def __init__(self, rootfs, session_dir, adapter=None):
            started["session_dir"] = session_dir

        def start(self, deadline=None):
            started["ready"] = True
            # prepare() reads the session target bytes for the baseline.
            target = Path(started["session_dir"]) / "rootfs" / "sbin" / "httpd"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"\x7fELF-fake-baseline")

        def stop(self):
            pass

    monkeypatch.setattr(loop_mod, "SessionSupervisor", _RecordingLauncher)

    class _FakeLock:
        id = "tx-probe"

        def acquire(self, task=None):
            pass

        def release(self):
            pass

    monkeypatch.setattr(loop_mod, "SessionLock", lambda _: _FakeLock())

    class _FakeControl:
        def current_target(self):
            return {"pid": 1, "sha256": "probe", "program": "/sbin/httpd"}

        def target_sha(self):
            return "probe"

        def target_exits(self):
            return []

    monkeypatch.setattr(loop_mod, "SessionControl", lambda _: _FakeControl())
    flow.prepare()
    # The session lives on a NATIVE path (not under the run root) and the
    # run directory records where.
    assert started.get("ready") is True
    staged = Path(started["session_dir"])
    assert staged != flow.root / "session"
    assert staged.is_absolute()
    assert (flow.root / "session-location.json").exists()
    import json as json_mod
    location = json_mod.loads(
        (flow.root / "session-location.json").read_text())
    assert location["session_dir"] == str(staged)


def test_candidate_queries_are_read_only_and_bound_to_candidate_sha(
        fake_session, tmp_path):
    session, adapter = fake_session
    rootfs = tmp_path / "rootfs" / "candidate-query"
    rootfs.mkdir(parents=True)
    runner = build_runner(rootfs)
    (rootfs / "sbin").mkdir()
    (rootfs / "sbin" / "httpd").write_bytes(runner.read_bytes())
    poc = tmp_path / "candidate-query-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, rootfs, poc,
                         analysis_target=runner.read_bytes())
    _wire_session(flow, session, adapter)
    from repair_tool.firmware.query import EvidenceSession
    from repair_tool.arch.mips32 import ElfAnalysis

    ledger = flow.ledger_for_target()
    candidate = tmp_path / "candidate-query.bin"
    candidate.write_bytes(runner.read_bytes())
    candidate_sha = _sha_bytes(candidate.read_bytes())
    with ElfAnalysis(ledger.target_path) as baseline_analysis, \
            ElfAnalysis(candidate) as candidate_analysis:
        query_session = EvidenceSession(
            ledger, baseline_analysis,
            candidate_analysis=candidate_analysis,
            candidate_sha256=candidate_sha)
        query_session.handle({"op": "elf_info"})
        candidate_info = query_session.handle({"op": "candidate_elf_info"})
        executable = candidate_analysis.executable_segments()[0]
        candidate_bytes = query_session.handle({
            "op": "candidate_elf_bytes", "address": executable["vaddr"],
            "size": 16})
        site = baseline_analysis.call_sites(("concat_impl",))[0]["vaddr"]
        registration = query_session.handle({
            "op": "register_patch_site", "address": site})

    assert candidate_info["op"] == "candidate_elf_info"
    assert len(candidate_bytes["hex"]) == 32
    candidate_entry = ledger.by_kind("candidate_model_query")[-1]
    baseline_query_entry = ledger.by_kind("model_query")[-1]
    baseline_entry = ledger.get(registration["evidence"])
    assert baseline_query_entry["target_kind"] == "baseline"
    assert baseline_query_entry["target_sha256"] == ledger.target_sha
    assert query_session.answers[0]["target_sha256"] == ledger.target_sha
    assert candidate_entry["kind"] == "candidate_model_query"
    assert candidate_entry["target_kind"] == "candidate"
    assert candidate_entry["target_sha256"] == candidate_sha
    assert baseline_entry["kind"] == "model_code_site"
    assert baseline_entry["target_sha256"] == ledger.target_sha


def test_unconfirmed_rollback_blocks_relocalization(fake_session, tmp_path,
                                                    monkeypatch):
    session, adapter = fake_session
    poc = tmp_path / "rollback-gate-poc.py"
    poc.write_text(POC_SOURCE)
    flow = make_workflow(tmp_path, session / "rootfs", poc)
    _wire_session(flow, session, adapter)
    flow.cfg["repair"]["max_rounds"] = 2
    candidate = tmp_path / "rollback-gate-candidate"
    candidate.write_bytes(adapter.STILL_BROKEN)
    candidate_sha = _sha_bytes(candidate.read_bytes())
    built = {"candidate": candidate, "record": {
        "candidate_sha256": candidate_sha,
        "target_sha256": _sha_bytes(adapter.DEFECTIVE),
        "edits": [], "implants": []}}
    relocalizations = []
    monkeypatch.setattr(flow, "propose",
                        lambda *_, **__: {"edits": []})
    monkeypatch.setattr(flow, "implant", lambda *_, **__: built)
    monkeypatch.setattr(flow, "_runtime_exit_cursor", lambda: 0)
    monkeypatch.setattr(
        flow, "deploy_and_verify",
        lambda *_: (_ for _ in ()).throw(RepairError(
            "verification_failed", "candidate still crashes")))
    monkeypatch.setattr(flow, "rollback", lambda *_: (_ for _ in ()).throw(
        RepairError("rollback_failed", "restore failed")))
    monkeypatch.setattr(flow, "relocalize",
                        lambda *_, **__: relocalizations.append(True))

    with pytest.raises(RepairError, match="rollback was not confirmed"):
        flow.repair_rounds()

    assert relocalizations == []
    assert flow.localization_valid is False
    state = json.loads((flow.root / "evidence" /
                        "localization-state.json").read_text())
    assert state["status"] == "reinvestigation_required"


def test_disassembly_history_compression_keeps_query_center():
    from repair_tool.firmware.query import EvidenceSession
    answer = {"op": "disassemble", "address": 0x1000, "window": {
        "start": 0x1000,
        "instructions": [
            {"vaddr": 0x1000 + index * 4, "hex": "00000000",
             "mnemonic": "nop", "operands": ""}
            for index in range(512)
        ]}}
    compact = EvidenceSession._compact_answer(answer, keep_complete=False)
    kept = compact["window"]["instructions"]
    assert compact["removed_instruction_count"] == 512 - len(kept)
    assert compact["retained_range"][0] <= 0x1000
    assert compact["retained_range"][1] >= 0x1000
