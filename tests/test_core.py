from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
import yaml

from repair_tool.config import DEFAULTS, RepairError, load_config
from repair_tool.evidence import fingerprint, parse_asan, read_requested
from repair_tool.execution import Runner, artifact_inventory, binding_evidence, build_plan, child_env, expand
from repair_tool.model import redact_data
from repair_tool.patching import apply_patch
from repair_tool.storage import clean_artifacts, fresh_project, inventory, safe_file, snapshot
from repair_tool.workflow import Workflow, write_model_files
from elf_fixture import elf_bytes


def test_inline_key_loading_and_saved_config_redaction(case, monkeypatch):
    from repair_tool.config import model_secret, public_config
    from repair_tool.model import ModelClient
    path, _ = case
    data = yaml.safe_load(path.read_text())
    data["model"]["api_key"] = "test-inline-credential"
    path.write_text(yaml.safe_dump(data))
    monkeypatch.setenv("REPAIR_API_KEY", "other-env-credential")
    cfg = load_config(path)
    assert model_secret(cfg) == "test-inline-credential"
    assert ModelClient(cfg, path.parent).secret == "test-inline-credential"
    saved = public_config(cfg)
    assert saved["model"]["api_key"] is None
    assert "test-inline-credential" not in json.dumps(saved)
    cfg["model"]["api_key"] = None
    assert model_secret(cfg) == "other-env-credential"


def test_localization_failure_uses_repair_exit_code():
    from repair_tool.cli import exit_code

    assert exit_code("localization_failed") == 3


@pytest.mark.parametrize("value", [123, "", "   ", False])
def test_invalid_inline_key(case, value):
    path, _ = case
    data = yaml.safe_load(path.read_text())
    data["model"]["api_key"] = value
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(RepairError, match="model.api_key"):
        load_config(path)


def test_adapter_placeholder_path_rejected_before_writing(tmp_path):
    with pytest.raises(RepairError, match="without placeholders"):
        write_model_files(tmp_path, [{"path": "{adapter}/launch.py", "content": "print('poc')"}])
    assert not list(tmp_path.iterdir())


def test_adapter_missing_command_target_rejected(tmp_path):
    flow = object.__new__(Workflow)
    flow.root = tmp_path
    flow.poc = tmp_path / "poc.c"
    flow.external = None
    flow.adapter = {"source": "model", "command": ["python3", "{adapter}/launch.py"]}
    with pytest.raises(RepairError, match="missing helper"):
        flow.poc_command(tmp_path / "project")


def test_adapter_relative_file_matches_expanded_command(tmp_path):
    flow = object.__new__(Workflow)
    flow.root = tmp_path
    flow.poc = tmp_path / "poc.c"
    flow.external = None
    flow.adapter = {"source": "model", "command": ["python3", "{adapter}/helpers/launch.py", "{project}", "{poc}"]}
    write_model_files(tmp_path / "adapter", [{"path": "helpers/launch.py", "content": "print('poc')"}])
    command = flow.poc_command(tmp_path / "project")
    assert command[0] == "python3"
    assert [Path(arg) for arg in command[1:]] == [
        tmp_path / "adapter" / "helpers" / "launch.py",
        tmp_path / "project", flow.poc]


@pytest.mark.parametrize("source", ["model", "user"])
@pytest.mark.parametrize("arg", ["{poc}/poc.c", "-I{poc}/include", "{poc}\\payload.bin"])
def test_poc_file_cannot_be_used_as_directory_before_execution(tmp_path, source, arg):
    flow = object.__new__(Workflow)
    flow.cfg = {"validation": {"baseline_runs": 1, "poc_timeout_seconds": 10}}
    flow.adapter = {"source": source, "command": ["cc", arg]}
    flow.root = tmp_path
    flow.poc = tmp_path / "poc.c"
    flow.external = None
    calls = []
    flow.execute = lambda *a, **k: calls.append(a)
    with pytest.raises(RepairError, match="full path to the original PoC file") as caught:
        flow.run_poc(tmp_path, {"artifacts": {}}, tmp_path / "logs", baseline=True)
    assert caught.value.status == "model_output_invalid"
    assert "{poc_dir}/filename" in str(caught.value)
    assert not calls and not (tmp_path / "logs").exists()


def test_poc_directory_expands_in_adapter_and_test_commands(tmp_path):
    flow = object.__new__(Workflow)
    flow.root = tmp_path
    flow.poc = tmp_path / "copied poc" / "poc.c"
    flow.external = None
    project = tmp_path / "project"
    flow.adapter = {"source": "model", "command": ["cc", "{poc}", "{poc_dir}/payload.c"]}
    assert flow.poc_command(project) == ["cc", str(flow.poc), str(flow.poc.parent) + "/payload.c"]
    suite = tmp_path / "suite"
    assert expand(["python3", "{suite}/test.py", "{poc}", "{poc_dir}"],
                  project, flow.poc, suite=suite) == [
                      "python3", str(suite) + "/test.py", str(flow.poc), str(flow.poc.parent)]


@pytest.fixture
def case(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.c").write_bytes(b"int f(void) {\n    return 0;\n}\n")
    poc = tmp_path / "poc"
    poc.mkdir()
    (poc / "poc.py").write_text("print('poc')\n")
    cfg = {"project": {"path": "./project"}, "poc": {"path": "./poc/poc.py"},
           "model": {"base_url": "https://example.test/v1", "name": "test-model"}}
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path, project


def test_config_resolves_against_yaml(case, monkeypatch, tmp_path):
    path, project = case
    monkeypatch.chdir(project)
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    cfg = load_config(path)
    assert cfg["project"]["path"] == str(project)
    assert cfg["repair"]["max_rounds"] == 5
    assert cfg["repair"]["firmware_query_max_output_tokens"] == 32768
    assert cfg["repair"]["firmware_query_reasoning_effort"] == "low"
    assert cfg["repair"][
        "firmware_length_recovery_reasoning_effort"] == "low"
    assert cfg["repair"]["firmware_decisive_site_inspections"] == 2
    assert cfg["repair"]["firmware_decisive_site_discoveries"] == 2
    assert cfg["repair"]["firmware_registration_max_output_tokens"] == 8192
    assert cfg["repair"]["firmware_registration_reasoning_effort"] == "low"
    assert cfg["repair"]["firmware_length_differential"] is False
    assert cfg["repair"]["firmware_length_probe_limit"] == 8


def test_software_layer_supplies_model_credentials(case, monkeypatch, tmp_path):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(yaml.safe_dump({
        "model": {"api_key": "global-key", "retries": 1,
                  "reasoning_effort": "high"}}))
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    cfg = load_config(path)
    # Keys the case does not set come from the software layer...
    assert cfg["model"]["api_key"] == "global-key"
    assert cfg["model"]["retries"] == 1
    assert cfg["model"]["reasoning_effort"] == "high"
    # ...while keys the case sets stay case-owned.
    assert cfg["model"]["base_url"] == "https://example.test/v1"
    assert cfg["model"]["name"] == "test-model"


def test_case_layer_overrides_software_layer(case, monkeypatch, tmp_path):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(yaml.safe_dump({
        "model": {"name": "global-model", "retries": 1}}))
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    case_cfg = yaml.safe_load(path.read_text())
    case_cfg["model"]["name"] = "case-model"
    path.write_text(yaml.safe_dump(case_cfg))
    cfg = load_config(path)
    assert cfg["model"]["name"] == "case-model"      # case wins
    assert cfg["model"]["retries"] == 1              # global default applies


def test_software_layer_rejects_path_sections(case, monkeypatch, tmp_path):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(yaml.safe_dump({"output": {"directory": "/tmp/x"}}))
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    with pytest.raises(RepairError, match="not allowed"):
        load_config(path)


def test_software_layer_disabled_by_empty_env(case, monkeypatch, tmp_path):
    path, _ = case
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    cfg = load_config(path)
    assert cfg["model"]["name"] == "test-model"     # only case layer applied


def test_software_layer_invalid_is_hard_error(case, monkeypatch, tmp_path):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(yaml.safe_dump({"model": {"unknown_key": 1}}))
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    with pytest.raises(RepairError):
        load_config(path)


@pytest.mark.parametrize("content", ["false", "0", "[]", "''"])
def test_software_layer_rejects_non_mapping_root(case, monkeypatch, tmp_path, content):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text(content)
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    with pytest.raises(RepairError, match="root must be a mapping"):
        load_config(path)


@pytest.mark.parametrize("directory", [False, True])
def test_explicit_software_config_must_be_a_file(case, monkeypatch, tmp_path, directory):
    path, _ = case
    global_cfg = tmp_path / "missing.yaml"
    if directory:
        global_cfg.mkdir()
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    with pytest.raises(RepairError, match="existing file"):
        load_config(path)


def test_empty_software_config_is_optional(case, monkeypatch, tmp_path):
    path, _ = case
    global_cfg = tmp_path / "global.yaml"
    global_cfg.write_text("# no overrides\n")
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", str(global_cfg))
    assert load_config(path)["model"]["name"] == "test-model"


@pytest.mark.parametrize("section,key,value", [
    ("repair", "max_rounds", 0), ("repair", "max_rounds", True),
    ("validation", "generate_tests", "false"), ("build", "command", "make"),
    ("poc", "args", [1]), ("build", "mode", "unknown"),
    ("model", "base_url", "http://remote.test/v1"),
    ("model", "base_url", "https://key:secret@example.test/v1"),
    ("model", "stream", "true"), ("model", "total_timeout_seconds", 0),
    ("model", "reasoning_effort", {}),
    ("repair", "firmware_query_reasoning_effort", "medium"),
    ("repair", "firmware_query_reasoning_effort", "xhigh"),
    ("repair", "firmware_length_recovery_reasoning_effort", "medium"),
    ("repair", "firmware_registration_reasoning_effort", "medium"),
    ("repair", "firmware_query_reasoning_effort", "urgent"),
])
def test_invalid_config(case, section, key, value):
    path, _ = case
    cfg = yaml.safe_load(path.read_text())
    cfg.setdefault(section, {})[key] = value
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(RepairError):
        load_config(path)


def test_output_cannot_be_inside_source(case):
    path, _ = case
    cfg = yaml.safe_load(path.read_text())
    cfg["output"] = {"directory": "project/results"}
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(RepairError, match="contain"):
        load_config(path)


def test_unknown_config(case):
    path, _ = case
    cfg = yaml.safe_load(path.read_text())
    cfg["case"] = {"id": "unnecessary"}
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(RepairError, match="Unknown"):
        load_config(path)


def test_independent_snapshots_and_old_artifacts(tmp_path):
    original = tmp_path / "source"
    original.mkdir()
    (original / "main.c").write_text("original")
    (original / "oldbin").write_bytes(b"\x7fELF__asan_init")
    (original / "old.o").write_bytes(b"object")
    before = inventory(original)
    baseline, first, second = [tmp_path / name for name in ("baseline", "first", "second")]
    snapshot(original, baseline)
    removed = fresh_project(baseline, first)
    fresh_project(baseline, second)
    (first / "main.c").write_text("patched")
    assert "oldbin" in removed and "old.o" in removed
    assert (second / "main.c").read_text() == "original"
    assert inventory(original) == before
    assert (baseline / "oldbin").exists()


def test_snapshot_keeps_local_git_metadata(tmp_path):
    original = tmp_path / "source"
    (original / ".git").mkdir(parents=True)
    (original / ".git" / "HEAD").write_text("ref: refs/heads/main")
    snapshot(original, tmp_path / "copy")
    assert (tmp_path / "copy" / ".git" / "HEAD").read_text() == "ref: refs/heads/main"


def test_external_worktree_metadata_rejected(tmp_path):
    original = tmp_path / "source"
    original.mkdir()
    (original / ".git").write_text("gitdir: ../other-repo/.git/worktrees/source")
    with pytest.raises(RepairError, match="worktree"):
        snapshot(original, tmp_path / "copy")


@pytest.mark.skipif(os.name == "nt", reason="Linux symlink permissions")
def test_external_symlink_refused(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.c"
    outside.write_text("external")
    (root / "bad.c").symlink_to(outside)
    with pytest.raises(RepairError, match="symlink"):
        snapshot(root, tmp_path / "copy")


@pytest.mark.parametrize("relative", ["../outside.c", "/outside.c", "a/../../outside.c", "a\\b.c"])
def test_path_traversal(tmp_path, relative):
    with pytest.raises(RepairError):
        safe_file(tmp_path, relative)


PATCH_A = "--- a/a.c\n+++ b/a.c\n@@ -1,3 +1,3 @@\n int f(void) {\n-    return 0;\n+    return 1;\n }\n"


def test_multifile_exact_patch(case):
    _, root = case
    (root / "a.h").write_bytes(b"#define VALUE 0\n")
    diff = PATCH_A + "--- a/a.h\n+++ b/a.h\n@@ -1 +1 @@\n-#define VALUE 0\n+#define VALUE 1\n"
    assert apply_patch(root, diff, {"a.c", "a.h"}, 4) == ["a.c", "a.h"]
    assert "return 1" in (root / "a.c").read_text()


def test_invalid_second_hunk_does_not_partially_apply(case):
    _, root = case
    (root / "a.h").write_text("original\n")
    before = inventory(root)
    diff = PATCH_A + "--- a/a.h\n+++ b/a.h\n@@ -1 +1 @@\n-other\n+new\n"
    with pytest.raises(RepairError):
        apply_patch(root, diff, {"a.c", "a.h"}, 20)
    assert inventory(root) == before


@pytest.mark.parametrize("diff,allowed,limit", [
    (PATCH_A, set(), 20), (PATCH_A, {"a.c"}, 1),
    (PATCH_A.replace("return 1", "exit(0)"), {"a.c"}, 20),
    (PATCH_A.replace("return 1", "__attribute__((no_sanitize_address))"), {"a.c"}, 20),
    (PATCH_A.replace("return 0", "return 99"), {"a.c"}, 20),
    (PATCH_A.replace("b/a.c", "b/other.c"), {"a.c"}, 20),
    (PATCH_A.replace("a/a.c", "a/../a.c").replace("b/a.c", "b/../a.c"), {"../a.c"}, 20),
])
def test_bad_patches(case, diff, allowed, limit):
    _, root = case
    before = inventory(root)
    with pytest.raises(RepairError):
        apply_patch(root, diff, allowed, limit)
    assert inventory(root) == before


def test_new_file_offset_is_derived_from_body(case):
    _, root = case
    assert apply_patch(root, PATCH_A.replace("+1,3", "+2,3"), {"a.c"}, 20) == ["a.c"]
    assert (root / "a.c").read_text() == "int f(void) {\n    return 1;\n}\n"


def test_second_hunk_ignores_new_offset_and_applies_whole_file(tmp_path):
    path = tmp_path / "a.c"
    path.write_bytes(b"first\nmiddle\nlast\n")
    diff = ("--- a/a.c\n+++ b/a.c\n@@ -1 +1,2 @@\n-first\n+changed\n+inserted\n"
            "@@ -3 +5 @@\n-last\n+updated\n")
    assert apply_patch(tmp_path, diff, {"a.c"}, 5) == ["a.c"]
    assert path.read_text() == "changed\ninserted\nmiddle\nupdated\n"


@pytest.mark.parametrize("original,start,expected", [
    ("first\nsecond\n", 1, "first\ninserted\nsecond\n"),
    ("first\n", 0, "inserted\nfirst\n"),
    ("first\nsecond\n", 2, "first\nsecond\ninserted\n"),
    ("", 0, "inserted\n"),
])
def test_pure_insertion_anchors_after_old_start(tmp_path, original, start, expected):
    path = tmp_path / "a.c"
    path.write_bytes(original.encode("utf-8"))
    diff = f"--- a/a.c\n+++ b/a.c\n@@ -{start},0 +1,1 @@\n+inserted\n"
    apply_patch(tmp_path, diff, {"a.c"}, 1)
    assert path.read_text() == expected


@pytest.mark.parametrize("body,error", [
    ("@@ -1 +1 @@\n+inserted\n", "declares existing lines"),
    ("@@ -1,0 +1,0 @@\n", "no changes or context"),
    ("@@ -3,0 +1 @@\n+inserted\n", "out-of-range"),
    ("@@ -0 +1 @@\n-first\n+changed\n", "out-of-range"),
    ("@@ -2,0 +1 @@\n+inserted\n@@ -1 +1 @@\n-first\n+changed\n", "Overlapping"),
    ("@@ -1 +1,2 @@\n-first\n+changed\n+inserted\n@@ -2 +4 @@\n-wrong\n+changed\n", "baseline="),
    ("@@ -1,99 +1,99 @@\n-first\n-second\n-extra\n+changed\n", "baseline ends"),
])
def test_invalid_hunk_body_or_anchor_never_writes_partial_file(tmp_path, body, error):
    path = tmp_path / "a.c"
    original = b"first\nsecond\n"
    path.write_bytes(original)
    with pytest.raises(RepairError, match=error):
        apply_patch(tmp_path, "--- a/a.c\n+++ b/a.c\n" + body, {"a.c"}, 20)
    assert path.read_bytes() == original


def test_body_counts_enforce_change_limit_despite_small_headers(tmp_path):
    path = tmp_path / "a.c"
    path.write_bytes(b"old\n")
    diff = "--- a/a.c\n+++ b/a.c\n@@ -1,0 +1,0 @@\n-old\n+new\n+more\n"
    with pytest.raises(RepairError, match="Changed lines 3"):
        apply_patch(tmp_path, diff, {"a.c"}, 2)
    assert path.read_text() == "old\n"


def test_build_change_reported(case):
    _, root = case
    (root / "Makefile").write_text("all:\n\ttrue\n")
    patch = "--- a/Makefile\n+++ b/Makefile\n@@ -1,2 +1,2 @@\n all:\n-\ttrue\n+\tfalse\n"
    with pytest.raises(RepairError) as caught:
        apply_patch(root, patch, {"Makefile"}, 10)
    assert caught.value.status == "needs_build_change"


def test_existing_test_source_protected(case):
    _, root = case
    (root / "tests").mkdir()
    (root / "tests" / "a.c").write_text((root / "a.c").read_text())
    with pytest.raises(RepairError):
        apply_patch(root, PATCH_A.replace("a/a.c", "a/tests/a.c").replace("b/a.c", "b/tests/a.c"), {"tests/a.c"}, 20)


def test_no_newline_patch(tmp_path):
    (tmp_path / "a.c").write_bytes(b"old")
    diff = "--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
    apply_patch(tmp_path, diff, {"a.c"}, 2)
    assert (tmp_path / "a.c").read_bytes() == b"new"


def test_child_environment_hides_credentials(monkeypatch):
    monkeypatch.setenv("REPAIR_API_KEY", "secret-key")
    monkeypatch.setenv("OTHER_TOKEN", "other-secret")
    monkeypatch.setenv("LD_PRELOAD", "/malicious.so")
    env = child_env("REPAIR_API_KEY")
    assert "REPAIR_API_KEY" not in env and "OTHER_TOKEN" not in env and "LD_PRELOAD" not in env
    assert "detect_leaks=0" in env["ASAN_OPTIONS"]


def test_asan_multifile_frames(case):
    _, root = case
    (root / "caller.c").write_text("caller")
    log = f"ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 1\n #0 0x123 in f {root.as_posix()}/a.c:2:3\n #1 0x456 in caller {root.as_posix()}/caller.c:8\n"
    first = parse_asan(log, root)
    second = parse_asan(log.replace("0x123", "0x999"), root)
    assert first["type"] == "heap-buffer-overflow"
    assert [f["file"] for f in first["frames"]] == ["a.c", "caller.c"]
    assert fingerprint(first) == fingerprint(second)


def test_requested_context_only_sources(case):
    _, root = case
    (root / "secret.env").write_text("secret")
    with pytest.raises(ValueError):
        read_requested(root, ["secret.env"], 1000)
    assert "a.c" in read_requested(root, [{"file": "a.c", "start_line": 1, "end_line": 3}], 1000)


def test_redaction_preserves_json_and_secret(monkeypatch):
    data = {"text": 'password="abc"; REPAIR_API_KEY=actual-secret', "patch": "int password=1;"}
    safe = redact_data(data, "actual-secret")
    assert "actual-secret" not in json.dumps(safe)
    assert json.loads(json.dumps(safe)) == safe


def test_build_discovery_and_override(case):
    path, root = case
    cfg = load_config(path)
    (root / "CMakeLists.txt").write_text("project(x)")
    kind, cmds = build_plan(cfg, root, Path(cfg["poc"]["path"]))
    assert kind == "cmake" and any("-fsanitize=address" in arg for arg in cmds[0])
    cfg["build"]["command"] = ["bash", "{project}/build.sh"]
    kind, cmds = build_plan(cfg, root, Path(cfg["poc"]["path"]))
    assert kind == "custom" and Path(cmds[0][1]) == root / "build.sh"


def test_binding_rejects_old_library_and_archive(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    old = tmp_path / "old.so"
    old.write_bytes(elf_bytes(3))
    fresh = root / "fresh"
    fresh.write_bytes(elf_bytes())
    archive = root / "lib.a"
    archive.write_bytes(b"!<arch>\n__asan_init")
    trace = tmp_path / "trace"
    trace.write_text(f'100 execve("{fresh.as_posix()}", ["fresh"], []) = 0\n')
    result = {"trace": str(trace)}
    assert binding_evidence(result, root, artifact_inventory(root))["passed"]
    trace.write_text(trace.read_text() + f'100 openat(AT_FDCWD, "{old.as_posix()}", O_RDONLY) = 4<{old.as_posix()}>\n'
                     f'100 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 4<{old.as_posix()}>, 0) = 0x7000\n')
    assert not binding_evidence(result, root, artifact_inventory(root))["passed"]
    trace.write_text(f'openat(AT_FDCWD, "{archive.as_posix()}", O_RDONLY) = 3<{archive.as_posix()}>\n')
    assert not binding_evidence(result, root, artifact_inventory(root))["passed"]


def test_fixed_tests_cannot_be_replaced(case):
    path, _ = case
    flow = Workflow(load_config(path))
    entry = {"id": "regression", "kind": "regression", "baseline": "pass", "basis": "API contract",
             "expected_cases": 1, "files": [{"path": "run.py", "content": "print('test')"}],
             "command": ["python3", "{suite}/run.py"]}
    flow.tests = flow.install_tests({"tests": [entry]}, "base")
    with pytest.raises(RepairError, match="unique"):
        flow.install_tests({"tests": [entry]}, "append")


def test_generated_test_cannot_fake_missing_result(case, monkeypatch):
    path, root = case
    flow = Workflow(load_config(path))
    directory = flow.root / "generated-tests" / "test"
    directory.mkdir(parents=True)
    (directory / "test.py").write_text("pass")
    test = {"id": "fake", "kind": "regression", "baseline": "pass", "expected_cases": 1,
            "directory": str(directory), "command": ["python3", "{suite}/test.py"]}
    def execute(command, project, log, timeout, extra_env=None, trace=False):
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("all okay")
        return {"passed": True, "log": str(log), "returncode": 0, "reason": None}
    monkeypatch.setattr(flow, "execute", execute)
    with pytest.raises(RepairError, match="Missing/invalid"):
        flow.generated_test(test, root, flow.root / "logs", False)


def test_integrity_guard_detects_fixed_test_change(case):
    path, _ = case
    flow = Workflow(load_config(path))
    fixed = flow.root / "generated-tests"
    fixed.mkdir()
    (fixed / "test.py").write_text("original")
    from repair_tool.workflow import fixed_inventory
    before = fixed_inventory([fixed])
    (fixed / "test.py").write_text("weakened")
    with pytest.raises(RepairError, match="Protected"):
        flow.guard(before)
