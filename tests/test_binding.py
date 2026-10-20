from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest

from elf_fixture import elf_bytes
from repair_tool.elf import elf_evidence
from repair_tool.execution import artifact_inventory, binding_evidence, instrumented, artifact_summary
from repair_tool.config import RepairError
from repair_tool.workflow import Workflow


@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
@pytest.mark.parametrize("defined", [False, True])
def test_valid_symbol_tables_include_undefined_references(tmp_path, bits, endian, defined):
    path = tmp_path / "target"
    path.write_bytes(elf_bytes(bits=bits, endian=endian, defined=defined))
    info = elf_evidence(path)
    assert info["asan"] and info["runtime_target"]
    assert info["asan_evidence"]["symbols"] == [
        {"name": "__asan_init", "section": "1" if defined else "SHN_UNDEF"}]


@pytest.mark.parametrize("payload", [b"\x7fELF__asan_init", b"!<arch>\n__asan_init",
                                     b"MZ__asan_init", elf_bytes()[:-1]])
def test_malformed_or_non_elf_is_rejected(tmp_path, payload):
    path = tmp_path / "bad"
    path.write_bytes(payload)
    assert not instrumented(path)
    assert not elf_evidence(path)["runtime_target"]


def test_appended_or_data_strings_do_not_count(tmp_path):
    path = tmp_path / "compiler"
    data = bytearray(elf_bytes(asan=False))
    # Put the spelling in the executable segment without adding any symbol.
    data[120:121] = b"_"  # Existing .text byte; table offsets remain intact.
    path.write_bytes(data + b"__asan_init __asan_report_load1 libasan.so.8")
    assert not instrumented(path)
    assert elf_evidence(path)["runtime_target"]


@pytest.mark.parametrize("needed", ["libasan.so.8", "libclang_rt.asan-x86_64.so"])
@pytest.mark.parametrize("sectionless", [False, True])
def test_needed_is_association_even_without_instrumentation(tmp_path, needed, sectionless):
    path = tmp_path / "linked_only"
    data = bytearray(elf_bytes(asan=False, needed=needed))
    if sectionless:
        struct.pack_into("<Q", data, 40, 0)  # e_shoff
        struct.pack_into("<HHH", data, 58, 0, 0, 0)
    path.write_bytes(data)
    info = elf_evidence(path)
    assert info["asan"] and info["runtime_target"]
    assert info["asan_evidence"] == {"needed": [needed], "symbols": []}


@pytest.fixture
def binaries(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for name, kind in [("fresh", 2), ("fresh.so", 3), ("fresh.o", 1)]:
        (root / name).write_bytes(elf_bytes(kind))
    (root / "lib.a").write_bytes(b"!<arch>\n__asan_init")
    (root.parent / "launcher").write_bytes(elf_bytes(asan=False))
    return root


def bind(root, trace, **extra):
    path = root.parent / "trace"
    path.write_text(trace)
    return binding_evidence({"trace": str(path), "cwd": str(root), **extra}, root, artifact_inventory(root))


def exec_line(path, pid=100):
    return f'{pid} execve("{path.as_posix()}", ["app"], []) = 0\n'


def load_line(path, pid=100, prot="PROT_READ|PROT_EXEC", result="0x7000"):
    return (f'{pid} openat(AT_FDCWD, "{path.as_posix()}", O_RDONLY) = 3<{path.as_posix()}>\n'
            f'{pid} mmap(NULL, 4096, {prot}, MAP_PRIVATE, 3<{path.as_posix()}>, 0) = {result}\n')


def test_inventory_distinguishes_runtime_targets(binaries):
    info = artifact_inventory(binaries)
    assert info["fresh.o"]["asan"] and not info["fresh.o"]["runtime_target"]
    assert not info["lib.a"]["runtime_target"]
    summary = artifact_summary(info)
    assert {t["path"] for t in summary["runtime_targets"]} == {"fresh", "fresh.so"}
    assert "sha256" not in json.dumps(summary)


@pytest.mark.parametrize("scenario", ["argv", "open", "object", "failed_exec", "failed_map", "read_map"])
def test_access_is_not_execution(binaries, scenario):
    fresh = binaries / "fresh"
    driver = exec_line(Path("/usr/bin/true"))
    traces = {
        "argv": f'100 execve("/usr/bin/true", ["true", "{fresh.as_posix()}"], []) = 0\n',
        "open": driver + f'100 openat(AT_FDCWD, "{fresh.as_posix()}", O_RDONLY) = 3<{fresh.as_posix()}>\n',
        "object": driver + load_line(binaries / "fresh.o"),
        "failed_exec": exec_line(fresh).replace("= 0", "= -1 ENOENT (No such file or directory)"),
        "failed_map": driver + load_line(binaries / "fresh.so", result="-1 ENOMEM (Cannot allocate memory)"),
        "read_map": driver + load_line(binaries / "fresh.so", prot="PROT_READ"),
    }
    result = bind(binaries, traces[scenario])
    assert not result["passed"]
    assert result["fresh_asan_targets"] == []
    if scenario == "argv":
        assert result["accessed_artifacts"] == []


def test_exec_and_same_process_dso_mapping_pass(binaries):
    trace = exec_line(binaries / "fresh") + load_line(binaries / "fresh.so")
    result = bind(binaries, trace, sanitizer_pids=[100], sanitizer_error=True)
    assert result["passed"]
    assert result["fresh_asan_targets"] == ["fresh", "fresh.so"]
    assert {r["kind"] for r in result["process_bindings"]} == {"exec", "load"}


def test_as_an_library_can_bind_to_python_driver(binaries):
    result = bind(binaries, exec_line(binaries.parent / "launcher") + load_line(binaries / "fresh.so"),
                  sanitizer_pids=[100], sanitizer_error=True)
    assert result["passed"]


def test_open_in_other_pid_is_not_load(binaries):
    trace = exec_line(Path("/usr/bin/python3")) + load_line(binaries / "fresh.so", pid=101)
    assert not bind(binaries, trace)["passed"]


def test_reporter_must_use_fresh_image_not_sibling_or_prior_exec(binaries):
    fresh = exec_line(binaries / "fresh")
    assert not bind(binaries, fresh + exec_line(Path("/usr/bin/true"), pid=101),
                    sanitizer_pids=[101], sanitizer_error=True)["passed"]
    assert not bind(binaries, fresh + exec_line(Path("/usr/bin/true")),
                    sanitizer_pids=[100], sanitizer_error=True)["passed"]
    assert not bind(binaries, fresh, sanitizer_error=True)["passed"]


def test_fork_inherits_and_exec_replaces_address_space(binaries):
    trace = exec_line(binaries / "fresh") + '100 clone(child_stack=NULL, flags=SIGCHLD) = 101\n'
    assert bind(binaries, trace, sanitizer_pids=[101], sanitizer_error=True)["passed"]
    trace += exec_line(Path("/usr/bin/true"), pid=101)
    assert not bind(binaries, trace, sanitizer_pids=[101], sanitizer_error=True)["passed"]


def test_unfinished_clone_exec_and_thread_shared_image(binaries):
    path = binaries / "fresh.so"
    trace = (exec_line(binaries.parent / "launcher") +
             '100 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) <unfinished ...>\n' +
             load_line(path, pid=101) + '<... clone resumed>) = 101\n')
    # Resumed lines must carry their PID when more than one process is traced.
    trace = trace.replace('<... clone resumed>', '100 <... clone resumed>')
    assert bind(binaries, trace, sanitizer_pids=[100], sanitizer_error=True)["passed"]
    path = binaries / "fresh"
    trace = f'100 execve("{path.as_posix()}", ["app"], [] <unfinished ...>\n100 <... execve resumed>) = 0\n'
    assert bind(binaries, trace)["passed"]
    assert not bind(binaries, trace.splitlines()[0] + "\n")["passed"]


def test_old_library_read_allowed_loaded_rejected(binaries):
    old = binaries.parent / "old.so"
    old.write_bytes(elf_bytes(3))
    fresh = exec_line(binaries / "fresh")
    assert bind(binaries, fresh + load_line(old).splitlines()[0] + "\n")["passed"]
    result = bind(binaries, fresh + load_line(old))
    assert not result["passed"] and result["foreign_asan_targets"] == [str(old.resolve())]
    old.write_bytes(elf_bytes(3, asan=False) + b"__asan_init")
    assert bind(binaries, fresh + load_line(old))["passed"]


def test_runtime_name_does_not_exempt_old_library(binaries):
    old = binaries.parent / "libasan.so.8"
    old.write_bytes(elf_bytes(3))
    assert not bind(binaries, exec_line(binaries / "fresh") + load_line(old))["passed"]


def test_hash_change_and_incomplete_trace_rejected(binaries):
    artifact = artifact_inventory(binaries)
    trace = binaries.parent / "trace"
    trace.write_text(exec_line(binaries / "fresh"))
    (binaries / "fresh").write_bytes(elf_bytes() + b"new")
    result = binding_evidence({"trace": str(trace)}, binaries, artifact)
    assert result["hash_mismatches"] == ["fresh"] and not result["passed"]
    assert not bind(binaries, trace.read_text(), reason="output_limit")["passed"]


def test_dirfd_chdir_dup_close_and_cloexec(binaries):
    launcher = exec_line(binaries.parent / "launcher")
    trace = (launcher + f'100 openat(AT_FDCWD, "{binaries.as_posix()}", O_RDONLY|O_DIRECTORY) = 4\n'
             '100 openat(4, "fresh.so", O_RDONLY) = 3\n'
             '100 dup(3) = 5\n100 close(3) = 0\n'
             '100 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 5, 0) = 0x7000\n')
    assert bind(binaries, trace)["passed"]
    trace = (launcher + f'100 chdir("{binaries.as_posix()}") = 0\n'
             '100 openat(AT_FDCWD, "fresh.so", O_RDONLY|O_CLOEXEC) = 3\n' + launcher +
             '100 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3, 0) = 0x7000\n')
    assert not bind(binaries, trace)["passed"]
    trace = launcher + f'100 execveat(AT_FDCWD, "{(binaries / "fresh").as_posix()}", ["fresh"], [], 0) = 0\n'
    assert bind(binaries, trace)["passed"]


def test_deleted_mapped_file_fails_closed(binaries):
    old = binaries.parent / "old.so"
    trace = exec_line(binaries / "fresh") + load_line(old)
    result = bind(binaries, trace)
    assert not result["passed"] and "runtime_file_unavailable" in result["failure_categories"]


def test_clone_fs_shares_directory_changes_with_parent(binaries):
    subdir = binaries / "child-cwd"
    subdir.mkdir()
    (subdir / "library.so").write_bytes(elf_bytes(3))
    trace = (exec_line(binaries.parent / "launcher") +
             '100 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FS|CLONE_THREAD) = 101\n' +
             f'101 chdir("{subdir.as_posix()}") = 0\n' +
             '100 openat(AT_FDCWD, "library.so", O_RDONLY) = 3\n' +
             '100 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3, 0) = 0x7000\n')
    assert bind(binaries, trace)["passed"]
    assert not bind(binaries, trace.replace("CLONE_FS|", ""))["passed"]


def test_replacement_failure_is_saved(binaries, tmp_path):
    flow = object.__new__(Workflow)
    flow.cfg = {"validation": {"baseline_runs": 1, "poc_runs": 1, "poc_timeout_seconds": 10}}
    flow.adapter = {"source": "user", "command": ["{project}/fresh"]}
    flow.poc = tmp_path / "poc.py"
    flow.external = None
    flow.root = tmp_path
    build = {"artifacts": artifact_inventory(binaries)}
    trace = tmp_path / "trace"
    trace.write_text(exec_line(binaries / "fresh"))
    log = tmp_path / "execution.log"
    log.write_text("")
    def execute(*args, **kwargs):
        (binaries / "fresh").write_bytes(elf_bytes() + b"replaced")
        return {"trace": str(trace), "log": str(log), "passed": True, "command": ["fresh"],
                "returncode": 0, "reason": None, "sanitizer_error": False}
    flow.execute = execute
    with pytest.raises(RepairError) as raised:
        flow.run_poc(binaries, build, tmp_path / "logs", baseline=False)
    saved = json.loads((tmp_path / "logs/poc-results.json").read_text())[0]
    assert "preexisting_artifact_replaced" in saved["binding"]["failure_categories"]
    assert saved["binding"]["hash_mismatches"] == ["fresh"]
    assert raised.value.status == "binding_failed"


@pytest.mark.skipif(os.name != "posix", reason="Quote characters require POSIX filenames")
def test_chdir_dirfd_and_escaped_paths(binaries):
    subdir = binaries / "sub space"
    subdir.mkdir()
    target = subdir / 'lib"quote.so'
    target.write_bytes(elf_bytes(3))
    # -yy provides resolved descriptors, including C-escaped path bytes.
    encoded = target.as_posix().replace('"', '\\"')
    trace = (exec_line(Path("/usr/bin/python3")) +
             f'100 chdir("{subdir.as_posix()}") = 0\n' +
             f'100 openat(AT_FDCWD, "lib\\"quote.so", O_RDONLY) = 3<{encoded}>\n' +
             f'100 mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE, 3<{encoded}>, 0) = 0x7000\n')
    # A quote is illegal in Windows filenames; this case runs on POSIX only.
    assert bind(binaries, trace)["passed"]


def test_failed_poc_audit_saved_and_feedback_omits_hashes(binaries, tmp_path):
    flow = object.__new__(Workflow)
    flow.cfg = {"validation": {"baseline_runs": 1, "poc_runs": 1, "poc_timeout_seconds": 10}}
    flow.adapter = {"source": "user", "command": ["true", "{project}/fresh"]}
    flow.poc = tmp_path / "poc.py"
    flow.external = None
    flow.root = tmp_path
    trace = tmp_path / "trace"
    trace.write_text(f'100 execve("/usr/bin/true", ["true", "{(binaries / "fresh").as_posix()}"], []) = 0\n')
    log = tmp_path / "execution.log"
    log.write_text("launcher completed without executing the target\n")
    flow.execute = lambda *a, **k: {"trace": str(trace), "log": str(log), "passed": True,
        "command": ["true"], "returncode": 0, "reason": None, "sanitizer_error": False}
    build = {"artifacts": artifact_inventory(binaries)}
    with pytest.raises(RepairError) as raised:
        flow.run_poc(binaries, build, tmp_path / "logs", baseline=True)
    assert raised.value.status == "binding_failed"
    assert json.loads(str(raised.value))["log_excerpt"] == log.read_text()
    saved = json.loads((tmp_path / "logs/poc-results.json").read_text())
    assert saved[0]["artifacts"] == build["artifacts"] and not saved[0]["binding"]["passed"]
    assert "sha256" not in str(raised.value) and "artifacts" not in str(raised.value)


@pytest.fixture
def poc_invocation(binaries, tmp_path):
    flow = object.__new__(Workflow)
    flow.cfg = {"validation": {"baseline_runs": 1, "poc_runs": 1, "poc_timeout_seconds": 10}}
    flow.adapter = {"source": "user", "command": ["python3", "{poc}"]}
    flow.poc = tmp_path / "poc.py"
    flow.external = None
    flow.root = tmp_path
    trace = tmp_path / "trace"
    trace.write_text(exec_line(binaries.parent / "launcher"))
    log = tmp_path / "execution.log"
    log.write_text("launcher failed\n")
    result = {"trace": str(trace), "log": str(log), "passed": False,
              "command": ["python3", str(flow.poc)], "returncode": 1,
              "reason": None, "sanitizer_error": False}
    flow.execute = lambda *a, **k: result.copy()
    return flow, trace, log, result


@pytest.mark.parametrize("baseline", [True, False])
@pytest.mark.parametrize("message", ["fatal error: missing.h: No such file or directory\n",
                                     "undefined reference to `target_api'\n",
                                     "Traceback: FileNotFoundError: payload.bin\n"])
def test_launcher_failure_has_separate_status_and_log(binaries, tmp_path, poc_invocation, baseline, message):
    flow, trace, log, result = poc_invocation
    log.write_text(message)
    # Merely opening a build artifact (e.g. by the linker) is not execution.
    trace.write_text(trace.read_text() + load_line(binaries / "fresh.so").splitlines()[0] + "\n")
    with pytest.raises(RepairError) as caught:
        flow.run_poc(binaries, {"artifacts": artifact_inventory(binaries)}, tmp_path / "logs", baseline)
    assert caught.value.status == "adapter_execution_failed"
    diagnostic = json.loads(str(caught.value))
    assert diagnostic["log_excerpt"] == message
    assert diagnostic["returncode"] == 1 and diagnostic["command"] == result["command"]
    assert "sha256" not in str(caught.value)
    saved = json.loads((tmp_path / "logs/poc-results.json").read_text())[0]
    assert saved["binding"]["accessed_artifacts"] == ["fresh.so"]
    assert saved["binding"]["fresh_runtime_targets"] == []


@pytest.mark.parametrize("scenario,expected", [
    ("zero_exit", "binding_failed"), ("asan", "binding_failed"),
    ("fresh_exec", "reproduction_failed"), ("fresh_load", "reproduction_failed"),
    ("uninstrumented_exec", "binding_failed"), ("uninstrumented_load", "binding_failed"),
    ("missing_trace", "binding_failed"), ("timeout", "binding_failed")])
def test_execution_failure_classification_preserves_other_gates(
        binaries, tmp_path, poc_invocation, scenario, expected):
    flow, trace, log, result = poc_invocation
    if scenario == "zero_exit":
        result.update(returncode=0, passed=True)
    elif scenario == "asan":
        result["sanitizer_error"] = True
        log.write_text("==100==ERROR: AddressSanitizer: heap-buffer-overflow\n")
    elif scenario == "fresh_exec":
        trace.write_text(exec_line(binaries / "fresh"))
    elif scenario == "fresh_load":
        trace.write_text(trace.read_text() + load_line(binaries / "fresh.so"))
    elif scenario.startswith("uninstrumented_"):
        target = binaries / "plain"
        target.write_bytes(elf_bytes(3 if scenario.endswith("load") else 2, asan=False))
        trace.write_text(trace.read_text() + (load_line(target) if scenario.endswith("load") else exec_line(target)))
    elif scenario == "missing_trace":
        trace.unlink()
    elif scenario == "timeout":
        result["reason"] = "timeout"
    with pytest.raises(RepairError) as caught:
        flow.run_poc(binaries, {"artifacts": artifact_inventory(binaries)}, tmp_path / "logs", baseline=True)
    assert caught.value.status == expected
    assert json.loads(str(caught.value))["log_excerpt"] == log.read_text()


def test_launch_os_error_is_adapter_execution_failure(binaries, tmp_path, poc_invocation):
    flow, trace, log, result = poc_invocation
    trace.unlink()
    result.update(returncode=None, reason="launch_failed: executable not found")
    log.write_text(result["reason"] + "\n")
    with pytest.raises(RepairError) as caught:
        flow.run_poc(binaries, {"artifacts": artifact_inventory(binaries)}, tmp_path / "logs", baseline=True)
    assert caught.value.status == "adapter_execution_failed"
    assert json.loads(str(caught.value))["log_excerpt"] == log.read_text()


def test_execution_failure_log_is_bounded(binaries, tmp_path, poc_invocation):
    flow, _, log, _ = poc_invocation
    log.write_text("first diagnostic\n" + "x" * 20000 + "\nlast diagnostic")
    with pytest.raises(RepairError) as caught:
        flow.run_poc(binaries, {"artifacts": artifact_inventory(binaries)}, tmp_path / "logs", baseline=True)
    excerpt = json.loads(str(caught.value))["log_excerpt"]
    assert "first diagnostic" in excerpt and "last diagnostic" in excerpt
    assert "<log truncated for prompt; original retained>" in excerpt
    assert len(excerpt) < 12100 and len(log.read_text()) > 20000
