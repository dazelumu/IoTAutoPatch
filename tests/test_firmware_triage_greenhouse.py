"""Greenhouse diagnostic execute adapter tests (W9)."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware.triage import run_greenhouse_triage
from repair_tool.firmware.triage_adapters import greenhouse as greenhouse_adapter


FIXTURE = Path(__file__).parent / "fixtures" / "diagnostics" / "greenhouse-crash.json"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_config(tmp_path: Path, *, enabled: bool = True,
                executable: Path | None = None,
                work_root: Path | None = None,
                timeout_seconds: int = 19, required: bool = False,
                expose_to_model: bool = True,
                firmae_work_root: Path | None = None) -> dict:
    return {
        "config_path": str(tmp_path / "case.yaml"),
        "firmware": {"diagnostics": {"expose_to_model": expose_to_model}},
        "triage": {
            "output_root": str(tmp_path / "triage-results"),
            "firmae": {
                "work_root": str(firmae_work_root) if firmae_work_root else None,
            },
            "greenhouse": {
                "enabled": enabled,
                "executable": str(executable) if executable else None,
                "work_root": str(work_root) if work_root else None,
                "timeout_seconds": timeout_seconds,
                "required": required,
            },
        },
        "model": {"api_key": "secret-not-for-greenhouse"},
    }


def fake_report(firmware: Path) -> dict:
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    report["input"]["firmware_sha256"] = file_sha256(firmware)
    return report


def report_bytes(report: dict) -> bytes:
    payload = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    return b"greenhouse log prefix\n" + greenhouse_adapter._REPORT_BEGIN + b"\n" + \
        payload + b"\n" + greenhouse_adapter._REPORT_END + b"\n"


def setup_success(tmp_path: Path, *, expose_to_model: bool = True):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"original firmware bytes")
    executable = tmp_path / "tools" / "fake-greenhouse"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    work_root = tmp_path / "work" / "greenhouse"
    cfg = make_config(tmp_path, executable=executable, work_root=work_root,
                      expose_to_model=expose_to_model)
    return cfg, firmware, fake_report(firmware)


def patch_execution(monkeypatch, *, stdout: bytes = b"", stderr: bytes = b"",
                    returncode: int = 0, timed_out: bool = False,
                    output_limited: bool = False,
                    error: str | None = None, side_effect=None):
    calls = []

    def fake_execute(self, command, cwd, raw_dir):
        calls.append({"command": command, "cwd": cwd, "raw_dir": raw_dir})
        if side_effect is not None:
            side_effect(command, cwd, raw_dir)
        return {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "timed_out": timed_out,
            "output_limited": output_limited,
            "failure_reason": ("timeout" if timed_out else
                               "output_limit" if output_limited else None),
            "error": error,
            "duration_seconds": 0.0,
            "capture_limit_bytes": greenhouse_adapter.MAX_CAPTURE_BYTES,
            "process_group": True,
        }

    monkeypatch.setattr(greenhouse_adapter.GreenhouseAdapter, "_execute_process",
                        fake_execute)
    return calls


def test_execute_process_uses_bounded_files_and_isolated_group(
        tmp_path, monkeypatch) -> None:
    adapter = greenhouse_adapter.GreenhouseAdapter(
        tmp_path / "greenhouse", tmp_path / "work", 5)
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    captured = {}

    class FakeProcess:
        pid = 4423

        def poll(self):
            return 0

        def wait(self):
            return 0

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        kwargs["stdout"].write(b"stdout")
        kwargs["stderr"].write(b"stderr")
        return FakeProcess()

    monkeypatch.setattr(greenhouse_adapter.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("REPAIR_API_KEY", "secret-not-for-greenhouse")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-not-for-greenhouse")
    result = adapter._execute_process(["greenhouse"], cwd=tmp_path,
                                      raw_dir=raw_dir)

    assert captured["command"] == ["greenhouse"]
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True
    assert set(captured["kwargs"]["env"]) <= {"PATH", "HOME", "LANG"}
    assert "REPAIR_API_KEY" not in captured["kwargs"]["env"]
    assert "OPENAI_API_KEY" not in captured["kwargs"]["env"]
    assert result["stdout"] == b"stdout"
    assert result["stderr"] == b"stderr"
    assert result["capture_limit_bytes"] == greenhouse_adapter.MAX_CAPTURE_BYTES
    assert result["process_group"] is True


def test_greenhouse_success_persists_all_diagnostic_outputs(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    stdout = report_bytes(report_input)
    calls = patch_execution(monkeypatch, stdout=stdout,
                            stderr=b"greenhouse warning")

    result = run_greenhouse_triage(cfg, firmware, service="/sbin/httpd")
    output = Path(result["output"])
    assert result["status"] == "diagnostics_generated"
    assert result["backend"] == "greenhouse"
    assert result["authoritative"] is False
    assert result["diagnostic_only"] is True
    assert result["compatibility"]["real_cli_verified"] is False
    assert result["compatibility"]["argv_contract"] == \
        greenhouse_adapter._ARGV_CONTRACT
    assert result["greenhouse"]["interventions"] == report_input["interventions"]
    assert result["greenhouse"]["crashes"] == report_input["crashes"]
    assert result["greenhouse"]["patch_suggestions"] == \
        report_input["patch_suggestions"]
    assert result["greenhouse"]["records"] == 3

    command = calls[0]["command"]
    firmware_copy = Path(command[5])
    executable = Path(cfg["triage"]["greenhouse"]["executable"])
    assert command == [
        str(executable), "diagnostic-only", "--mode", "rehost",
        "--firmware", str(firmware_copy), "--service", "/sbin/httpd",
    ]
    assert firmware_copy.is_relative_to(Path(cfg["triage"]["greenhouse"]["work_root"]))
    assert firmware != firmware_copy
    assert firmware_copy.read_bytes() == firmware.read_bytes()
    assert calls[0]["cwd"] == firmware_copy.parent
    assert calls[0]["raw_dir"] == output / "raw"

    assert (output / "raw" / "stdout.bin").read_bytes() == stdout
    assert (output / "raw" / "stderr.bin").read_bytes() == b"greenhouse warning"
    assert (output / "stdout" / "stdout.txt").is_file()
    assert (output / "stderr" / "stderr.txt").is_file()
    assert (output / "raw" / "greenhouse-report-v1.json").is_file()
    records = json.loads((output / "normalized" /
                          "greenhouse-report-v1.json").read_text(encoding="utf-8"))
    assert len(records) == 3
    # Greenhouse may transform a target; execute-side reports never enter the
    # ledger as bound to the authoritative original ELF.
    assert all(record["binding"]["status"] == "related" for record in records)
    ledger = json.loads(
        (output / "diagnostics-ledger.json").read_text(encoding="utf-8"))
    assert ledger["counts"]["total"] == 3
    assert all(record["authoritative"] is False for record in ledger["records"])
    assert all(record["backend"] == "greenhouse" for record in ledger["records"])
    assert [decision["decision"] for decision in ledger["decisions"]] == \
        ["exposed"] * 3
    capability = json.loads(
        (output / "capability-report.json").read_text(encoding="utf-8"))
    assert capability["runtime"] == "greenhouse"
    assert capability["capabilities"]["authoritative_verification"] is False


def test_expose_to_model_false_marks_every_record_filtered(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path, expose_to_model=False)
    patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    ledger = json.loads(
        (Path(result["output"]) / "diagnostics-ledger.json").read_text(
            encoding="utf-8"))
    assert [decision["decision"] for decision in ledger["decisions"]] == \
        ["filtered"] * 3


@pytest.mark.parametrize(("values", "reason"), [
    ({"enabled": False}, "disabled"),
    ({"executable": None}, "executable_not_configured"),
    ({"work_root": None}, "work_root_not_configured"),
])
def test_not_configured_never_launches_subprocess(
        tmp_path, monkeypatch, values, reason) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    executable = tmp_path / "tools" / "fake-greenhouse"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    cfg = make_config(tmp_path, executable=executable,
                      work_root=tmp_path / "work", required=True)
    cfg["triage"]["greenhouse"].update(values)

    def fail_execute(*args, **kwargs):
        raise AssertionError("unconfigured Greenhouse must not launch")

    monkeypatch.setattr(greenhouse_adapter.GreenhouseAdapter, "_execute_process",
                        fail_execute)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    assert result["status"] == "greenhouse_not_configured"
    assert result["not_configured_reason"] == reason
    assert result["execution"] is None
    assert (Path(result["output"]) / "capability-report.json").is_file()
    assert not list((Path(result["output"]) / "raw").iterdir())


def test_missing_tool_returns_not_configured_without_subprocess(
        tmp_path, monkeypatch) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    cfg = make_config(tmp_path, executable=tmp_path / "missing-greenhouse",
                      work_root=tmp_path / "work")
    calls = patch_execution(monkeypatch)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    assert result["not_configured_reason"] == "executable_missing"
    assert calls == []
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_timeout_preserves_partial_output_and_does_not_import(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=b"partial stdout",
                    stderr=b"partial stderr", returncode=None, timed_out=True)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    output = Path(result["output"])
    assert result["status"] == "greenhouse_timeout"
    assert result["execution"]["timed_out"] is True
    assert result["execution"]["returncode"] is None
    assert result["execution"]["timeout_seconds"] == 19
    assert (output / "raw" / "stdout.bin").read_bytes() == b"partial stdout"
    assert (output / "raw" / "stderr.bin").read_bytes() == b"partial stderr"
    assert not (output / "diagnostics-ledger.json").exists()


def test_output_limit_preserves_partial_output_and_does_not_import(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=report_bytes(report_input) + b"x" * 32,
                    output_limited=True)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    output = Path(result["output"])
    assert result["execution"]["output_limited"] is True
    assert result["execution"]["failure_reason"] == "output_limit"
    assert (output / "raw" / "stdout.bin").read_bytes().endswith(b"x" * 32)
    assert not (output / "raw" / "greenhouse-report-v1.json").exists()
    assert not (output / "diagnostics-ledger.json").exists()


def test_nonzero_exit_is_recorded_without_import(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=report_bytes(report_input),
                    stderr=b"failed", returncode=3)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    output = Path(result["output"])
    assert result["status"] == "greenhouse_nonzero_exit"
    assert result["execution"]["returncode"] == 3
    assert result["greenhouse"]["records"] == 0
    assert not (output / "raw" / "greenhouse-report-v1.json").exists()
    assert not (output / "diagnostics-ledger.json").exists()


def test_empty_stdout_is_not_treated_as_generated_diagnostics(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=b"")
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    assert result["status"] == "greenhouse_report_invalid"
    assert "output is empty" in result["normalization_error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_report_identity_mismatch_is_not_imported(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    report_input["input"]["firmware_sha256"] = "0" * 64
    patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    output = Path(result["output"])
    assert "identity does not match" in result["normalization_error"]
    assert (output / "raw" / "greenhouse-report-v1.json").is_file()
    assert not (output / "diagnostics-ledger.json").exists()


def test_original_firmware_mutation_is_detected(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)

    def mutate_original(command, cwd, raw_dir):
        firmware.write_bytes(b"unexpected original mutation")

    patch_execution(monkeypatch, side_effect=mutate_original)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    assert result["firmware"]["original_unchanged"] is False
    assert "Original firmware changed" in result["execution"]["error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_original_replay_input_mutation_is_detected(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    replay = tmp_path / "replay.bin"
    replay.write_bytes(b"replay bytes")

    def mutate_replay(command, cwd, raw_dir):
        replay.write_bytes(b"unexpected replay mutation")

    patch_execution(monkeypatch, stdout=report_bytes(report_input),
                    side_effect=mutate_replay)
    result = run_greenhouse_triage(cfg, firmware, service="httpd",
                                   mode="replay", replay_input=replay)
    assert result["status"] == "greenhouse_input_changed"
    assert result["execution"]["replay_original_unchanged"] is False
    assert "replay input changed" in result["execution"]["error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_corrupt_firmware_copy_is_never_executed(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)

    def corrupt_copy(source, destination):
        Path(destination).write_bytes(b"corrupt firmware copy")

    calls = patch_execution(monkeypatch)
    monkeypatch.setattr(greenhouse_adapter.shutil, "copyfile", corrupt_copy)
    result = run_greenhouse_triage(cfg, firmware, service="httpd")
    assert result["firmware"]["copy_integrity"] is False
    assert result["execution"]["command"] is None
    assert "does not match" in result["execution"]["error"]
    assert calls == []
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_unknown_greenhouse_config_fields_are_rejected(tmp_path) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    cfg["triage"]["greenhouse"]["replay_input"] = "controller-supplied"
    with pytest.raises(RepairError, match="Unexpected triage.greenhouse fields"):
        run_greenhouse_triage(cfg, firmware, service="httpd")


def test_greenhouse_work_output_overlap_is_rejected(tmp_path) -> None:
    executable = tmp_path / "fake-greenhouse"
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    adapter = greenhouse_adapter.GreenhouseAdapter(
        executable, tmp_path / "work" / "greenhouse", timeout_seconds=5)
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "work" / "greenhouse" / "run"
    output.mkdir(parents=True)
    with pytest.raises(RepairError, match="must not contain each other"):
        adapter.execute(firmware, output=output, run_id="run", service="httpd")


def test_firmae_work_output_overlap_is_also_rejected(tmp_path) -> None:
    executable = tmp_path / "fake-greenhouse"
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    adapter = greenhouse_adapter.GreenhouseAdapter(
        executable, tmp_path / "work" / "greenhouse", timeout_seconds=5,
        peer_work_roots=(tmp_path / "work" / "firmae",))
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "work" / "firmae" / "run"
    output.mkdir(parents=True)
    with pytest.raises(RepairError, match="must not contain each other"):
        adapter.execute(firmware, output=output, run_id="run", service="httpd")


def test_work_directory_under_output_root_is_rejected(tmp_path) -> None:
    executable = tmp_path / "fake-greenhouse"
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    adapter = greenhouse_adapter.GreenhouseAdapter(
        executable, tmp_path / "triage-results" / "greenhouse-work",
        timeout_seconds=5)
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "triage-results" / "run"
    output.mkdir(parents=True)
    with pytest.raises(RepairError, match="must not contain each other"):
        adapter.execute(firmware, output=output, run_id="run", service="httpd")


def test_work_directory_may_not_contain_original_inputs_or_executable(
        tmp_path) -> None:
    firmware = tmp_path / "inputs" / "firmware.bin"
    replay = tmp_path / "inputs" / "replay.bin"
    firmware.parent.mkdir(parents=True)
    firmware.write_bytes(b"firmware")
    replay.write_bytes(b"replay")
    executable = tmp_path / "tools" / "fake-greenhouse"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    output = tmp_path / "triage-results" / "run"
    output.mkdir(parents=True)

    adapter = greenhouse_adapter.GreenhouseAdapter(
        executable, firmware.parent, timeout_seconds=5)
    with pytest.raises(RepairError, match="configured inputs"):
        adapter.execute(firmware, output=output, run_id="run", service="httpd",
                        mode="replay", replay_input=replay)

    adapter = greenhouse_adapter.GreenhouseAdapter(
        executable, executable.parent, timeout_seconds=5)
    with pytest.raises(RepairError, match="executable"):
        adapter.execute(firmware, output=output, run_id="run", service="httpd")


def test_replay_and_fuzz_arguments_are_explicit_and_bounded(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    replay = tmp_path / "replay.bin"
    replay.write_bytes(b"replay bytes")
    calls = patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_greenhouse_triage(cfg, firmware, service="httpd",
                                   mode="replay", replay_input=replay)
    assert result["status"] == "diagnostics_generated"
    replay_copy = Path(calls[0]["command"][9])
    assert calls[0]["command"][-2:] == ["--replay-input", str(replay_copy)]
    assert replay_copy.read_bytes() == replay.read_bytes()

    calls = patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_greenhouse_triage(cfg, firmware, service="httpd",
                                   mode="fuzz", fuzz_seconds=8)
    assert result["status"] == "diagnostics_generated"
    assert calls[0]["command"][-2:] == ["--fuzz-seconds", "8"]

    with pytest.raises(RepairError, match="fuzz_seconds"):
        run_greenhouse_triage(cfg, firmware, service="httpd", mode="fuzz",
                              fuzz_seconds=greenhouse_adapter.MAX_FUZZ_SECONDS + 1)
    with pytest.raises(RepairError, match="shorter than timeout_seconds"):
        run_greenhouse_triage(cfg, firmware, service="httpd", mode="fuzz",
                              fuzz_seconds=19)


def test_direct_sudo_is_rejected(tmp_path) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    executable = tmp_path / "sudo"
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    cfg = make_config(tmp_path, executable=executable, work_root=tmp_path / "work")
    with pytest.raises(RepairError, match="may not invoke sudo"):
        run_greenhouse_triage(cfg, firmware, service="httpd")


def test_resolved_sudo_is_rejected(tmp_path, monkeypatch) -> None:
    sudo = tmp_path / "sudo"
    sudo.write_text("#!/bin/sh\n", encoding="ascii")
    executable = tmp_path / "ordinary-greenhouse"
    real_resolve = Path.resolve

    def resolved(self, strict=False):
        return sudo if self == executable else real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolved)
    cfg = make_config(tmp_path, executable=executable, work_root=tmp_path / "work")
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    with pytest.raises(RepairError, match="may not invoke sudo"):
        run_greenhouse_triage(cfg, firmware, service="httpd")
