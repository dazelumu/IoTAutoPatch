"""FirmAE diagnostic execute adapter tests (W8)."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from repair_tool.config import RepairError
from repair_tool.firmware.triage import run_firmae_triage
from repair_tool.firmware.triage_adapters import firmae as firmae_adapter


FIXTURE = Path(__file__).parent / "fixtures" / "diagnostics" / "firmae-valid.json"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_config(tmp_path: Path, *, enabled: bool = True,
                executable: Path | None = None, work_root: Path | None = None,
                timeout_seconds: int = 17, required: bool = False) -> dict:
    return {
        "config_path": str(tmp_path / "case.yaml"),
        "firmware": {"diagnostics": {"expose_to_model": True}},
        "triage": {
            "output_root": str(tmp_path / "triage-results"),
            "firmae": {
                "enabled": enabled,
                "executable": str(executable) if executable else None,
                "work_root": str(work_root) if work_root else None,
                "timeout_seconds": timeout_seconds,
                "required": required,
            },
        },
        "model": {"api_key": "secret-not-for-firmae"},
    }


def fake_report(firmware: Path) -> dict:
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    report["input"]["firmware_sha256"] = file_sha256(firmware)
    report["results"]["boot"] = "yes"
    report["interventions"] = [{
        "kind": "rootfs-normalization",
        "description": "test diagnostic intervention",
    }]
    return report


def report_bytes(report: dict) -> bytes:
    payload = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    return b"firmae log prefix\n" + firmae_adapter._REPORT_BEGIN + b"\n" + \
        payload + b"\n" + firmae_adapter._REPORT_END + b"\n"


def setup_success(tmp_path: Path):
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"original firmware bytes")
    executable = tmp_path / "tools" / "fake-firmae"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    work_root = tmp_path / "work" / "firmae"
    cfg = make_config(tmp_path, executable=executable, work_root=work_root)
    return cfg, firmware, fake_report(firmware)


def patch_execution(monkeypatch, *, stdout: bytes = b"", stderr: bytes = b"",
                    returncode: int = 0, timed_out: bool = False,
                    output_limited: bool = False, error: str | None = None,
                    side_effect=None):
    calls = []

    def fake_execute(self, command, cwd, raw_dir):
        calls.append({"command": command, "cwd": cwd, "raw_dir": raw_dir})
        if side_effect is not None:
            side_effect(command, cwd, raw_dir)
        return {
            "stdout": stdout, "stderr": stderr, "returncode": returncode,
            "timed_out": timed_out, "output_limited": output_limited,
            "failure_reason": ("timeout" if timed_out else
                               "output_limit" if output_limited else None),
            "error": error, "duration_seconds": 0.0,
            "capture_limit_bytes": firmae_adapter.MAX_CAPTURE_BYTES,
            "process_group": True,
        }

    monkeypatch.setattr(firmae_adapter.FirmAEAdapter, "_execute_process",
                        fake_execute)
    return calls


def test_execute_process_uses_bounded_files_and_isolated_group(
        tmp_path, monkeypatch) -> None:
    adapter = firmae_adapter.FirmAEAdapter(
        tmp_path / "firmae", tmp_path / "work", 5)
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    captured = {}

    class FakeProcess:
        pid = 4242

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

    monkeypatch.setattr(firmae_adapter.subprocess, "Popen", fake_popen)
    result = adapter._execute_process(["firmae"], cwd=tmp_path,
                                      raw_dir=raw_dir)

    assert captured["command"] == ["firmae"]
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True
    assert set(captured["kwargs"]["env"]) <= {"PATH", "HOME", "LANG"}
    assert "REPAIR_API_KEY" not in captured["kwargs"]["env"]
    assert result["stdout"] == b"stdout"
    assert result["stderr"] == b"stderr"
    assert result["returncode"] == 0
    assert result["capture_limit_bytes"] == firmae_adapter.MAX_CAPTURE_BYTES
    assert result["process_group"] is True


def test_firmae_success_persists_raw_execution_and_diagnostics(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    stdout = report_bytes(report_input)
    calls = patch_execution(monkeypatch, stdout=stdout,
                            stderr=b"firmae warning")
    monkeypatch.setenv("REPAIR_API_KEY", "secret-not-for-firmae")

    result = run_firmae_triage(cfg, firmware, mode="compatibility", brand="test-brand")
    output = Path(result["output"])
    assert result["status"] == "diagnostics_generated"
    assert result["authoritative"] is False
    assert result["firmae"]["results"]["boot"] == "yes"
    assert result["firmae"]["results"]["network"] == "observed"
    assert result["firmae"]["interventions"] == report_input["interventions"]
    assert result["firmae"]["records"] == 4

    execution_call = calls[0]
    command = execution_call["command"]
    firmware_copy = Path(command[3])
    assert command[:3] == [str(Path(cfg["triage"]["firmae"]["executable"])),
                           "-c", "test-brand"]
    assert firmware_copy.is_relative_to(Path(cfg["triage"]["firmae"]["work_root"]))
    assert firmware != firmware_copy
    assert firmware_copy.read_bytes() == firmware.read_bytes()
    assert execution_call["cwd"] == firmware_copy.parent
    assert execution_call["raw_dir"] == output / "raw"

    execution = result["execution"]
    assert execution["returncode"] == 0
    assert execution["timed_out"] is False
    assert execution["duration_seconds"] >= 0
    assert execution["capture_limit_bytes"] == firmae_adapter.MAX_CAPTURE_BYTES
    assert execution["process_group"] is True
    assert result["firmware"]["original_unchanged"] is True
    assert (output / "raw" / "stdout.bin").read_bytes() == stdout
    assert (output / "raw" / "stderr.bin").read_bytes() == b"firmae warning"
    assert (output / "stdout" / "stdout.txt").is_file()
    assert (output / "stderr" / "stderr.txt").is_file()
    assert (output / "raw" / "firmae-report-v1.json").is_file()

    records = json.loads(
        (output / "normalized" / "firmae-report-v1.json").read_text(encoding="utf-8"))
    assert len(records) == 4
    # The execute adapter verifies the firmware image, not the claimed ELF
    # target/rootfs digests, so records cannot enter the ledger as bound.
    assert all(record["binding"]["status"] == "related" for record in records)
    ledger = json.loads(
        (output / "diagnostics-ledger.json").read_text(encoding="utf-8"))
    assert ledger["counts"]["total"] == 4
    assert all(record["authoritative"] is False for record in ledger["records"])
    assert [decision["decision"] for decision in ledger["decisions"]] == \
        ["exposed"] * 4
    assert {decision["diagnostic"] for decision in ledger["decisions"]} == \
        {record["id"] for record in ledger["records"]}
    assert ledger["imports"][0]["format"] == "firmae-report-v1"
    capability = json.loads(
        (output / "capability-report.json").read_text(encoding="utf-8"))
    assert capability["runtime"] == "firmae"
    assert capability["capabilities"]["authoritative_verification"] is False


@pytest.mark.parametrize(("mode", "argument"), [
    ("compatibility", "-c"),
    ("analysis", "-a"),
])
def test_firmae_mode_arguments_are_explicit(tmp_path, monkeypatch, mode, argument) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    report_input["input"]["brand"] = "dlink"
    calls = patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_firmae_triage(cfg, firmware, mode=mode, brand="dlink")
    assert result["status"] == "diagnostics_generated"
    assert calls[0]["command"][1] == argument
    assert calls[0]["command"][2] == "dlink"


def test_firmae_run_mode_requires_network_isolation_contract(tmp_path) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    with pytest.raises(RepairError, match="Unsupported FirmAE mode: run"):
        run_firmae_triage(cfg, firmware, mode="run", brand="dlink")


def test_missing_optional_firmae_returns_not_configured_without_subprocess(
        tmp_path, monkeypatch) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    executable = tmp_path / "missing-firmae"
    cfg = make_config(tmp_path, executable=executable,
                      work_root=tmp_path / "work", required=True)

    def fail_execute(*args, **kwargs):
        raise AssertionError("missing FirmAE must not launch a subprocess")

    monkeypatch.setattr(firmae_adapter.FirmAEAdapter, "_execute_process",
                        fail_execute)
    result = run_firmae_triage(cfg, firmware)
    assert result["status"] == "firmae_not_configured"
    assert result["not_configured_reason"] == "executable_missing"
    assert result["configuration"]["required"] is True
    assert result["execution"] is None
    assert (Path(result["output"]) / "capability-report.json").is_file()
    assert not list((Path(result["output"]) / "raw").iterdir())


def test_timeout_preserves_partial_output_and_fails(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=b"partial stdout",
                    stderr=b"partial stderr", returncode=None, timed_out=True)
    result = run_firmae_triage(cfg, firmware)
    output = Path(result["output"])
    assert result["status"] == "firmae_timeout"
    assert result["execution"]["timed_out"] is True
    assert result["execution"]["returncode"] is None
    assert result["execution"]["timeout_seconds"] == 17
    assert (output / "raw" / "stdout.bin").read_bytes() == b"partial stdout"
    assert (output / "raw" / "stderr.bin").read_bytes() == b"partial stderr"
    assert not (output / "diagnostics-ledger.json").exists()


def test_nonzero_exit_is_recorded_without_normalization(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=report_bytes(report_input),
                    stderr=b"failed", returncode=2)
    result = run_firmae_triage(cfg, firmware)
    output = Path(result["output"])
    assert result["status"] == "firmae_nonzero_exit"
    assert result["execution"]["returncode"] == 2
    assert result["firmae"]["records"] == 0
    assert not (output / "raw" / "firmae-report-v1.json").exists()
    assert not (output / "diagnostics-ledger.json").exists()


def test_report_identity_mismatch_is_not_imported(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    report_input["input"]["firmware_sha256"] = "0" * 64

    patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_firmae_triage(cfg, firmware)
    output = Path(result["output"])
    assert result["status"] == "firmae_report_identity_mismatch"
    assert "identity does not match" in result["normalization_error"]
    assert (output / "raw" / "firmae-report-v1.json").is_file()
    assert not (output / "diagnostics-ledger.json").exists()


def test_report_brand_mismatch_is_not_imported(tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    report_input["input"]["brand"] = "other-brand"

    patch_execution(monkeypatch, stdout=report_bytes(report_input))
    result = run_firmae_triage(cfg, firmware, mode="analysis", brand="dlink")
    output = Path(result["output"])
    assert result["status"] == "firmae_report_brand_mismatch"
    assert "brand does not match" in result["normalization_error"]
    assert (output / "raw" / "firmae-report-v1.json").is_file()
    assert not (output / "diagnostics-ledger.json").exists()


def test_original_firmware_mutation_is_detected(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)

    def mutate_original(command, cwd, raw_dir):
        firmware.write_bytes(b"unexpected original mutation")

    patch_execution(monkeypatch, side_effect=mutate_original)
    result = run_firmae_triage(cfg, firmware)
    assert result["status"] == "firmae_input_changed"
    assert result["firmware"]["original_unchanged"] is False
    assert "Original firmware changed" in result["execution"]["error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_invalid_stdout_is_raw_failure_not_diagnostics(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=b"plain log output")
    result = run_firmae_triage(cfg, firmware)
    assert result["status"] == "firmae_report_invalid"
    assert "not a valid report" in result["normalization_error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_empty_stdout_is_not_treated_as_generated_diagnostics(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=b"")
    result = run_firmae_triage(cfg, firmware)
    assert result["status"] == "firmae_report_invalid"
    assert "output is empty" in result["normalization_error"]
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_sudo_and_invalid_requests_are_rejected(tmp_path) -> None:
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    executable = tmp_path / "sudo"
    executable.write_text("", encoding="ascii")
    cfg = make_config(tmp_path, executable=executable,
                      work_root=tmp_path / "work", enabled=False)
    with pytest.raises(RepairError, match="may not invoke sudo"):
        run_firmae_triage(cfg, firmware)

    cfg["triage"]["firmae"]["executable"] = str(tmp_path / "fake")
    cfg["triage"]["firmae"]["enabled"] = True
    with pytest.raises(RepairError, match="Unsupported FirmAE mode"):
        run_firmae_triage(cfg, firmware, mode="install", brand="brand")
    with pytest.raises(RepairError, match="brand must be"):
        run_firmae_triage(cfg, firmware, mode="compatibility", brand="bad brand")


def test_sudo_symlink_is_rejected_by_resolved_executable(
        tmp_path, monkeypatch) -> None:
    sudo = tmp_path / "sudo"
    sudo.write_text("#!/bin/sh\n", encoding="ascii")
    executable = tmp_path / "ordinary-firmae"
    real_resolve = Path.resolve

    def resolved(self, strict=False):
        return sudo if self == executable else real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", resolved)
    cfg = make_config(tmp_path, executable=executable,
                      work_root=tmp_path / "work")
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    with pytest.raises(RepairError, match="may not invoke sudo"):
        run_firmae_triage(cfg, firmware)
    cfg = make_config(tmp_path, executable=executable,
                      work_root=tmp_path / "work")
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    with pytest.raises(RepairError, match="may not invoke sudo"):
        run_firmae_triage(cfg, firmware)


def test_unknown_firmae_config_fields_are_rejected(tmp_path) -> None:
    cfg = make_config(tmp_path, executable=tmp_path / "fake",
                      work_root=tmp_path / "work")
    cfg["triage"]["firmae"]["sudo"] = "allowed"
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    with pytest.raises(RepairError, match="Unexpected triage.firmae fields"):
        run_firmae_triage(cfg, firmware)


def test_work_directory_may_not_overlap_output_directory(tmp_path) -> None:
    executable = tmp_path / "fake-firmae"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    adapter = firmae_adapter.FirmAEAdapter(
        executable, tmp_path / "work", timeout_seconds=5)
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    output = tmp_path / "work" / "same-run"
    output.mkdir(parents=True)
    with pytest.raises(RepairError, match="must not contain each other"):
        adapter.execute(firmware, output=output, run_id="same-run")


def test_work_directory_may_not_overlap_source_rootfs(tmp_path) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    cfg["firmware"]["rootfs"] = str(rootfs)
    cfg["triage"]["firmae"]["work_root"] = str(rootfs / "firmae-work")
    with pytest.raises(RepairError, match="firmware.rootfs"):
        run_firmae_triage(cfg, firmware, mode="analysis", brand="test-brand")
    assert not (tmp_path / "triage-results").exists()


def test_work_directory_may_not_contain_original_firmware_or_executable(
        tmp_path) -> None:
    firmware = tmp_path / "inputs" / "firmware.bin"
    firmware.parent.mkdir(parents=True)
    firmware.write_bytes(b"firmware")
    executable = tmp_path / "tools" / "fake-firmae"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="ascii")
    executable.chmod(0o755)
    output = tmp_path / "triage-results" / "run"
    output.mkdir(parents=True)

    adapter = firmae_adapter.FirmAEAdapter(
        executable, firmware.parent, timeout_seconds=5)
    with pytest.raises(RepairError, match="configured inputs"):
        adapter.execute(firmware, output=output, run_id="run",
                        mode="compatibility", brand="dlink")

    adapter = firmae_adapter.FirmAEAdapter(
        executable, executable.parent, timeout_seconds=5)
    with pytest.raises(RepairError, match="executable"):
        adapter.execute(firmware, output=output, run_id="run",
                        mode="compatibility", brand="dlink")


def test_triage_output_may_not_overlap_source_rootfs(tmp_path) -> None:
    cfg, firmware, _ = setup_success(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    cfg["firmware"]["rootfs"] = str(rootfs)
    cfg["triage"]["output_root"] = str(rootfs / "triage-results")
    with pytest.raises(RepairError, match="firmware.rootfs"):
        run_firmae_triage(cfg, firmware, mode="analysis", brand="test-brand")
    assert not (rootfs / "triage-results").exists()


def test_corrupt_firmware_copy_is_never_executed(tmp_path, monkeypatch) -> None:
    cfg, firmware, _ = setup_success(tmp_path)

    def corrupt_copy(source, destination):
        Path(destination).write_bytes(b"corrupt firmware copy")

    calls = patch_execution(monkeypatch)
    monkeypatch.setattr(firmae_adapter.shutil, "copyfile", corrupt_copy)
    result = run_firmae_triage(cfg, firmware)

    assert result["status"] == "firmae_copy_integrity_failed"
    assert result["firmware"]["copy_integrity"] is False
    assert result["firmware"]["copy_sha256"] != result["firmware"]["sha256"]
    assert result["execution"]["command"] is None
    assert "does not match" in result["execution"]["error"]
    assert calls == []
    assert not (Path(result["output"]) / "diagnostics-ledger.json").exists()


def test_output_limit_preserves_partial_output_without_import(
        tmp_path, monkeypatch) -> None:
    cfg, firmware, report_input = setup_success(tmp_path)
    patch_execution(monkeypatch, stdout=report_bytes(report_input) + b"x" * 32,
                    output_limited=True)
    result = run_firmae_triage(cfg, firmware)
    output = Path(result["output"])
    assert result["status"] == "firmae_output_limited"
    assert result["execution"]["output_limited"] is True
    assert result["execution"]["failure_reason"] == "output_limit"
    assert (output / "raw" / "stdout.bin").read_bytes().endswith(b"x" * 32)
    assert not (output / "raw" / "firmae-report-v1.json").exists()
    assert not (output / "diagnostics-ledger.json").exists()
