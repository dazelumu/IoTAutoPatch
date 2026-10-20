"""Import-only firmware triage CLI tests (W3)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
import pytest

from repair_tool.cli import main


FIXTURES = Path(__file__).parent / "fixtures" / "diagnostics"


@pytest.fixture(autouse=True)
def skip_linux_only_firmware_validation_on_windows(monkeypatch):
    """Keep import-only CLI tests usable on Windows.

    Full firmware config validation imports the Linux rehost module for
    request validation.  ``repair triage`` itself does not rehost, and W3 must
    not modify that Linux-only boundary, so only these Windows unit tests use
    the config schema checks that do not require ``fcntl``.
    """
    if sys.platform.startswith("win"):
        from repair_tool.firmware import case
        monkeypatch.setattr(case, "validate_firmware_config",
                            lambda cfg, path: None)


def write_case(tmp_path: Path, imports: list[dict], *,
               output_root: str = "triage-results") -> Path:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"placeholder")
    (tmp_path / "poc.py").write_text("print('read-only')\n", encoding="utf-8")
    cfg = {
        "firmware": {
            "mode": True,
            "rootfs": "rootfs",
            "adapter": "dir825",
            "target": "sbin/httpd",
            "diagnostics": {
                "expose_to_model": True,
                "max_record_bytes": 32768,
                "max_page_size": 20,
                "imports": imports,
            },
        },
        "triage": {"output_root": output_root},
        "poc": {"path": "poc.py"},
        "model": {
            "base_url": "https://model.example.test/v1",
            "name": "test-model",
            "api_key": "super-secret-api-key",
        },
    }
    case = tmp_path / "case.yaml"
    case.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return case


def test_triage_import_only_creates_redacted_report_and_ledger(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    report_file = tmp_path / "reports" / "firmae-valid.json"
    report_file.parent.mkdir()
    report_file.write_bytes((FIXTURES / "firmae-valid.json").read_bytes())
    case = write_case(tmp_path, [{
        "id": "firmae-test", "path": "reports/firmae-valid.json",
        "backend": "firmae", "format": "firmae-report-v1", "required": True,
    }])

    assert main(["triage", "--config", str(case), "--import-only"]) == 0
    printed = json.loads(capsys.readouterr().out)
    output = Path(printed["output"])
    assert printed["status"] == "diagnostics_only"
    assert printed["mode"] == "import-only"
    assert printed["counts"]["total"] == 4
    assert (output / "report.json").is_file()
    assert (output / "raw" / "firmae-valid.json").is_file()

    ledger = json.loads((output / "diagnostics-ledger.json").read_text(encoding="utf-8"))
    assert ledger["schema"] == "diagnostics-ledger-v1"
    assert ledger["counts"]["by_kind"].get("crash_context", 0) == 0
    assert ledger["imports"][0]["import_id"] == "firmae-test"

    redacted_text = (output / "config-redacted.json").read_text(encoding="utf-8")
    assert "super-secret-api-key" not in redacted_text
    assert "reports/firmae-valid.json" not in redacted_text


def test_required_missing_import_fails_without_creating_result(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [{
        "id": "missing-required", "path": "reports/missing.json",
        "backend": "firmae", "format": "firmae-report-v1", "required": True,
    }])
    assert main(["triage", "--config", str(case), "--import-only"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["status"] == "preparation_failed"
    assert "Required diagnostics report" in error["error"]
    assert not (tmp_path / "triage-results").exists()


def test_optional_missing_import_is_recorded_not_fatal(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [{
        "id": "missing-optional", "path": "reports/missing.json",
        "backend": "greenhouse", "format": "greenhouse-report-v1", "required": False,
    }])
    assert main(["triage", "--config", str(case), "--import-only"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "diagnostics_only"
    assert report["missing_optional"] == [
        {"id": "missing-optional", "backend": "greenhouse"}
    ]
    assert report["counts"]["total"] == 0
    assert list((Path(report["output"]) / "raw").iterdir()) == []


def test_backend_filter_selects_only_requested_imports(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    reports = tmp_path / "reports"
    reports.mkdir()
    for name in ("firmae-valid.json", "greenhouse-crash.json"):
        (reports / name).write_bytes((FIXTURES / name).read_bytes())
    case = write_case(tmp_path, [
        {"id": "firmae", "path": "reports/firmae-valid.json", "backend": "firmae",
         "format": "firmae-report-v1", "required": False},
        {"id": "greenhouse", "path": "reports/greenhouse-crash.json",
         "backend": "greenhouse", "format": "greenhouse-report-v1", "required": True},
    ])
    assert main(["triage", "--config", str(case), "--import-only",
                 "--backend", "greenhouse"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["backend_filter"] == "greenhouse"
    assert report["counts"]["total"] == 3
    assert [item["id"] for item in report["imported"]] == ["greenhouse"]
    output = Path(report["output"])
    assert (output / "raw" / "greenhouse-crash.json").is_file()
    assert not (output / "raw" / "firmae-valid.json").exists()


def test_firmae_execute_cli_dispatches_controlled_adapter(
        tmp_path, monkeypatch, capsys) -> None:
    from repair_tool.firmware import triage

    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [])
    firmware = tmp_path / "original" / "firmware.bin"
    firmware.parent.mkdir()
    firmware.write_bytes(b"firmware image")
    calls = []

    def fake_run(cfg, firmware_value, *, mode, brand):
        calls.append({
            "config": cfg,
            "firmware": firmware_value,
            "mode": mode,
            "brand": brand,
        })
        return {
            "schema": "triage-report-v1", "kind": "firmware-triage",
            "status": "diagnostics_generated", "mode": "analysis",
            "output": str(tmp_path / "triage-results" / "fake-run"),
        }

    monkeypatch.setattr(triage, "run_firmae_triage", fake_run)
    assert main([
        "triage", "--config", str(case), "--backend", "firmae",
        "--mode", "analysis", "--firmware", str(firmware),
        "--brand", "dlink",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "diagnostics_generated"
    assert len(calls) == 1
    assert calls[0]["config"]["config_path"] == str(case.resolve())
    assert calls[0]["firmware"] == str(firmware)
    assert calls[0]["mode"] == "analysis"
    assert calls[0]["brand"] == "dlink"


def test_firmae_execute_cli_defaults_to_compatibility(
        tmp_path, monkeypatch, capsys) -> None:
    from repair_tool.firmware import triage

    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [])
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware image")
    calls = []

    def fake_run(cfg, firmware_value, *, mode, brand):
        calls.append({"mode": mode, "brand": brand})
        return {"status": "diagnostics_generated"}

    monkeypatch.setattr(triage, "run_firmae_triage", fake_run)
    assert main([
        "triage", "--config", str(case), "--backend", "firmae",
        "--firmware", str(firmware), "--brand", "dlink",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "diagnostics_generated"
    assert calls == [{"mode": "compatibility", "brand": "dlink"}]


def test_firmae_execute_cli_returns_nonzero_for_tool_failure(
        tmp_path, monkeypatch, capsys) -> None:
    from repair_tool.firmware import triage

    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [])
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware image")

    monkeypatch.setattr(
        triage, "run_firmae_triage",
        lambda *args, **kwargs: {"status": "firmae_nonzero_exit"})
    assert main([
        "triage", "--config", str(case), "--backend", "firmae",
        "--firmware", str(firmware), "--brand", "dlink",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "firmae_nonzero_exit"


def test_greenhouse_execute_is_not_yet_exposed(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [])
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware image")
    assert main([
        "triage", "--config", str(case), "--backend", "greenhouse",
        "--firmware", str(firmware), "--brand", "dlink",
    ]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["status"] == "preparation_failed"
    assert "requires --backend firmae" in error["error"]


def test_import_only_rejects_execute_arguments(
        tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [])
    assert main([
        "triage", "--config", str(case), "--import-only",
        "--mode", "analysis", "--firmware", "firmware.bin",
        "--brand", "dlink",
    ]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["status"] == "preparation_failed"
    assert "remove --import-only" in error["error"]


def test_import_format_must_match_backend(tmp_path, monkeypatch) -> None:
    from repair_tool.config import RepairError
    from repair_tool.firmware.triage import run_import_triage
    from repair_tool.config import load_config

    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    case = write_case(tmp_path, [{
        "id": "bad-format", "path": "reports/x.json", "backend": "firmae",
        "format": "greenhouse-report-v1", "required": False,
    }])
    cfg = load_config(case)
    try:
        run_import_triage(cfg)
    except RepairError as exc:
        assert "format does not match backend" in str(exc)
    else:
        raise AssertionError("format mismatch was accepted")
