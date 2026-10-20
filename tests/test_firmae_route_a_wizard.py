from __future__ import annotations

import json
from pathlib import Path

import yaml

from repair_tool.config import load_firmae_execute_config
from scripts.firmae_route_a_wizard import CommandRunner, RouteAState, RouteAWizard


class FakeRunner(CommandRunner):
    def __init__(self, root: Path, *, failed_run: bool = False):
        self.root = root
        self.failed_run = failed_run
        self.calls: list[tuple[list[str], bool]] = []

    def run(self, argv: list[str], *, capture_stdout: bool = False,
            heartbeat: str | None = None) -> tuple[int, str]:
        self.calls.append((argv, capture_stdout))
        action = argv[argv.index("-m", argv.index("repair_tool.cli") - 1) + 2] \
            if "repair_tool.cli" in argv else argv[1]
        if action == "triage":
            run = self.root / "triage-results" / "triage-fake"
            run.mkdir(parents=True)
            report = {
                "status": "diagnostics_generated", "backend": "firmae",
                "mode": "analysis", "output": str(run),
            }
            (run / "report.json").write_text(json.dumps(report), encoding="utf-8")
            return 0, json.dumps(report)
        if action == "intake":
            output = self.root / "generated-case"
            (output / "work").mkdir(parents=True)
            (output / "work" / "intake-manifest.json").write_text(
                json.dumps({"schema": "firmware-intake-v1", "status": "intake_ready"}),
                encoding="utf-8")
            case = output / "case.generated.yaml"
            case.write_text(yaml.safe_dump({
                "output": {"directory": str(output / "repair-results")},
            }), encoding="utf-8")
            return 0, json.dumps({
                "status": "intake_ready", "generated_case": str(case),
                "target": {"sha256": "a" * 64},
            })
        if action == "doctor":
            return 0, json.dumps({"status": "ready"})
        if action == "run":
            run = self.root / "generated-case" / "repair-results" / "repair-fake"
            run.mkdir(parents=True, exist_ok=True)
            if self.failed_run:
                progress_dir = run / "test-generation" / "3" / "baseline"
                progress_dir.mkdir(parents=True)
                (progress_dir / "test-progress.json").write_text(json.dumps([
                    {"id": "vuln_a205_gif", "kind": "vulnerability",
                     "passed": True, "http_status": None},
                ]), encoding="utf-8")
                report = {
                    "run_id": run.name,
                    "version": "test",
                    "status": "infrastructure_failed",
                    "stage": "generate-tests",
                    "error": "Admin RPC restart: listener remained",
                    "seconds": 12.5,
                    "rounds": [],
                    "model_calls": [{"status": "completed"}],
                    "failure": {
                        "kind": "target_cleanup_failed",
                        "listener_owners": [{"pid": 1338}],
                    },
                }
            else:
                report = {"run_id": run.name, "status": "validated_candidate"}
            (run / "report.json").write_text(json.dumps(report), encoding="utf-8")
            return 0, ""
        return 0, ""


def write_template(root: Path) -> Path:
    firmware = root / "dir825.bin"
    firmware.write_bytes(b"firmware")
    poc = root / "poc.py"
    poc.write_text("print('readonly')\n", encoding="utf-8")
    template = root / "intake.yaml"
    template.write_text(yaml.safe_dump({
        "firmware": {
            "mode": True, "rootfs": None, "adapter": "dir825",
            "target": "sbin/httpd",
            "checks": [{"request": {"path": "/"}, "statuses": [200],
                        "contains": "LOGIN"}],
            "diagnostics": {"expose_to_model": True, "imports": []},
        },
        "poc": {"path": str(poc)},
        "model": {"base_url": "https://model.example.test", "name": "test"},
        "triage": {
            "output_root": str(root / "triage-results"),
            "firmae": {"enabled": True, "executable": "/usr/local/bin/fake",
                       "work_root": str(root / "triage-work")},
        },
    }), encoding="utf-8")
    return template


def test_firmae_execute_accepts_route_a_template_without_rootfs(tmp_path,
                                                                 monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    template = write_template(tmp_path)
    cfg = load_firmae_execute_config(template)
    assert cfg["firmware"]["rootfs"] is None
    assert cfg["triage"]["firmae"]["enabled"] is True


def test_firmae_execute_cli_uses_route_a_template(tmp_path, monkeypatch, capsys):
    from repair_tool.cli import main
    from repair_tool.firmware import triage

    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    template = write_template(tmp_path)
    firmware = tmp_path / "dir825.bin"
    calls = []

    def fake_run(cfg, firmware_value, *, mode, brand):
        calls.append({"config": cfg["config_path"], "firmware": firmware_value,
                      "mode": mode, "brand": brand})
        return {"status": "diagnostics_generated"}

    monkeypatch.setattr(triage, "run_firmae_triage", fake_run)
    assert main([
        "triage", "--config", str(template), "--backend", "firmae",
        "--mode", "analysis", "--firmware", str(firmware),
        "--brand", "dlink",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "diagnostics_generated"
    assert calls == [{"config": str(template), "firmware": str(firmware),
                      "mode": "analysis", "brand": "dlink"}]


def test_wizard_advances_by_validated_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    template = write_template(tmp_path)
    runner = FakeRunner(tmp_path)
    wizard = RouteAWizard(
        RouteAState(config_path=str(template), firmware_path=str(tmp_path / "dir825.bin"),
                    brand="dlink", intake_output_root=str(tmp_path / "generated-case")),
        runner=runner,
        interactive=False,
        color=False,
    )
    wizard.configure()
    wizard.run_firmae_analysis()
    wizard.run_intake()
    wizard.run_doctor()
    wizard.run_repair()
    wizard.inspect()

    assert wizard.state.inputs_checked is True
    assert wizard.state.triage_run_id == "triage-fake"
    assert wizard.state.generated_case_path == str(
        tmp_path / "generated-case" / "case.generated.yaml")
    assert wizard.state.target_sha256 == "a" * 64
    assert wizard.state.doctor_status == "ready"
    assert wizard.state.repair_status == "validated_candidate"
    assert wizard.state.inspect_completed is True
    assert wizard.next_action() == "verify"
    triage_args = runner.calls[0][0]
    intake_args = runner.calls[1][0]
    run_args = runner.calls[3][0]
    inspect_args = runner.calls[4][0]
    assert triage_args[triage_args.index("triage") + 1:] == [
        "--config", str(template), "--backend", "firmae", "--mode", "analysis",
        "--firmware", str(tmp_path / "dir825.bin"), "--brand", "dlink",
    ]
    assert intake_args[intake_args.index("intake") + 1:] == [
        "--config", str(template), "--triage-run", str(tmp_path / "triage-results" / "triage-fake"),
        "--output-root", str(tmp_path / "generated-case"),
    ]
    assert run_args[run_args.index("run"):] == [
        "run", "--config", wizard.state.generated_case_path]
    assert inspect_args[inspect_args.index("inspect"):] == [
        "inspect", "--run", wizard.state.repair_run_path]


def test_wizard_cannot_skip_input_check(tmp_path):
    template = write_template(tmp_path)
    wizard = RouteAWizard(
        RouteAState(config_path=str(template), firmware_path=str(tmp_path / "dir825.bin"),
                    brand="dlink"),
        runner=FakeRunner(tmp_path),
        interactive=False,
        color=False,
    )
    assert wizard.next_action() == "configure"
    try:
        wizard.run_firmae_analysis()
    except Exception as exc:
        assert "第 1 步" in str(exc)
    else:
        raise AssertionError("wizard allowed FirmAE before input validation")
    assert wizard.runner.calls == []


def test_wizard_recommends_first_repair_run_after_doctor_ready(tmp_path):
    template = write_template(tmp_path)
    wizard = RouteAWizard(
        RouteAState(config_path=str(template),
                    firmware_path=str(tmp_path / "dir825.bin"),
                    inputs_checked=True,
                    generated_case_path=str(template),
                    doctor_status="ready"),
        runner=FakeRunner(tmp_path),
        interactive=False,
        color=False,
    )
    assert wizard.next_action() == "repair_run"


def test_repair_requires_explicit_yes_in_interactive_mode(tmp_path, monkeypatch):
    template = write_template(tmp_path)
    wizard = RouteAWizard(
        RouteAState(config_path=str(template), firmware_path=str(tmp_path / "dir825.bin"),
                    generated_case_path=str(template), doctor_status="ready",
                    repair_status=None),
        runner=FakeRunner(tmp_path),
        interactive=True,
        color=False,
    )
    prompts: list[str] = []

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return "NO"

    monkeypatch.setattr("builtins.input", fake_input)
    wizard.run_repair()
    assert wizard.state.repair_status is None
    assert all("run" not in call[0][1:3] for call in wizard.runner.calls)
    assert prompts
    assert all("Y/n" not in prompt and "y/N" not in prompt for prompt in prompts)
    assert all("必须输入 YES" in prompt for prompt in prompts)


def test_repair_accepts_only_exact_uppercase_yes(tmp_path, monkeypatch):
    template = write_template(tmp_path)
    generated = tmp_path / "case.generated.yaml"
    generated.write_text(yaml.safe_dump({
        "output": {"directory": str(tmp_path / "generated-case" / "repair-results")},
    }), encoding="utf-8")
    wizard = RouteAWizard(
        RouteAState(config_path=str(template), firmware_path=str(tmp_path / "dir825.bin"),
                    generated_case_path=str(generated), doctor_status="ready"),
        runner=FakeRunner(tmp_path),
        interactive=True,
        color=False,
    )
    answers = iter(("Y", "YES"))
    monkeypatch.setattr("builtins.input", lambda _: next(answers))

    wizard.run_repair()
    wizard.run_repair()

    assert wizard.state.repair_status == "validated_candidate"
    assert len([call for call in wizard.runner.calls if "run" in call[0]]) == 1


def test_wizard_diagnoses_failure_before_allowing_explicit_retry(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    template = write_template(tmp_path)
    generated = tmp_path / "case.generated.yaml"
    generated.write_text(yaml.safe_dump({
        "output": {"directory": str(tmp_path / "generated-case" / "repair-results")},
    }), encoding="utf-8")
    wizard = RouteAWizard(
        RouteAState(
            config_path=str(template),
            firmware_path=str(tmp_path / "dir825.bin"),
            generated_case_path=str(generated),
            doctor_status="ready",
        ),
        runner=FakeRunner(tmp_path, failed_run=True),
        interactive=False,
        color=False,
    )

    try:
        wizard.run_repair()
    except Exception as exc:
        assert "不要直接重试" in str(exc)
    else:
        raise AssertionError("wizard accepted infrastructure_failed as success")

    assert wizard.state.repair_status == "infrastructure_failed"
    assert wizard.state.repair_stage == "generate-tests"
    assert wizard.next_action() == "diagnose"
    output = capsys.readouterr().out
    assert "本地托管/重启/清理" in output
    assert "listener owners" in output

    wizard.diagnose()
    diagnosis = capsys.readouterr().out
    assert "vuln_a205_gif" in diagnosis
    assert "显式选择 repair run" in diagnosis
    assert wizard.state.failure_reviewed is True
    assert wizard.next_action() == ""
