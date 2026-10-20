#!/usr/bin/env python3
"""FirmAE Route-A 交互式分步向导。

向导不替代修复控制器。它调用已安装的 ``repair_tool.cli`` 命令、校验产物、
保存不含密钥的进度，并在进入下一步（特别是会调用真实模型的步骤）前显式确认。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

import yaml


STAGES = (
    "inputs",
    "firmae_analysis",
    "intake",
    "doctor",
    "repair_run",
    "inspect",
)


@dataclass
class RouteAState:
    config_path: str | None = None
    firmware_path: str | None = None
    brand: str | None = None
    inputs_checked: bool = False
    intake_output_root: str | None = None
    triage_run_path: str | None = None
    triage_run_id: str | None = None
    intake_manifest_path: str | None = None
    generated_case_path: str | None = None
    target_sha256: str | None = None
    doctor_status: str | None = None
    repair_run_path: str | None = None
    repair_run_id: str | None = None
    repair_status: str | None = None
    repair_stage: str | None = None
    repair_error: str | None = None
    repair_seconds: float | None = None
    failure_reviewed: bool = False
    inspect_completed: bool = False
    verify_status: str | None = None


class WizardError(Exception):
    pass


class CommandRunner:
    """Run a child command with a conservative progress indicator."""

    def run(self, argv: list[str], *, capture_stdout: bool = False,
            heartbeat: str | None = None) -> tuple[int, str]:
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE if capture_stdout else None,
                stderr=None,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            raise WizardError(f"无法启动命令 {argv[0]}: {exc}") from exc

        output_chunks: list[str] = []

        def drain() -> None:
            if process.stdout is None:
                return
            for line in process.stdout:
                output_chunks.append(line)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        next_heartbeat = time.monotonic() + (10 if heartbeat else 1 << 30)
        while process.poll() is None:
            time.sleep(0.2)
            now = time.monotonic()
            if heartbeat and now >= next_heartbeat:
                print(f"  ⏳ {heartbeat} 已运行 {int(now - started)} 秒", flush=True)
                next_heartbeat = now + 10
        reader.join(timeout=2)
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        elapsed = time.monotonic() - started
        print(f"  ↩ 命令退出码 {process.returncode}，耗时 {elapsed:.1f} 秒", flush=True)
        return process.returncode, "".join(output_chunks)


class RouteAWizard:
    def __init__(self, state: RouteAState | None = None, *,
                 runner: CommandRunner | None = None,
                 interactive: bool = True,
                 color: bool = True,
                 state_path: Path | None = None):
        self.state = state or RouteAState()
        self.runner = runner or CommandRunner()
        self.interactive = interactive
        self.color = color
        self.state_path = state_path

    def bold(self, text: str) -> str:
        return f"\033[1m{text}\033[0m" if self.color else text

    def good(self, text: str) -> str:
        return f"\033[32m{text}\033[0m" if self.color else text

    def warn(self, text: str) -> str:
        return f"\033[33m{text}\033[0m" if self.color else text

    def bad(self, text: str) -> str:
        return f"\033[31m{text}\033[0m" if self.color else text

    def input(self, prompt: str, default: str | None = None) -> str:
        suffix = "" if default is None else f" [{default}]"
        value = input(f"{prompt}{suffix}: ").strip()
        return value or (default or "")

    def confirm(self, prompt: str, *, default: bool = True,
                explicit_yes: str | None = None) -> bool:
        if not self.interactive:
            return True
        if explicit_yes is not None:
            value = input(
                f"{prompt}（必须输入 {explicit_yes} 继续，其他任意输入取消）: ").strip()
            if value == explicit_yes:
                return True
            print(self.bad(f"未输入 {explicit_yes}，已取消。"))
            return False
        hint = "Y/n" if default else "y/N"
        while True:
            value = input(f"{prompt} [{hint}]: ").strip()
            if not value:
                return default
            if value.lower() in {"y", "yes"}:
                return True
            if value.lower() in {"n", "no"}:
                return False
            print(self.bad("请输入 y 或 n。"))

    def save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(asdict(self.state), ensure_ascii=False, indent=2) + "\n"
        with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.state_path.parent,
                prefix=self.state_path.name + ".", delete=False) as handle:
            handle.write(data)
            temporary = Path(handle.name)
        temporary.replace(self.state_path)

    def command(self, arguments: list[str]) -> list[str]:
        override = os.environ.get("REPAIR_COMMAND")
        if override:
            return [*shlex.split(override), *arguments]
        return [sys.executable, "-m", "repair_tool.cli", *arguments]

    def require_file(self, value: str | None, label: str) -> Path:
        if not value:
            raise WizardError(f"{label} 尚未设置。")
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise WizardError(f"{label} 不存在或不是文件: {path}")
        return path

    def require_dir(self, value: str | None, label: str) -> Path:
        if not value:
            raise WizardError(f"{label} 尚未设置。")
        path = Path(value).expanduser().resolve()
        if not path.is_dir():
            raise WizardError(f"{label} 不存在或不是目录: {path}")
        return path

    def read_json(self, path: Path) -> dict:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WizardError(f"无法读取 JSON {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise WizardError(f"JSON 根节点必须是对象: {path}")
        return value

    def parse_command_json(self, output: str, label: str) -> dict:
        try:
            value = json.loads(output)
        except json.JSONDecodeError as exc:
            raise WizardError(f"{label} 输出不是有效 JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise WizardError(f"{label} 输出根节点不是对象")
        return value

    def header(self, title: str) -> None:
        print("\n" + self.bold("=" * 74))
        print(self.bold(title))
        print(self.bold("=" * 74))

    @staticmethod
    def compact_path(value: str | None, limit: int = 58) -> str:
        if not value:
            return "未设置"
        text = str(value)
        if len(text) <= limit:
            return text
        return "…" + text[-(limit - 1):]

    @staticmethod
    def display_width(text: str) -> int:
        return sum(2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
                   for char in text)

    @classmethod
    def pad_display(cls, text: str, width: int) -> str:
        return text + " " * max(0, width - cls.display_width(text))

    def configure(self) -> None:
        self.header("第 1 步：检查输入")
        if self.interactive:
            if not self.state.config_path:
                self.state.config_path = self.input("Route-A intake 模板 YAML 路径")
            if not self.state.firmware_path:
                self.state.firmware_path = self.input("原始固件 .bin/.zip 路径")
            if not self.state.brand:
                self.state.brand = self.input("FirmAE brand", "dlink")
            if not self.state.intake_output_root:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                config_path = Path(self.state.config_path).expanduser().resolve()
                default = str(config_path.parent / f"generated-case-{stamp}")
                self.state.intake_output_root = self.input(
                    "intake 输出目录（必须为空或不存在）", default)

        config_path = self.require_file(self.state.config_path, "配置模板")
        firmware_path = self.require_file(self.state.firmware_path, "原始固件")
        if self.state.brand != "dlink":
            raise WizardError("Route-A 第一阶段只支持 brand=dlink")
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise WizardError(f"无法读取配置模板: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("firmware"), dict):
            raise WizardError("配置模板缺少 firmware 对象")
        firmware = raw["firmware"]
        if firmware.get("mode") is not True:
            raise WizardError("firmware.mode 必须为 true")
        if firmware.get("rootfs") is not None:
            raise WizardError("Route-A 模板应不设置 firmware.rootfs，由 intake 生成")
        if firmware.get("target") != "sbin/httpd":
            raise WizardError("Route-A 第一阶段只支持 firmware.target=sbin/httpd")
        triage = raw.get("triage")
        if not isinstance(triage, dict):
            raise WizardError("配置模板缺少 triage 对象")
        firmae = triage.get("firmae")
        if not isinstance(firmae, dict) or not firmae.get("enabled"):
            raise WizardError("triage.firmae.enabled 必须为 true")
        for key in ("executable", "work_root"):
            if not isinstance(firmae.get(key), str) or not firmae[key]:
                raise WizardError(f"triage.firmae.{key} 必须显式配置")
        if not isinstance(triage.get("output_root"), str) or not triage["output_root"]:
            raise WizardError("triage.output_root 必须显式配置")

        output_root = Path(self.state.intake_output_root or "").expanduser().resolve()
        if output_root.exists():
            if not output_root.is_dir():
                raise WizardError(f"intake 输出路径不是目录: {output_root}")
            if any(output_root.iterdir()):
                existing = self._existing_intake(output_root)
                if existing is None:
                    raise WizardError(
                        f"intake 输出目录非空且没有完整结果: {output_root}")
                manifest, generated_case = existing
                self.state.intake_manifest_path = str(manifest)
                self.state.generated_case_path = str(generated_case)
                self.state.target_sha256 = manifest.get("target", {}).get("sha256")
        self.state.intake_output_root = str(output_root)
        self.state.inputs_checked = True
        self.save()
        size_mb = firmware_path.stat().st_size / 1024 / 1024
        print(self.good("✅ 输入检查通过"))
        print(f"  模板: {config_path}")
        print(f"  固件: {firmware_path} ({size_mb:.2f} MiB)")
        print(f"  brand: {self.state.brand}")
        print(f"  intake 输出: {output_root}")
        if self.state.generated_case_path:
            print(self.warn("  已发现完整 generated case；可跳过 FirmAE/intake，直接 doctor。"))

    def _existing_intake(self, output_root: Path) -> tuple[dict, Path] | None:
        manifest_path = output_root / "work" / "intake-manifest.json"
        case_path = output_root / "case.generated.yaml"
        if not manifest_path.is_file() or not case_path.is_file():
            return None
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            yaml.safe_load(case_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError):
            return None
        if (not isinstance(manifest, dict)
                or manifest.get("schema") != "firmware-intake-v1"
                or manifest.get("status") != "intake_ready"):
            return None
        return manifest, case_path

    def run_firmae_analysis(self) -> None:
        self.header("第 2 步：FirmAE diagnostic-only analysis")
        if not self.state.inputs_checked:
            raise WizardError("必须先完成第 1 步输入检查。")
        config_path = self.require_file(self.state.config_path, "配置模板")
        firmware_path = self.require_file(self.state.firmware_path, "原始固件")
        if not self.state.brand:
            self.state.brand = "dlink"
        print("将执行: repair triage --backend firmae --mode analysis")
        print(self.warn("只允许 FirmAE analysis；不会执行 FirmAE run/-r，不调用模型。"))
        returncode, output = self.runner.run(
            self.command([
                "triage", "--config", str(config_path),
                "--backend", "firmae", "--mode", "analysis",
                "--firmware", str(firmware_path),
                "--brand", self.state.brand,
            ]),
            capture_stdout=True,
            heartbeat="FirmAE analysis",
        )
        if returncode != 0:
            raise WizardError(f"FirmAE analysis 失败，退出码 {returncode}")
        report = self.parse_command_json(output, "FirmAE triage")
        if report.get("status") != "diagnostics_generated":
            raise WizardError(f"FirmAE triage 状态异常: {report.get('status')!r}")
        if report.get("backend") != "firmae" or report.get("mode") != "analysis":
            raise WizardError("FirmAE triage 报告身份不是 firmae/analysis")
        output_value = report.get("output")
        if not isinstance(output_value, str):
            raise WizardError("FirmAE triage 报告缺少 output")
        run_dir = Path(output_value).resolve()
        disk_report = self.read_json(run_dir / "report.json")
        if disk_report.get("status") != "diagnostics_generated":
            raise WizardError("FirmAE 磁盘报告状态不是 diagnostics_generated")
        self.state.triage_run_path = str(run_dir)
        self.state.triage_run_id = str(disk_report.get("run_id") or run_dir.name)
        self.save()
        print(self.good("✅ FirmAE analysis 完成"))
        print(f"  run: {self.state.triage_run_id}")
        print(f"  目录: {run_dir}")

    def run_intake(self) -> None:
        self.header("第 3 步：artifact 校验与 rootfs 物化")
        config_path = self.require_file(self.state.config_path, "配置模板")
        run_dir = self.require_dir(self.state.triage_run_path, "FirmAE triage run")
        output_root = Path(self.state.intake_output_root or "").expanduser().resolve()
        if output_root.exists() and any(output_root.iterdir()):
            existing = self._existing_intake(output_root)
            if existing is None:
                raise WizardError(
                    "intake 输出目录非空且不是完整结果；请选择新的空目录。")
            manifest, case_path = existing
            self.state.intake_manifest_path = str(output_root / "work" / "intake-manifest.json")
            self.state.generated_case_path = str(case_path)
            self.state.target_sha256 = manifest.get("target", {}).get("sha256")
            self.save()
            print(self.good("✅ 复用已有 intake 结果"))
            print(f"  case: {case_path}")
            return
        print("将执行: repair intake")
        returncode, output = self.runner.run(
            self.command([
                "intake", "--config", str(config_path),
                "--triage-run", str(run_dir),
                "--output-root", str(output_root),
            ]),
            capture_stdout=True,
            heartbeat="rootfs materialization",
        )
        if returncode != 0:
            raise WizardError(f"repair intake 失败，退出码 {returncode}")
        report = self.parse_command_json(output, "repair intake")
        if report.get("status") != "intake_ready":
            raise WizardError(f"repair intake 状态异常: {report.get('status')!r}")
        generated = report.get("generated_case")
        if not isinstance(generated, str) or not Path(generated).is_file():
            raise WizardError("repair intake 没有生成 case.generated.yaml")
        self.state.intake_manifest_path = str(
            output_root / "work" / "intake-manifest.json")
        self.state.generated_case_path = str(Path(generated).resolve())
        self.state.target_sha256 = report.get("target", {}).get("sha256")
        self.save()
        print(self.good("✅ intake 完成"))
        print(f"  case: {self.state.generated_case_path}")
        print(f"  target SHA256: {self.state.target_sha256}")

    def run_doctor(self) -> None:
        self.header("第 4 步：generated case doctor")
        case_path = self.require_file(self.state.generated_case_path, "generated case")
        returncode, output = self.runner.run(
            self.command(["doctor", "--config", str(case_path)]),
            capture_stdout=True,
        )
        if returncode != 0:
            raise WizardError(f"repair doctor 失败，退出码 {returncode}")
        report = self.parse_command_json(output, "repair doctor")
        self.state.doctor_status = str(report.get("status"))
        self.save()
        if self.state.doctor_status != "ready":
            raise WizardError(f"doctor 不是 ready: {self.state.doctor_status!r}")
        print(self.good("✅ doctor ready"))
        print(f"  case: {case_path}")

    def _repair_output_root(self, case_path: Path) -> Path:
        try:
            case = yaml.safe_load(case_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise WizardError(f"无法读取 generated case: {exc}") from exc
        value = case.get("output", {}).get("directory") if isinstance(case, dict) else None
        if not isinstance(value, str) or not value:
            raise WizardError("generated case 缺少 output.directory")
        return Path(value).expanduser().resolve()

    @staticmethod
    def _model_call_summary(calls) -> str:
        if not isinstance(calls, list):
            return "未记录"
        completed = sum(
            1 for call in calls
            if isinstance(call, dict) and call.get("status") == "completed")
        failed = sum(
            1 for call in calls
            if isinstance(call, dict) and call.get("status") not in (
                None, "completed"))
        return f"{len(calls)} 次（completed={completed}, failed/other={failed}）"

    @staticmethod
    def _latest_test_progress(run_dir: Path) -> dict | None:
        root = run_dir / "test-generation"
        if not root.is_dir():
            return None
        candidates = sorted(
            (path for path in root.glob("*/baseline/test-progress.json")
             if path.is_file()),
            key=lambda path: path.stat().st_mtime,
        )
        if not candidates:
            return None
        try:
            value = json.loads(candidates[-1].read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, list) else None

    @staticmethod
    def _status_explanation(status: str | None) -> str:
        explanations = {
            "infrastructure_failed":
                "本地托管/重启/清理等运行环境失败；这不是候选补丁的功能结论。",
            "reproduction_failed":
                "PoC 未能按证据要求复现目标故障。",
            "baseline_checks_failed":
                "原始固件的固定检查未通过，不能进入修复。",
            "localization_failed":
                "模型未能注册满足证据约束的补丁点。",
            "contract_information_required":
                "模型输出或生成测试未满足控制器契约。",
            "rounds_exhausted":
                "修复轮次耗尽，没有产生通过验收的候选。",
            "validated_candidate":
                "候选补丁已通过控制器权威验收。",
        }
        return explanations.get(status, "查看 report.json/failure 获取详细状态。")

    def _print_run_summary(self, report: dict, run_dir: Path) -> None:
        status = str(report.get("status") or "unknown")
        success = status == "validated_candidate"
        print(self.good("✅ repair run 成功") if success else
              self.bad("❌ repair run 失败"))
        print(f"  run: {report.get('run_id') or run_dir.name}")
        print(f"  version: {report.get('version') or 'unknown'}")
        print(f"  status: {status}")
        print(f"  stage: {report.get('stage') or '-'}")
        seconds = report.get("seconds")
        print(f"  elapsed: {seconds:.1f} 秒" if isinstance(seconds, (int, float))
              else "  elapsed: -")
        print(f"  结论解释: {self._status_explanation(status)}")
        error = report.get("error")
        if error:
            print(self.bad(f"  controller error: {error}"))
        failure = report.get("failure")
        if isinstance(failure, dict):
            print(self.bad(f"  failure kind: {failure.get('kind') or '-'}"))
            owners = failure.get("listener_owners")
            if isinstance(owners, list) and owners:
                print(self.bad(f"  listener owners: {json.dumps(owners, ensure_ascii=False)}"))
        rounds = report.get("rounds")
        print(f"  repair rounds: {len(rounds) if isinstance(rounds, list) else '-'}")
        print(f"  model calls: {self._model_call_summary(report.get('model_calls'))}")
        baseline = report.get("baseline_checks")
        if isinstance(baseline, dict):
            print(f"  baseline fixed checks: {baseline.get('status') or baseline.get('result') or '-'}")
        progress = self._latest_test_progress(run_dir)
        if progress:
            last = progress[-1] if progress else {}
            if isinstance(last, dict):
                print("  last generated oracle test: "
                      f"{last.get('id')} ({last.get('kind')}, "
                      f"passed={last.get('passed')}, "
                      f"http_status={last.get('http_status')})")
        print(f"  report JSON: {run_dir / 'report.json'}")
        print(f"  report HTML: {run_dir / 'final' / 'report.html'}")

    def run_repair(self) -> None:
        self.header("第 5 步：真实模型 repair run")
        case_path = self.require_file(self.state.generated_case_path, "generated case")
        if self.state.doctor_status != "ready":
            raise WizardError("必须先通过 doctor，才能启动 repair run。")
        print(self.warn("即将外发：目标 ELF 证据、PoC、诊断和分析数据。"))
        print(self.warn("即将消耗：真实模型调用时间/额度；repair run 会创建新任务。"))
        if not self.confirm("确认外发并启动 repair run", default=False, explicit_yes="YES"):
            print(self.warn("已取消 repair run。"))
            return
        output_parent = self._repair_output_root(case_path)
        output_parent.mkdir(parents=True, exist_ok=True)
        before = {path for path in output_parent.glob("*/report.json")}
        self.state.inspect_completed = False
        self.state.verify_status = None
        print("将执行: repair run；控制器会实时输出各阶段。")
        returncode, _ = self.runner.run(
            self.command(["run", "--config", str(case_path)]),
            heartbeat="repair run",
        )
        after = {path for path in output_parent.glob("*/report.json")}
        new_paths = sorted(after - before, key=lambda p: p.stat().st_mtime, reverse=True)
        if not new_paths:
            candidates = sorted(after, key=lambda p: p.stat().st_mtime, reverse=True)
            new_paths = candidates[:1]
        if not new_paths:
            raise WizardError(
                f"repair 返回 {returncode}，但没有找到 report.json 于 {output_parent}")
        report_path = new_paths[0]
        report = self.read_json(report_path)
        run_dir = report_path.parent
        self.state.repair_run_path = str(run_dir)
        self.state.repair_run_id = str(report.get("run_id") or run_dir.name)
        self.state.repair_status = str(report.get("status"))
        self.state.repair_stage = str(report.get("stage") or "") or None
        self.state.repair_error = str(report.get("error") or "") or None
        seconds = report.get("seconds")
        self.state.repair_seconds = (
            float(seconds) if isinstance(seconds, (int, float)) else None)
        self.state.failure_reviewed = self.state.repair_status == "validated_candidate"
        self.save()
        self._print_run_summary(report, run_dir)
        if self.state.repair_status != "validated_candidate":
            raise WizardError(
                f"repair run 结束但状态是 {self.state.repair_status!r}；"
                f"请先执行菜单 d) 诊断失败 run，不要直接重试。报告保留在 {run_dir}")

    def diagnose(self, run_path: str | None = None) -> None:
        self.header("诊断 repair run")
        value = run_path or self.state.repair_run_path
        if not value and self.interactive:
            value = self.input("要诊断的 run 目录（留空取消）")
        if not value:
            print(self.warn("未指定 run 目录。"))
            return
        run_dir = self.require_dir(value, "repair run")
        report = self.read_json(run_dir / "report.json")
        self._print_run_summary(report, run_dir)
        self.state.repair_run_path = str(run_dir)
        self.state.repair_run_id = str(report.get("run_id") or run_dir.name)
        self.state.repair_status = str(report.get("status"))
        self.state.repair_stage = str(report.get("stage") or "") or None
        self.state.repair_error = str(report.get("error") or "") or None
        seconds = report.get("seconds")
        self.state.repair_seconds = (
            float(seconds) if isinstance(seconds, (int, float)) else None)
        self.state.failure_reviewed = True
        self.state.inspect_completed = False
        self.state.verify_status = None
        self.save()
        if self.state.repair_status != "validated_candidate":
            print(self.warn("下一步建议：先检查上面的 failure/test 证据；如需重试，请在菜单显式选择 repair run 并输入 YES。"))

    def inspect(self) -> None:
        self.header("第 6 步：只读查看修复报告")
        run_dir = self.require_dir(self.state.repair_run_path, "repair run")
        returncode, _ = self.runner.run(
            self.command(["inspect", "--run", str(run_dir)]),
            capture_stdout=False,
        )
        if returncode != 0:
            raise WizardError(f"repair inspect 失败，退出码 {returncode}")
        self.state.inspect_completed = True
        self.save()
        print(self.good("✅ inspect 完成"))
        print("  可选下一步：独立 verify（不调用模型）")

    def verify(self) -> None:
        self.header("可选第 7 步：独立 verify")
        run_dir = self.require_dir(self.state.repair_run_path, "repair run")
        if self.state.repair_status != "validated_candidate":
            raise WizardError("只有 validated_candidate run 才建议执行独立 verify。")
        if not self.confirm("启动独立 verify（会重新托管与测试，不调用模型）", default=False):
            return
        returncode, output = self.runner.run(
            self.command(["verify", "--run", str(run_dir)]),
            capture_stdout=True,
            heartbeat="independent verification",
        )
        if returncode != 0:
            raise WizardError(f"repair verify 失败，退出码 {returncode}")
        result = self.parse_command_json(output, "repair verify")
        self.state.verify_status = str(result.get("status"))
        self.save()
        print(self.good(f"✅ verify 完成: {self.state.verify_status}"))

    def status(self) -> None:
        self.header("Route-A 进度")
        triage_detail = self.compact_path(self.state.triage_run_path)
        if (not self.state.triage_run_path and self.state.generated_case_path):
            triage_detail = "可跳过（已有 generated case）"
        rows: list[tuple[str, Callable[[], bool], str]] = [
            ("1 输入检查", lambda: self.state.inputs_checked,
             self.compact_path(self.state.config_path)),
            ("2 FirmAE analysis", lambda: bool(self.state.triage_run_path),
             triage_detail),
            ("3 intake", lambda: bool(self.state.generated_case_path),
             self.compact_path(self.state.generated_case_path)),
            ("4 doctor", lambda: self.state.doctor_status == "ready",
             self.state.doctor_status or "未执行"),
            ("5 repair run", lambda: self.state.repair_status == "validated_candidate",
             (f"{self.state.repair_status} · {self.compact_path(self.state.repair_run_path)}"
              if self.state.repair_run_path else "未执行")),
            ("6 inspect", lambda: self.state.inspect_completed,
             self.compact_path(self.state.repair_run_path) if self.state.repair_run_path else "未执行"),
            ("7 verify", lambda: self.state.verify_status is not None,
             self.state.verify_status or "未执行"),
        ]
        for name, completed, detail in rows:
            failed = (name.startswith("5 ")
                      and self.state.repair_status is not None
                      and self.state.repair_status != "validated_candidate")
            mark = self.good("✅") if completed() else (
                self.bad("❌") if failed else self.warn("…"))
            print(f"  {mark} {self.pad_display(name, 22)} {detail}")
        if (self.state.repair_status is not None
                and self.state.repair_status != "validated_candidate"):
            print(self.bad(f"\n失败阶段: {self.state.repair_stage or '-'}"))
            if self.state.repair_error:
                print(self.bad(f"失败原因: {self.state.repair_error}"))
            if not self.state.failure_reviewed:
                print(self.warn("建议先执行菜单 d) 诊断当前 run。"))
        print(f"\n  状态文件: {self.compact_path(str(self.state_path) if self.state_path else None)}")

    def next_action(self) -> str:
        if (self.state.repair_run_path
                and self.state.repair_status is not None
                and self.state.repair_status != "validated_candidate"):
            return "" if self.state.failure_reviewed else "diagnose"
        if not self.state.inputs_checked:
            return "configure"
        if not self.state.generated_case_path:
            return "firmae_analysis" if not self.state.triage_run_path else "intake"
        if self.state.doctor_status != "ready":
            return "doctor"
        if self.state.repair_status is None:
            return "repair_run"
        if self.state.repair_status != "validated_candidate":
            return "" if self.state.failure_reviewed else "diagnose"
        if not self.state.inspect_completed:
            return "inspect"
        return "verify" if self.state.verify_status is None else ""

    def prompt_next(self, action: str) -> None:
        labels = {
            "configure": "第 1 步：检查输入",
            "firmae_analysis": "第 2 步：FirmAE analysis",
            "intake": "第 3 步：repair intake",
            "doctor": "第 4 步：doctor",
            "repair_run": "第 5 步：repair run（会外发模型数据）",
            "diagnose": "诊断当前/指定 repair run",
            "inspect": "第 6 步：只读 inspect",
            "verify": "可选第 7 步：独立 verify",
        }
        if not action:
            print("\n没有自动推荐的下一步；请从菜单显式选择。")
            return
        print(self.bold(f"\n➡ 推荐下一步: {labels[action]}"))
        if action == "repair_run":
            print(self.warn("返回菜单后选择 5，会再次要求输入大写 YES。"))
            return
        if self.confirm("现在执行这一步", default=True):
            self.execute(action)

    def execute(self, action: str) -> None:
        if action == "configure":
            self.configure()
        elif action == "firmae_analysis":
            self.run_firmae_analysis()
        elif action == "intake":
            self.run_intake()
        elif action == "doctor":
            self.run_doctor()
        elif action == "repair_run":
            self.run_repair()
        elif action == "diagnose":
            self.diagnose()
        elif action == "inspect":
            self.inspect()
        elif action == "verify":
            self.verify()
        else:
            raise WizardError(f"未知操作: {action}")


def default_state_path(config_path: Path) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", config_path.stem).strip("._") or "case"
    return config_path.parent / f".route-a-{safe}-wizard.json"


def load_state(path: Path) -> RouteAState:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WizardError(f"无法读取向导状态 {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WizardError("向导状态根节点必须是对象")
    known = set(RouteAState.__dataclass_fields__)
    unknown = set(value) - known
    if unknown:
        raise WizardError(f"向导状态包含未知字段: {sorted(unknown)}")
    return RouteAState(**value)


def menu(wizard: RouteAWizard) -> None:
    repair_failed = (wizard.state.repair_status is not None
                     and wizard.state.repair_status != "validated_candidate")
    actions = {
        "1": ("configure", "检查/填写输入", "先校验模板、固件和输出目录"),
        "2": ("firmae_analysis", "FirmAE analysis", "只做诊断分析，不执行 run/-r"),
        "3": ("intake", "repair intake", "物化并校验 rootfs/generated case"),
        "4": ("doctor", "repair doctor", "ready 后才允许第 5 步"),
        "5": ("repair_run", (
            "重新 repair run（真实模型，需输入 YES）" if repair_failed
            else "repair run（真实模型，需输入 YES）"), "会外发数据并消耗额度"),
        "6": ("inspect", "inspect 报告", "只读查看当前 run"),
        "7": ("verify", "独立 verify", "重新托管验证，不调用模型"),
        "d": ("diagnose", "诊断 repair run", "优先诊断失败，不自动重跑"),
        "s": ("status", "显示进度", "回到进度面板"),
        "n": ("next", "执行推荐下一步", "按产物状态推荐"),
        "q": ("quit", "退出", "进度文件保留"),
    }
    action_keys = {
        "configure": "1", "firmae_analysis": "2", "intake": "3",
        "doctor": "4", "repair_run": "5", "diagnose": "d",
        "inspect": "6", "verify": "7", "": "s",
    }
    while True:
        wizard.status()
        repair_failed = (wizard.state.repair_status is not None
                         and wizard.state.repair_status != "validated_candidate")
        actions["5"] = ("repair_run", (
            "重新 repair run（真实模型，需输入 YES）" if repair_failed
            else "repair run（真实模型，需输入 YES）"), "会外发数据并消耗额度")
        recommended_key = action_keys[wizard.next_action()]
        print(wizard.bold("\n操作菜单"))
        print("  ──────────────────────────────────────────────")
        for key, (_, label, description) in actions.items():
            marker = "→" if key == recommended_key else " "
            danger = wizard.warn("⚠") if key == "5" else " "
            label_display = wizard.pad_display(label, 36)
            print(f"  {marker}{danger} {key:>2}) {label_display} {description}")
        choice = input(
            f"选择操作（回车={recommended_key}，q=退出）: ").strip().lower()
        if not choice:
            choice = recommended_key
        if choice == "q":
            return
        if choice == "s":
            continue
        if choice == "n":
            wizard.prompt_next(wizard.next_action())
            continue
        item = actions.get(choice)
        if item is None:
            print(wizard.bad("无效选择"))
            continue
        try:
            wizard.execute(item[0])
            if item[0] != "status":
                wizard.prompt_next(wizard.next_action())
        except (WizardError, KeyboardInterrupt) as exc:
            print(wizard.bad(f"\n❌ 步骤失败: {exc}"))
            if (wizard.state.repair_run_path
                    and wizard.state.repair_status
                    and wizard.state.repair_status != "validated_candidate"
                    and not wizard.state.failure_reviewed):
                print(wizard.warn("建议先选择 d) 诊断该 run；不要直接重跑真实模型。"))
            else:
                print(wizard.warn("已产生的报告/目录会保留；可修正输入后从菜单显式重试。"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("-h", "--help", action="help",
                        help="显示帮助并退出")
    parser.add_argument("--config", help="Route-A intake 模板 YAML 路径")
    parser.add_argument("--firmware", help="原始固件 .bin/.zip 路径")
    parser.add_argument("--brand", default="dlink", help="FirmAE brand（第一阶段仅 dlink）")
    parser.add_argument("--output-root", help="新的或空的 generated-case 输出目录")
    parser.add_argument("--state", type=Path, help="进度 JSON 路径")
    parser.add_argument("--no-color", action="store_true", help="禁用 ANSI 颜色")
    for group in parser._action_groups:
        if group.title == "options":
            group.title = "选项"
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser().resolve() if args.config else None
    state_path = args.state.expanduser().resolve() if args.state else (
        default_state_path(config_path) if config_path else None)
    state = load_state(state_path) if state_path and state_path.is_file() else RouteAState()
    if config_path:
        state.config_path = str(config_path)
    if args.firmware:
        state.firmware_path = str(Path(args.firmware).expanduser().resolve())
    if args.brand:
        state.brand = args.brand
    if args.output_root:
        state.intake_output_root = str(Path(args.output_root).expanduser().resolve())
    wizard = RouteAWizard(
        state,
        interactive=True,
        color=(not args.no_color
               and sys.stdout.isatty()
               and os.environ.get("TERM", "").lower() != "dumb"),
        state_path=state_path,
    )
    try:
        menu(wizard)
        return 0
    except KeyboardInterrupt:
        print("\n已退出；进度已保留。")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
