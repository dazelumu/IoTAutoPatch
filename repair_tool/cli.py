from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path

from .config import model_secret, RepairError, load_config


def doctor(cfg: dict) -> dict:
    commands = ("python3", "cmake", "make", "gcc", "g++", "strace", "llvm-symbolizer")
    tools = {name: shutil.which(name) for name in commands}
    linux = sys.platform.startswith("linux")
    required = ["python3", "strace", "llvm-symbolizer"]
    if not cfg["build"]["command"] and cfg["project"]["path"] is not None:
        project = Path(cfg["project"]["path"])
        required.append("cmake" if (project / "CMakeLists.txt").exists() else "make")
        required.extend(["gcc", "g++"])
    key_present = bool(model_secret(cfg))
    return {"status": "ready" if linux and all(tools[t] for t in required) and key_present else "not_ready",
            "platform": platform.platform(), "linux": linux, "tools": tools,
            "missing_tools": [t for t in required if not tools[t]], "api_key_present": key_present,
            "model": cfg["model"]["name"], "source_upload": "Relevant source, PoC and logs are sent to configured API",
            "execution": "Direct Ubuntu processes, not a security sandbox; no nested VM/Docker"}


def resolve_run(value: str, output: str) -> Path:
    path = Path(value)
    if not path.is_dir():
        path = Path(output) / value
    if not path.is_dir() or not (path / "report.json").exists():
        raise RepairError("preparation_failed", f"Run not found: {value}; use absolute run path or --output")
    return path.resolve()


def exit_code(status: str) -> int:
    if status in {"validated_candidate", "patched_and_survived"}:
        return 0
    if status == "interrupted":
        return 130
    if status == "rounds_exhausted":
        return 4
    if status == "independent_rejected":
        return 5
    if status in {"infrastructure_failed", "integrity_failed", "rollback_failed"}:
        return 6
    if status in {"adaptation_failed", "adapter_execution_failed", "reproduction_failed",
                  "localization_failed",
                  "functional_failed", "contract_information_required",
                  "verification_failed", "baseline_oracle_failed"}:
        return 3
    return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Automatic repair: C/C++ source projects or rehosted IoT firmware (Ubuntu 24)")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("doctor", "run"):
        command = sub.add_parser(action)
        command.add_argument("--config", required=True)
    triage = sub.add_parser("triage")
    triage.add_argument("--config", required=True)
    triage.add_argument("--import-only", action="store_true",
                        help="Import configured reports without launching external tools")
    triage.add_argument("--backend", choices=("firmae", "greenhouse"),
                        help="Import backend filter, or firmae execute backend")
    triage.add_argument("--mode", choices=("compatibility", "analysis"),
                        help="FirmAE diagnostic mode (run is intentionally unavailable)")
    triage.add_argument("--firmware",
                        help="Case-relative or absolute firmware image for FirmAE execute")
    triage.add_argument("--brand",
                        help="FirmAE brand identifier passed to the configured wrapper")
    intake = sub.add_parser("intake")
    intake.add_argument("--config", required=True,
                        help="Intake template before firmware.rootfs exists")
    intake.add_argument("--triage-run", required=True,
                        help="Absolute FirmAE analysis triage run directory")
    intake.add_argument("--output-root", required=True,
                        help="New or empty independent generated-case directory")
    boot_plan = sub.add_parser("boot-plan")
    boot_plan.add_argument("--rootfs", required=True,
                           help="Materialized firmware rootfs directory")
    boot_plan.add_argument("--target", action="append", default=[],
                           help="Safe rootfs-relative target hint; repeatable")
    for action in ("inspect", "verify"):
        command = sub.add_parser(action)
        command.add_argument("--run", required=True, help="Run ID or absolute run directory")
        command.add_argument("--output", default="./repair-results", help="Run parent directory when using ID")
    args = parser.parse_args(argv)
    try:
        if args.action == "triage":
            from .config import load_firmae_execute_config, load_triage_config
            cfg = (load_firmae_execute_config(args.config)
                   if not args.import_only and args.backend == "firmae"
                   else load_triage_config(args.config))
            if not cfg["firmware"]["mode"]:
                raise RepairError("preparation_failed",
                                  "repair triage requires firmware.mode=true")
            if args.import_only:
                if args.firmware is not None or args.brand is not None \
                        or args.mode is not None:
                    raise RepairError("preparation_failed",
                                      "--firmware/--brand/--mode require FirmAE execute mode; "
                                      "remove --import-only")
                from .firmware.triage import run_import_triage
                report = run_import_triage(cfg, backend=args.backend)
            else:
                if args.backend != "firmae":
                    raise RepairError("preparation_failed",
                                      "non-import triage currently requires --backend firmae")
                if not args.firmware or not args.brand:
                    raise RepairError("preparation_failed",
                                      "FirmAE execute requires --firmware and --brand")
                mode = args.mode or "compatibility"
                from .firmware.triage import run_firmae_triage
                report = run_firmae_triage(cfg, args.firmware, mode=mode,
                                           brand=args.brand)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["status"] in {
                "diagnostics_generated", "diagnostics_only"} else exit_code(report["status"])
        if args.action in {"doctor", "run"}:
            cfg = load_config(args.config)
            if cfg["firmware"]["mode"]:
                from .firmware.case import firmware_doctor
                checks = firmware_doctor(cfg)
            else:
                checks = doctor(cfg)
            if args.action == "doctor":
                print(json.dumps(checks, ensure_ascii=False, indent=2))
                return 0 if checks["status"] == "ready" else 2
            if checks["status"] != "ready":
                print(json.dumps(checks, ensure_ascii=False, indent=2))
                return 2
            if cfg["firmware"]["mode"]:
                print("Firmware repair: model API receives target evidence, PoC source and logs. "
                      "Original rootfs is preserved; the session runs on a private copy.", flush=True)
                from .firmware.loop import FirmwareWorkflow
                report = FirmwareWorkflow(cfg).run()
                return exit_code(report["status"])
            from .workflow import Workflow
            print("Source upload: configured model API receives relevant source/PoC/logs. "
                  "Original project is preserved; execution is directly in this Ubuntu VM.", flush=True)
            report = Workflow(cfg).run()
            return exit_code(report["status"])
        if args.action == "intake":
            from .config import load_intake_config
            from .firmware.intake import run_firmae_intake
            cfg = load_intake_config(args.config)
            report = run_firmae_intake(cfg, args.triage_run, args.output_root)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["status"] == "intake_ready" else 2
        if args.action == "boot-plan":
            from .firmware.profiles.boot_plan import infer_boot_plan
            report = infer_boot_plan(args.rootfs, tuple(args.target))
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["status"] == "candidates_found" else 2
        root = resolve_run(args.run, args.output)
        if args.action == "inspect":
            print((root / "report.json").read_text(encoding="utf-8"))
            return 0
        report = json.loads((root / "report.json").read_text(encoding="utf-8"))
        if report.get("kind") == "firmware":
            from .firmware.loop import verify_firmware_run
            result = verify_firmware_run(root)
        else:
            from .workflow import verify_run
            result = verify_run(root)
        print(json.dumps({"status": result["status"], "run": str(root)}, ensure_ascii=False, indent=2))
        return 0
    except KeyboardInterrupt:
        return 130
    except RepairError as exc:
        print(json.dumps({"status": exc.status, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return exit_code(exc.status)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "preparation_failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
