"""Release source manifest tests."""
from __future__ import annotations

from pathlib import Path


def test_package_manifest_includes_diagnostic_fixtures() -> None:
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "project_package", root / "scripts" / "package.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    files = module.collect_files(root)
    relative = {path.relative_to(root).as_posix() for path in files}
    assert "tests/fixtures/diagnostics/firmae-valid.json" in relative
    assert "tests/fixtures/diagnostics/greenhouse-crash.json" in relative
    assert "tests/fixtures/diagnostics/untrusted-text.json" in relative
    assert "scripts/install_firmae_root_wrapper.sh" in relative
    assert {
        "repair_tool/firmware/http_multi_step.py",
        "repair_tool/firmware/session/processes.py",
        "repair_tool/firmware/session/http_tunnel.py",
        "repair_tool/firmware/runtimes/native_proot_mips32be/loader.py",
        "repair_tool/firmware/profiles/registry.py",
        "repair_tool/firmware/profiles/boot_plan.py",
        "repair_tool/firmware/profiles/dlink/dir825b_2_03/device_supervisor.py",
    } <= relative


def test_package_manifest_includes_curated_documentation() -> None:
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "project_package_docs", root / "scripts" / "package.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    relative = {path.relative_to(root).as_posix() for path in module.collect_files(root)}
    expected = {
        "docs/ARCHITECTURE.md",
        "docs/SUPPORTED_FIRMWARE.md",
        "cases/README.md",
        "cases/dlink/dir825b-2.03/cve-2025-6291/README.md",
        "cases/dlink/dir825b-2.03/cve-2024-57595/README.md",
        "cases/dlink/dir825b-2.03/cve-2024-57595/config/intake.example.yaml",
        "cases/dlink/dir825b-2.03/cve-2024-57595/results/controller-marker-reproduction.json",
        "cases/dlink/dir825b-2.03/cve-2025-6291/poc/poc_trigger.py",
        "cases/dlink/dir825b-2.03/cve-2025-6291/config/intake.example.yaml",
        "cases/dlink/dir825b-2.03/cve-2025-6291/patches/repair.c",
        "cases/dlink/dir825b-2.03/cve-2025-6291/results/result-summary.json",
        "cases/dlink/dir825b-2.03/cve-2025-6291/results/poc-plan.json",
        "cases/dlink/dir825b-2.03/cve-2025-6291/results/generated-tests.json",
        "docs/ROADMAP.md",
        "docs/OPERATIONS.md",
        "docs/CHANGELOG.md",
        "docs/releases/0.3.0.md",
        "docs/releases/0.3.1.md",
        "README.md",
        "VALIDATION.md",
        "AGENTS.md",
        "pyproject.toml",
        "requirements.txt",
    }
    assert expected <= relative
    forbidden = {
        path for path in relative
        if "/archive/" in f"/{path}/" or path.endswith((".ZIP", ".bin", ".tar.gz"))
    }
    assert not forbidden
