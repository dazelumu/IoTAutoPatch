"""Nested configuration and import-only triage loading tests."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from repair_tool.config import RepairError, load_config, load_triage_config
from repair_tool.config import DEFAULTS


def write_case(tmp_path: Path, firmware: dict | None = None,
               triage: dict | None = None, *, complete: bool = False) -> Path:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"target")
    (tmp_path / "poc.py").write_text("print('poc')\n", encoding="utf-8")
    data = {
        "firmware": {
            "mode": True, "rootfs": str(rootfs), "target": "sbin/httpd",
            **(firmware or {}),
        },
    }
    if triage is not None:
        data["triage"] = triage
    if complete:
        data["poc"] = {"path": str(tmp_path / "poc.py")}
        data["model"] = {"base_url": "https://model.example.test/v1",
                         "name": "test-model", "api_key": "test-key"}
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_nested_unknown_keys_are_rejected(tmp_path) -> None:
    path = write_case(
        tmp_path,
        firmware={"diagnostics": {"expose_to_model": True, "unexpected": True}},
        complete=True)
    with pytest.raises(RepairError, match="Unknown keys in firmware.diagnostics"):
        load_config(path)


def test_relocalize_default_budget_and_case_override(tmp_path) -> None:
    path = write_case(tmp_path, complete=True)
    cfg = load_config(path)
    assert DEFAULTS["repair"]["firmware_relocalize_queries"] == 16
    assert cfg["repair"]["firmware_relocalize_queries"] == 16

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["repair"] = {"firmware_relocalize_queries": 8}
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    cfg = load_config(path)
    assert cfg["repair"]["firmware_relocalize_queries"] == 8


def test_non_string_yaml_keys_fail_cleanly(tmp_path) -> None:
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump({123: {}}), encoding="utf-8")
    with pytest.raises(RepairError, match="Unknown or invalid section"):
        load_triage_config(path)

    path.write_text(yaml.safe_dump({"firmware": {123: "invalid"}}),
                    encoding="utf-8")
    with pytest.raises(RepairError, match="section firmware: \\[123\\]"):
        load_triage_config(path)


def test_nested_backend_types_are_rejected(tmp_path) -> None:
    path = write_case(
        tmp_path,
        triage={"firmae": {"timeout_seconds": True}},
        complete=True)
    with pytest.raises(RepairError,
                       match="triage.firmae.timeout_seconds must be an integer"):
        load_config(path)


def test_triage_work_roots_may_not_overlap_source_rootfs(tmp_path) -> None:
    path = write_case(
        tmp_path,
        triage={"output_root": str(tmp_path / "triage-results"),
                "firmae": {"work_root": str(tmp_path / "rootfs" / "firmae")}},
        complete=True)
    with pytest.raises(RepairError, match="firmware.rootfs"):
        load_config(path)


def test_import_only_config_does_not_require_model_or_poc(tmp_path) -> None:
    path = write_case(tmp_path, triage={"output_root": "triage-results"})
    cfg = load_triage_config(path)
    assert cfg["model"]["name"] is None
    assert cfg["poc"]["path"] is None
    assert cfg["triage"]["output_root"] == \
        str((tmp_path / "triage-results").resolve())


def test_import_only_default_output_may_not_overlap_source_rootfs(tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"target")
    path = tmp_path / "rootfs" / "case.yaml"
    path.write_text(yaml.safe_dump({
        "firmware": {"mode": True, "rootfs": str(rootfs),
                     "target": "sbin/httpd"},
    }), encoding="utf-8")
    with pytest.raises(RepairError, match="firmware.rootfs"):
        load_triage_config(path)
