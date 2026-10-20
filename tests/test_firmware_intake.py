"""Route-A FirmAE automated intake tests."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
import yaml

from repair_tool.config import RepairError, load_intake_config
from repair_tool.firmware import intake
from repair_tool.firmware.intake import parse_seven_zip_listing, run_firmae_intake


def mips_elf() -> bytes:
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 1                       # ELF32
    data[5] = 2                       # big-endian
    data[6] = 1                       # version
    data[16:18] = (2).to_bytes(2, "big")     # ET_EXEC
    data[18:20] = (8).to_bytes(2, "big")     # EM_MIPS
    data[20:24] = (1).to_bytes(4, "big")     # version
    data[36:40] = (0x00001000).to_bytes(4, "big")  # o32, not microMIPS
    return bytes(data)


def write_artifacts(root: Path, *, image: bytes = b"image-raw") -> dict:
    root.mkdir(parents=True)
    values = {
        "image.raw": image,
        "fileList": "./sbin\n./sbin/httpd\n./www\n",
        "architecture": "mipseb",
        "brand": "dlink",
        "ip": "192.168.0.1",
        "kernelVersion": "2.6.31",
        "run.sh": "#!/bin/sh\necho never-executed\n",
    }
    entries = {}
    for name, payload in values.items():
        path = root / name
        path.write_bytes(payload if isinstance(payload, bytes)
                         else payload.encode("utf-8"))
        entries[name] = {
            "sha256": intake._sha256(path),
            "size": path.stat().st_size,
            "mode": "0o444",
        }
    manifest = {
        "schema": "firmae-artifacts-v1",
        "firmware_iid": 2,
        "transformed_image": True,
        "origin": "firmae-analysis-scratch",
        "execute_policy": "data-only; artifacts are never executed",
        "artifacts": entries,
    }
    (root / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return entries


def build_case(tmp_path: Path, *, work_root: Path, output_root: Path) -> Path:
    poc = tmp_path / "poc_trigger.py"
    poc.write_text("print('readonly poc')\n", encoding="utf-8")
    data = {
        "firmware": {
            "mode": True,
            "adapter": "dir825",
            "target": "sbin/httpd",
            "checks": [{"request": {"path": "/"}, "statuses": [200],
                        "contains": "LOGIN"}],
            "diagnostics": {"expose_to_model": True, "imports": []},
        },
        "poc": {"path": str(poc)},
        "model": {"base_url": "https://model.example.test/v1", "name": "test-model",
                  "api_key": "secret-value"},
        "triage": {
            "output_root": str(output_root),
            "firmae": {
                "enabled": True,
                "executable": str(tmp_path / "firmae-wrapper"),
                "work_root": str(work_root),
            },
        },
    }
    path = tmp_path / "intake.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def build_run(tmp_path: Path, *, status: str = "diagnostics_generated"):
    triage_output = tmp_path / "triage-results"
    work_root = tmp_path / "triage-work" / "firmae"
    config_path = build_case(tmp_path, work_root=work_root,
                             output_root=triage_output)
    run_id = "triage-test-run"
    run_dir = triage_output / run_id
    artifact_root = work_root / run_id / "artifacts"
    entries = write_artifacts(artifact_root)
    raw = {
        "schema": "firmae-report-v1",
        "input": {"firmware_sha256": "a" * 64, "brand": "dlink"},
        "results": {"architecture": "mipseb"},
        "runs": {"firmware_iid": 2},
        "artifacts": {"schema": "firmae-artifacts-v1", "firmware_iid": 2,
                      "files": entries},
    }
    raw_path = run_dir / "raw" / "firmae-report-v1.json"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    report = {
        "schema": "triage-report-v1",
        "kind": "firmware-triage",
        "backend": "firmae",
        "mode": "analysis",
        "status": status,
        "run_id": run_id,
        "firmware": {"sha256": "a" * 64, "original_unchanged": True},
        "execution": {
            "returncode": 0,
            "firmware_copy": str(work_root / run_id / "dir825.bin"),
        },
    }
    (run_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    return config_path, run_dir, artifact_root, raw


def fake_materialize(image: Path, file_list: Path, target: str,
                     output_root: Path):
    output_root.mkdir(parents=True)
    target_path = output_root / "sbin" / "httpd"
    target_path.parent.mkdir(parents=True)
    target_path.write_bytes(mips_elf())
    digest = intake._sha256(target_path)
    return output_root, {
        "file_count": 1, "directory_count": 1, "symlink_count": 0,
        "total_bytes": len(mips_elf()), "archive_logical_bytes": len(mips_elf()),
        "target_sha256": digest,
    }


def test_load_intake_config_allows_missing_rootfs(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    config_path, _, _, _ = build_run(tmp_path)
    cfg = load_intake_config(config_path)
    assert cfg["firmware"]["rootfs"] is None
    assert cfg["triage"]["firmae"]["work_root"].endswith("firmae")


def test_intake_generates_manifest_and_validated_case(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    fcntl = types.ModuleType("fcntl")
    fcntl.LOCK_EX = 2
    fcntl.LOCK_NB = 4
    monkeypatch.setitem(sys.modules, "fcntl", fcntl)
    config_path, run_dir, _, _ = build_run(tmp_path)
    cfg = load_intake_config(config_path)
    monkeypatch.setattr(intake, "materialize_rootfs", fake_materialize)
    output_root = tmp_path / "generated-case"

    result = run_firmae_intake(cfg, run_dir, output_root)

    assert result["schema"] == "firmware-intake-v1"
    assert result["status"] == "intake_ready"
    assert result["materialized_rootfs"]["not_original_pristine_rootfs"] is True
    assert result["runtime"]["authoritative_verification"] is True
    generated = yaml.safe_load((output_root / "case.generated.yaml").read_text(
        encoding="utf-8"))
    assert generated["firmware"]["rootfs"] == str(
        output_root / "work" / "rootfs-firmae")
    assert "api_key" not in generated["model"]
    assert generated["firmware"]["diagnostics"]["imports"][-1]["path"] == str(
        run_dir / "raw" / "firmae-report-v1.json")
    saved = json.loads((output_root / "work" / "intake-manifest.json").read_text(
        encoding="utf-8"))
    assert saved == result


def test_intake_rejects_unsuccessful_triage(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    config_path, run_dir, _, _ = build_run(tmp_path, status="firmae_boot_failed")
    cfg = load_intake_config(config_path)
    monkeypatch.setattr(intake, "materialize_rootfs", fake_materialize)
    with pytest.raises(RepairError, match="not successful"):
        run_firmae_intake(cfg, run_dir, tmp_path / "out")


def test_intake_rejects_artifact_hash_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    config_path, run_dir, artifact_root, _ = build_run(tmp_path)
    (artifact_root / "architecture").write_text("mipseb-corrupt", encoding="utf-8")
    cfg = load_intake_config(config_path)
    monkeypatch.setattr(intake, "materialize_rootfs", fake_materialize)
    with pytest.raises(RepairError, match="artifact identity mismatch"):
        run_firmae_intake(cfg, run_dir, tmp_path / "out")


def test_intake_rejects_nonempty_output_root(tmp_path, monkeypatch):
    monkeypatch.setenv("REPAIR_GLOBAL_CONFIG", "")
    config_path, run_dir, _, _ = build_run(tmp_path)
    cfg = load_intake_config(config_path)
    monkeypatch.setattr(intake, "materialize_rootfs", fake_materialize)
    output = tmp_path / "out"
    output.mkdir()
    (output / "existing.txt").write_text("x", encoding="utf-8")
    with pytest.raises(RepairError, match="must be empty"):
        run_firmae_intake(cfg, run_dir, output)


def test_seven_zip_listing_parses_sizes_and_rejects_duplicate_paths():
    text = "\n".join([
        "Path = sbin",
        "Size = 0",
        "Attributes = D_",
        "",
        "Path = sbin/httpd",
        "Size = 478344",
        "Attributes = A_",
        "",
    ])
    records = parse_seven_zip_listing(text)
    assert records["sbin/httpd"]["size"] == 478344
    with pytest.raises(RepairError, match="Duplicate archive path"):
        parse_seven_zip_listing(text + "\nPath = sbin/httpd\nSize = 1\n")


@pytest.mark.parametrize("value", ["../escape", "/absolute", "bad\\slash", "."])
def test_archive_path_safety(value):
    with pytest.raises(RepairError, match="Unsafe archive path"):
        intake._safe_archive_path(value)
