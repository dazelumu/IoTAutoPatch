"""Safety tests for the controlled FirmAE root wrapper."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


WRAPPER = Path(__file__).parents[1] / "scripts" / "firmae_root_wrapper.py"
spec = importlib.util.spec_from_file_location("firmae_root_wrapper", WRAPPER)
assert spec is not None and spec.loader is not None
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


def test_run_mode_is_rejected_before_path_handling(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(wrapper, "is_root", lambda: True)
    assert wrapper.main(["-r", "dlink", str(tmp_path / "firmware.bin")]) == 2


def test_unknown_brand_is_rejected(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(wrapper, "is_root", lambda: True)
    assert wrapper.main(["-c", "other", str(tmp_path / "firmware.bin")]) == 2


def test_firmware_outside_firmware_lab_is_rejected(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(wrapper, "is_root", lambda: True)
    firmware = tmp_path / "firmware.bin"
    firmware.write_bytes(b"firmware")
    assert wrapper.main(["-c", "dlink", str(firmware)]) == 2


def test_firmware_copy_must_be_regular_and_in_firmae_work_tree(
        tmp_path) -> None:
    path = tmp_path / "triage-work" / "firmae" / "run" / "firmware.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"firmware")
    try:
        wrapper.validate_firmware_copy(str(path))
    except ValueError as exc:
        assert "outside firmware-lab" in str(exc)
    else:
        raise AssertionError("firmware outside firmware-lab was accepted")


def test_firmae_environment_provides_fixed_tap_user() -> None:
    environment = wrapper.firmae_environment()
    assert environment["USER"] == "lumu"
    assert environment["HOME"] == "/root"
    assert environment["PATH"] == (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )


def test_root_wrapper_executes_from_secure_root_owned_tree() -> None:
    assert wrapper.FIRMAE_ROOT == Path(
        "/usr/local/lib/firmae-controller/FirmAE"
    )
    assert not wrapper.FIRMAE_ROOT.is_relative_to(Path("/home/lumu"))


def test_export_artifacts_writes_verified_read_only_manifest(
        monkeypatch, tmp_path) -> None:
    scratch = tmp_path / "FirmAE" / "scratch" / "2"
    scratch.mkdir(parents=True)
    for name in ("image.raw", "fileList", "architecture", "brand", "ip",
                 "kernelVersion", "run.sh"):
        (scratch / name).write_bytes(name.encode("utf-8"))
    monkeypatch.setattr(wrapper, "FIRMAE_ROOT", tmp_path / "FirmAE")
    firmware = tmp_path / "run" / "firmware.bin"
    firmware.parent.mkdir(parents=True)
    firmware.write_bytes(b"firmware")
    def fake_copy(command, **_kwargs):
        Path(command[-1]).write_bytes(Path(command[-2]).read_bytes())
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(wrapper.subprocess, "run", fake_copy)

    exported, error = wrapper.export_artifacts(firmware, 2)

    assert error is None
    assert exported is not None
    artifacts = tmp_path / "run" / "artifacts"
    manifest = json.loads((artifacts / "artifact-manifest.json").read_text(
        encoding="utf-8"))
    assert manifest["schema"] == "firmae-artifacts-v1"
    assert manifest["firmware_iid"] == 2
    assert manifest["transformed_image"] is True
    assert manifest["artifacts"]["image.raw"]["sha256"] == wrapper.sha256(
        artifacts / "image.raw")
    assert exported["files"]["image.raw"]["size"] == len(b"image.raw")


def test_export_artifacts_rejects_missing_artifact(monkeypatch, tmp_path) -> None:
    scratch = tmp_path / "FirmAE" / "scratch" / "3"
    scratch.mkdir(parents=True)
    (scratch / "image.raw").write_bytes(b"image")
    monkeypatch.setattr(wrapper, "FIRMAE_ROOT", tmp_path / "FirmAE")
    firmware = tmp_path / "run" / "firmware.bin"
    firmware.parent.mkdir(parents=True)
    firmware.write_bytes(b"firmware")
    def fake_copy(command, **_kwargs):
        Path(command[-1]).write_bytes(Path(command[-2]).read_bytes())
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(wrapper.subprocess, "run", fake_copy)

    exported, error = wrapper.export_artifacts(firmware, 3)

    assert exported is None
    assert "missing or unsafe FirmAE artifact" in error
