from __future__ import annotations

import json
import struct
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import yaml
import pytest


@pytest.fixture(autouse=True)
def windows_fcntl_stub():
    """Config validation imports a POSIX-only rehost module on Windows."""
    if sys.platform == "win32":
        module = types.ModuleType("fcntl")
        module.flock = lambda *args, **kwargs: None
        module.LOCK_EX = 2
        module.LOCK_NB = 4
        sys.modules.setdefault("fcntl", module)


def minimal_elf32(machine: int = 8, big_endian: bool = True,
                  e_flags: int = 0x1000) -> bytes:
    endian = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes((1, 2 if big_endian else 1, 1)) + b"\0" * 9
    header = struct.pack(
        endian + "HHIIIIIHHHHHH",
        2, machine, 1, 0x400000, 52, 0, e_flags, 52, 32, 1, 40, 0, 0,
    )
    program_header = struct.pack(
        endian + "IIIIIIII",
        1, 84, 0x400000, 0x400000, 16, 16, 1, 0x1000,
    )
    return ident + header + program_header + b"\0" * 16


def minimal_elf64(e_flags: int = 0x20002000) -> bytes:
    ident = b"\x7fELF" + bytes((2, 2, 1)) + b"\0" * 9
    header = struct.pack(
        ">HHIQQQIHHHHHH",
        2, 8, 1, 0, 0, 0, e_flags, 64, 56, 0, 0, 0, 0)
    return ident + header


def test_architecture_facts_uses_elf64_flag_offset(tmp_path: Path) -> None:
    from repair_tool.firmware.case import _architecture_facts

    target = tmp_path / "target.elf"
    target.write_bytes(minimal_elf64())
    result = _architecture_facts(target)

    assert result["candidate"] is None
    assert result["elf"]["class"] == "ELF64"
    assert result["elf"]["machine"] == "MIPS"
    assert result["elf"]["e_flags"] == 0x20002000
    assert result["elf"]["abi"] is None
    assert "unregistered ELF identity" in result["reason"]


def doctor_case(tmp_path: Path, target: bytes) -> dict:
    from repair_tool.config import load_config

    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(target)
    (tmp_path / "poc.py").write_text("print('poc')\n", encoding="utf-8")
    data = {
        "firmware": {"mode": True, "rootfs": str(rootfs),
                     "target": "sbin/httpd",
                     "checks": [{"request": {"path": "/"},
                                 "statuses": [200], "contains": ""}]},
        "poc": {"path": str(tmp_path / "poc.py")},
        "model": {"base_url": "https://example.test/v1", "name": "test",
                  "api_key": "k"},
    }
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_config(path)


def patch_doctor_environment(monkeypatch) -> None:
    import shutil
    import subprocess

    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="mips\n", stderr=""))


def test_doctor_lists_registries_and_supports_current_dir825_case(
        tmp_path, monkeypatch) -> None:
    from repair_tool.firmware.case import firmware_doctor

    patch_doctor_environment(monkeypatch)
    result = firmware_doctor(doctor_case(tmp_path, minimal_elf32()))
    capabilities = result["capabilities"]

    assert [item["runtime"] for item in
            capabilities["registered_runtimes"]] == [
        "native-proot-mips32be", "firmae", "greenhouse"]
    assert capabilities["registered_architectures"] == ["mips32be"]
    assert capabilities["registered_protocols"] == [
        "http-ascii-get-head-port80",
        "http-ascii-auth-form-multi-step-port80"]
    assert capabilities["case"]["status"] == "supported"
    assert capabilities["case"]["runtime"] == {
        "selected": "native-proot-mips32be", "registered": True,
        "supports_architecture": True, "supports_protocol": True,
        "authoritative_verification": True,
    }
    assert capabilities["case"]["architecture"]["selected"] == "mips32be"
    assert capabilities["case"]["protocol"]["supported"] is True


def test_doctor_explicitly_rejects_unregistered_architecture(
        tmp_path, monkeypatch) -> None:
    from repair_tool.firmware.case import firmware_doctor

    patch_doctor_environment(monkeypatch)
    result = firmware_doctor(doctor_case(tmp_path, minimal_elf32(
        machine=40, big_endian=False)))
    architecture = result["capabilities"]["case"]["architecture"]

    assert result["capabilities"]["case"]["status"] == "unsupported"
    assert "architecture" in result["capabilities"]["case"]["unsupported"]
    assert architecture["selected"] is None
    assert architecture["detected"]["machine"] == "ARM"
    assert "unregistered ELF identity" in architecture["reason"]
    assert result["status"] == "not_ready"


@pytest.mark.parametrize(("e_flags", "reason"), [
    (0x2000, "unsupported MIPS ABI"),
    (0x02001000, "unsupported MIPS ABI or instruction encoding"),
])
def test_doctor_rejects_non_o32_and_micromips_mips(
        tmp_path, monkeypatch, e_flags, reason) -> None:
    from repair_tool.firmware.case import firmware_doctor

    patch_doctor_environment(monkeypatch)
    result = firmware_doctor(doctor_case(tmp_path, minimal_elf32(e_flags=e_flags)))
    architecture = result["capabilities"]["case"]["architecture"]

    assert result["capabilities"]["case"]["status"] == "unsupported"
    assert architecture["selected"] is None
    assert architecture["detected"]["machine"] == "MIPS"
    assert reason in architecture["reason"]
    assert result["status"] == "not_ready"


def test_doctor_explicitly_rejects_request_outside_protocol_capability(
        tmp_path, monkeypatch) -> None:
    from repair_tool.firmware.case import firmware_doctor

    patch_doctor_environment(monkeypatch)
    cfg = doctor_case(tmp_path, minimal_elf32())
    cfg["firmware"]["checks"][0]["request"]["method"] = "POST"
    result = firmware_doctor(cfg)
    protocol = result["capabilities"]["case"]["protocol"]

    assert result["capabilities"]["case"]["status"] == "unsupported"
    assert "protocol" in result["capabilities"]["case"]["unsupported"]
    assert protocol["registered"] is True
    assert protocol["supported"] is False
    assert protocol["invalid_checks"][0]["check"] == 0
    assert result["status"] == "not_ready"


def test_doctor_accepts_declared_form_multi_step_protocol(
        tmp_path, monkeypatch) -> None:
    from repair_tool.firmware.case import firmware_doctor

    patch_doctor_environment(monkeypatch)
    cfg = doctor_case(tmp_path, minimal_elf32())
    cfg["firmware"]["protocol"] = "http-ascii-auth-form-multi-step-port80"
    cfg["firmware"]["checks"] = [{
        "protocol": "http-ascii-auth-form-multi-step-port80",
        "steps": [
            {"id": "home", "method": "GET", "path": "/",
             "statuses": [200], "capture_cookies": True},
            {"id": "login", "method": "POST", "path": "/login.cgi",
             "form": {"login_name": "YWRtaW4="}, "statuses": [200]},
        ],
        "statuses": [200],
    }]
    result = firmware_doctor(cfg)
    protocol = result["capabilities"]["case"]["protocol"]

    assert protocol["selected"] == "http-ascii-auth-form-multi-step-port80"
    assert protocol["profile_supported"] is True
    assert protocol["runtime_supported"] is True
    assert protocol["supported"] is True
    assert result["capabilities"]["case"]["status"] == "supported"


def test_repair_doctor_prints_capability_diagnosis(tmp_path, monkeypatch, capsys):
    from repair_tool import cli
    from repair_tool.firmware import case

    cfg = doctor_case(tmp_path, minimal_elf32())
    monkeypatch.setattr(case, "firmware_doctor", lambda value: {
        "status": "not_ready", "capabilities": {"case": {"status": "supported"}},
    })
    code = cli.main(["doctor", "--config", cfg["config_path"]])
    printed = json.loads(capsys.readouterr().out)

    assert code == 2
    assert printed["capabilities"]["case"]["status"] == "supported"
