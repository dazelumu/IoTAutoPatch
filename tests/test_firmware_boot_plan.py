"""Generic boot-plan inference tests."""
from __future__ import annotations

import json
import sys
import struct
from pathlib import Path

import pytest

from repair_tool.cli import main
from repair_tool.firmware.profiles.boot_plan import infer_boot_plan


def elf32(machine: int = 8, *, big_endian: bool = True,
          e_flags: int = 0x1000) -> bytes:
    endian = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes((1, 2 if big_endian else 1, 1)) + b"\0" * 9
    header = struct.pack(
        endian + "HHIIIIIHHHHHH",
        2, machine, 1, 0x400000, 52, 0, e_flags,
        52, 32, 0, 0, 0, 0,
    )
    return ident + header + b"\0" * 12


def write_rootfs(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "etc/init.d").mkdir(parents=True)
    (rootfs / "www").mkdir()
    (rootfs / "sbin/httpd").write_bytes(elf32())
    (rootfs / "usr/sbin/lighttpd").write_bytes(elf32())
    (rootfs / "sbin/rc").write_text("#!/bin/sh\n", encoding="utf-8")
    (rootfs / "etc/init.d/S80httpd").write_text(
        "#!/bin/sh\nhttpd -f\n", encoding="utf-8")
    return rootfs


def test_boot_plan_ranks_init_referenced_http_target(tmp_path: Path) -> None:
    plan = infer_boot_plan(write_rootfs(tmp_path))

    assert plan["schema"] == "candidate-boot-plan-v1"
    assert plan["status"] == "candidates_found"
    assert plan["targets"][0]["path"] == "sbin/httpd"
    assert plan["targets"][0]["architecture"]["candidate"] == "mips32be"
    assert plan["targets"][0]["architecture"]["registered"] is True
    assert plan["targets"][0]["protocol"] == "http-ascii-get-head-port80"
    assert plan["targets"][0]["protocol_registered"] is True
    assert plan["targets"][0]["init_references"] == ["etc/init.d/S80httpd"]
    assert {item["path"] for item in plan["init_candidates"]} == {
        "sbin/rc", "etc/init.d/S80httpd"}
    assert all(item["requires_validation"] for item in plan["launch_modes"])


def test_boot_plan_accepts_future_architecture_as_unauthorized_candidate(
        tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "usr/sbin").mkdir(parents=True)
    (rootfs / "usr/sbin/mini_httpd").write_bytes(elf32(machine=40, big_endian=False))

    plan = infer_boot_plan(rootfs, ["usr/sbin/mini_httpd"])

    assert len(plan["targets"]) == 1
    assert plan["targets"][0]["path"] == "usr/sbin/mini_httpd"
    assert plan["targets"][0]["source"] == "explicit-hint"
    assert plan["targets"][0]["protocol"] is None
    assert plan["targets"][0]["architecture"]["candidate"] == "arm32"
    assert plan["targets"][0]["architecture"]["registered"] is False
    assert plan["targets"][0]["protocol_registered"] is False
    assert plan["authorization"].startswith("candidate-only")


def test_boot_plan_requires_regular_elf_target(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_text("not an ELF", encoding="utf-8")

    plan = infer_boot_plan(rootfs)

    assert plan["status"] == "insufficient_evidence"
    assert plan["targets"] == []


@pytest.mark.parametrize("hint", ["/sbin/httpd", "../outside", ""])
def test_boot_plan_rejects_unsafe_target_hint(tmp_path: Path, hint: str) -> None:
    with pytest.raises(ValueError, match="safe rootfs-relative"):
        infer_boot_plan(tmp_path, [hint])


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX symlink")
def test_boot_plan_rejects_target_symlink(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    outside = tmp_path / "outside.elf"
    outside.write_bytes(elf32())
    (rootfs / "sbin/httpd").symlink_to(outside)

    plan = infer_boot_plan(rootfs)

    assert plan["status"] == "insufficient_evidence"


def test_cli_boot_plan_prints_json(tmp_path: Path, capsys) -> None:
    rootfs = write_rootfs(tmp_path)

    code = main(["boot-plan", "--rootfs", str(rootfs),
                 "--target", "sbin/httpd"])
    output = json.loads(capsys.readouterr().out)

    assert code == 0
    assert output["status"] == "candidates_found"
    assert output["targets"][0]["path"] == "sbin/httpd"
