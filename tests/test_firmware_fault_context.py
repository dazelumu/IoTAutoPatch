"""Focused tests for DIR-825 ELF mappings and QEMU fault evidence."""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from repair_tool.firmware.profiles.dlink.dir825b_2_03 import (
    device_supervisor as supervisor_module,
)
from repair_tool.firmware.profiles.dlink.dir825b_2_03.device_supervisor import (
    Dir825Supervisor,
    TARGET_REL,
    executable_mappings,
)


def build_mips_elf(*, vaddr: int = 0x00400000,
                   code: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88") -> bytes:
    ident = b"\x7fELF\x01\x02\x01" + b"\x00" * 9
    header = struct.pack(
        ">HHIIIIIHHHHHH",
        2, 8, 1, vaddr, 52, 0, 0x50001007,
        52, 32, 1, 0, 0, 0,
    )
    program = struct.pack(
        ">IIIIIIII",
        1, 0x100, vaddr, vaddr, len(code), len(code) + 16, 5, 0x1000,
    )
    return ident + header + program + b"\x00" * (0x100 - 84) + code


def bare_supervisor(tmp_path: Path, image: bytes) -> Dir825Supervisor:
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    instance.root = tmp_path / "rootfs"
    target = instance.root / TARGET_REL
    target.parent.mkdir(parents=True)
    target.write_bytes(image)
    instance._mappings, instance._elf_header = executable_mappings(target)
    return instance


def test_executable_mappings_parses_all_elf32_header_fields(tmp_path):
    target = tmp_path / "httpd"
    target.write_bytes(build_mips_elf())

    mappings, header = executable_mappings(target)

    assert header == {
        "type": 2,
        "machine": 8,
        "version": 1,
        "entry": 0x00400000,
        "phoff": 52,
        "shoff": 0,
        "flags": 0x50001007,
        "ehsize": 52,
        "phentsize": 32,
        "phnum": 1,
        "shentsize": 0,
        "shnum": 0,
        "shstrndx": 0,
    }
    assert mappings == [{
        "guest_vaddr": 0x00400000,
        "file_offset": 0x100,
        "filesz": 8,
        "memsz": 24,
        "flags": 5,
        "alignment": 0x1000,
        "physical_address": 0x00400000,
    }]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data[:40], "truncated ELF32 header"),
        (lambda data: data[:42] + b"\x00\x10" + data[44:], "program-header size"),
        (lambda data: data[:28] + struct.pack(">I", len(data) - 4) + data[32:],
         "program-header table"),
        (lambda data: data[:56] + struct.pack(">I", len(data)) + data[60:],
         "exceeds the target file"),
    ],
)
def test_executable_mappings_rejects_truncated_or_out_of_bounds_data(
        tmp_path, mutate, message):
    target = tmp_path / "httpd"
    original = build_mips_elf()
    target.write_bytes(mutate(original))

    with pytest.raises(RuntimeError, match=message):
        executable_mappings(target)


def test_parse_fault_context_reads_latest_qemu_mips_snapshot(tmp_path):
    instance = bare_supervisor(tmp_path, build_mips_elf())
    fault_log = tmp_path / "httpd.qemu.log"
    fault_log.write_text(
        "pc=0x00400004 HI=0x00000000 LO=0x00000000\n"
        "GPR04: a0 aaaaaaaa a1 bbbbbbbb a2 cccccccc a3 dddddddd\n"
        "GPR28: gp 10008000 sp 7fff1000 s8 00000000 ra 00400000\n"
        "pc=0x00400000 HI=0x00000000 LO=0x00000000\n"
        "GPR04: a0 00000001 a1 00000002 a2 00000003 a3 00000004\n"
        "GPR28: gp 10009000 sp 7fff2000 s8 00000000 ra 00400004\n"
    )

    context = instance.parse_fault_context(fault_log)

    assert context == {
        "source": "qemu execution log tail",
        "log_path": str(fault_log),
        "pc": 0x00400000,
        "ra": 0x00400004,
        "sp": 0x7FFF2000,
        "gp": 0x10009000,
        "a0": 1,
        "a1": 2,
        "a2": 3,
        "a3": 4,
        "static_code_words": [
            {"register": "pc", "vaddr": 0x00400000, "bytes_hex": "11223344"},
            {"register": "ra", "vaddr": 0x00400004, "bytes_hex": "55667788"},
        ],
    }
    assert "stack_words" not in context


def test_launch_gives_each_httpd_process_its_own_fault_log(tmp_path, monkeypatch):
    commands = []

    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

    def fake_popen(command, **kwargs):
        del kwargs
        commands.append(command)
        return FakeProcess(1000 + len(commands))

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", fake_popen)
    instance = Dir825Supervisor.__new__(Dir825Supervisor)
    instance.out = tmp_path
    instance.runtime = tmp_path / "runtime"
    (instance.runtime / "log").mkdir(parents=True)
    instance.prefix = ["proot", "-q", "qemu-mips", "-r", "/rootfs"]
    instance.trace = False
    instance.env = {}
    instance.processes = []
    instance._mappings = [{
        "guest_vaddr": 0x00400000,
        "filesz": 0x1000,
        "flags": 5,
    }]
    instance.event = lambda *args, **kwargs: None

    instance.launch(["/sbin/rc", "init"], "rc")
    instance.launch(["/" + TARGET_REL], "httpd-1")
    instance.launch(["/" + TARGET_REL], "httpd-2")

    assert " -d " not in commands[0][2]
    first_fault_log = instance.processes[1]["fault_log"]
    second_fault_log = instance.processes[2]["fault_log"]
    assert instance.processes[0]["fault_log"] is None
    assert first_fault_log != second_fault_log
    assert first_fault_log.is_file()
    assert second_fault_log.is_file()
    assert "-d cpu -dfilter 0x400000..0x400fff" in commands[1][2]
    assert "-d cpu -dfilter 0x400000..0x400fff" in commands[2][2]
    assert f"-D /tmp/log/{first_fault_log.name}" in commands[1][2]
    assert f"-D /tmp/log/{second_fault_log.name}" in commands[2][2]


def test_observe_exits_uses_fault_log_bound_to_process(tmp_path):
    instance = bare_supervisor(tmp_path, build_mips_elf())
    process_log = tmp_path / "httpd.log"
    process_log.write_text(
        "pc=0xdeadbeef\n"
        "pid 4321: terminated with signal 11\n"
    )
    fault_log = tmp_path / "httpd.qemu.log"
    fault_log.write_text(
        "pc=0x00400000 HI=0x00000000 LO=0x00000000\n"
        "GPR04: a0 00000001 a1 00000002 a2 00000003 a3 00000004\n"
        "GPR28: gp 10009000 sp 7fff2000 s8 00000000 ra 00400004\n"
    )
    instance.processes = [{
        "label": "httpd-1",
        "process": object(),
        "log": process_log,
        "fault_log": fault_log,
        "offset": 0,
        "partial": b"",
    }]
    instance.target = {
        "pid": 4321,
        "label": "httpd-1",
        "sha256": "a" * 64,
        "intentional_stop": False,
        "exit_recorded": False,
    }
    instance.event = lambda *args, **kwargs: None

    instance.observe_exits()

    record = json.loads((tmp_path / "target-exits.jsonl").read_text())
    assert record["fault_log_path"] == str(fault_log)
    assert record["debug_context"]["pc"] == 0x00400000
    assert record["debug_context"]["ra"] == 0x00400004


def test_replace_refreshes_mappings_before_starting_target(tmp_path):
    instance = bare_supervisor(tmp_path, build_mips_elf(vaddr=0x00400000))
    replacement = tmp_path / "replacement-httpd"
    replacement.write_bytes(build_mips_elf(vaddr=0x00500000))
    mapping_seen_by_start = []
    instance.stop_target = lambda: None
    instance.start_target = lambda: mapping_seen_by_start.append(
        instance._mappings[0]["guest_vaddr"])
    instance.event = lambda *args, **kwargs: None

    instance.replace(replacement)

    assert (instance.root / TARGET_REL).read_bytes() == replacement.read_bytes()
    assert instance._elf_header["entry"] == 0x00500000
    assert instance._mappings[0]["guest_vaddr"] == 0x00500000
    assert mapping_seen_by_start == [0x00500000]
