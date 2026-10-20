"""ELF loader facts for the native PRoot/QEMU MIPS32BE runtime."""
from __future__ import annotations

import struct
import shutil
from pathlib import Path

ELF32_HEADER = struct.Struct(">HHIIIIIHHHHHH")
ELF32_HEADER_NAMES = (
    "type", "machine", "version", "entry", "phoff", "shoff", "flags",
    "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx",
)
ELF32_PROGRAM_HEADER = struct.Struct(">IIIIIIII")


def executable_mappings_from_bytes(data: bytes) -> tuple[list[dict], dict]:
    """Strictly parse file-backed LOAD mappings of an ELF32 BE MIPS image."""
    elf_header_size = 16 + ELF32_HEADER.size
    if len(data) < elf_header_size:
        raise RuntimeError("target has a truncated ELF32 header")
    ident = data[:16]
    if ident[:4] != b"\x7fELF":
        raise RuntimeError("target is not an ELF image")
    if ident[4] != 1 or ident[5] != 2:
        raise RuntimeError("target is not ELF32 big-endian")
    if ident[6] != 1:
        raise RuntimeError("target has an unsupported ELF identification version")

    values = ELF32_HEADER.unpack_from(data, 16)
    header = dict(zip(ELF32_HEADER_NAMES, values, strict=True))
    if header["machine"] != 8:
        raise RuntimeError("target is not MIPS")
    if header["version"] != 1:
        raise RuntimeError("target has an unsupported ELF version")
    if header["ehsize"] != elf_header_size:
        raise RuntimeError("target has an invalid ELF32 header size")

    phnum = header["phnum"]
    phoff = header["phoff"]
    phentsize = header["phentsize"]
    if phnum:
        if phentsize < ELF32_PROGRAM_HEADER.size:
            raise RuntimeError("target has an invalid ELF32 program-header size")
        if phoff < header["ehsize"]:
            raise RuntimeError("target has an invalid ELF32 program-header offset")
        table_end = phoff + phnum * phentsize
        if table_end > len(data):
            raise RuntimeError("target has a truncated ELF32 program-header table")

    mappings = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        (p_type, file_offset, vaddr, paddr, filesz, memsz,
         flags, alignment) = ELF32_PROGRAM_HEADER.unpack_from(data, offset)
        if filesz > memsz:
            raise RuntimeError(f"program header {index} has filesz larger than memsz")
        if file_offset + filesz > len(data):
            raise RuntimeError(f"program header {index} exceeds the target file")
        if vaddr + memsz > 1 << 32:
            raise RuntimeError(f"program header {index} exceeds the ELF32 address space")
        if p_type == 1:
            mappings.append({
                "guest_vaddr": vaddr,
                "file_offset": file_offset,
                "filesz": filesz,
                "memsz": memsz,
                "flags": flags,
                "alignment": alignment,
                "physical_address": paddr,
            })
    if not any(mapping["filesz"] and mapping["flags"] & 1 for mapping in mappings):
        raise RuntimeError("target has no file-backed executable LOAD segment")
    return mappings, header


def executable_mappings(target: Path) -> tuple[list[dict], dict]:
    """Extract validated LOAD mappings and header fields from a MIPS32BE ELF."""
    return executable_mappings_from_bytes(Path(target).read_bytes())


def remove_guest_qemu_logs(runtime: Path) -> None:
    """Bound session disk by discarding completed QEMU CPU traces."""
    log_dir = runtime / "log"
    shutil.rmtree(log_dir, ignore_errors=True)
    log_dir.mkdir(parents=True, exist_ok=True)
