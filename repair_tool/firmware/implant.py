"""Implant stage: cross-compile the proposed repair C, validate the object
file, and generate the patched candidate binary.

Pipeline per edit:
  1. clang --target=mips-linux-gnu -march=mips32 -EB -G0 -c  (cross compile)
  2. object validation: exactly one defined function named repair_entry,
     no relocations, no undefined symbols (leaf, self-contained)
  3. locate an executable PT_LOAD padding region; place the function bytes
  4. extend p_filesz/p_memsz of that segment (explicit, no implicit shifts)
  5. replace the 16-byte call site with lui/ori/jalr redirecting $t9 at the
     implant (original delay slot preserved)
The result is a candidate binary plus a machine-checkable patch record.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import hashlib
import time
from pathlib import Path

from ..arch.mips32 import (CALL_SEQUENCE_SPAN, ElfAnalysis, encode_jalr,
                           encode_ori, encode_lui, word_to_bytes)
from ..arch.registry import architecture_backend
from ..config import RepairError
from ..storage import sha

CLANG = "clang"
# -O0 keeps every branch PC-relative (b/beq/bne): clang uses absolute `j`
# (R_MIPS_26 against .text) for long-range jumps at -O1+, which cannot be
# transplanted to an arbitrary implant address. -G0 keeps $gp at bay for
# freestanding leaf code; -ffreestanding removes any libc assumptions.
MIPS32BE = architecture_backend("mips32be")
COMPILE_FLAGS = [f"--target={MIPS32BE.compiler_target}", *MIPS32BE.compiler_flags,
                 "-O0", "-fno-pic", "-fno-builtin", "-ffreestanding", "-c"]
MAX_CODE_BYTES = 2048


def compile_repair_object(source: str, workdir: Path,
                          deadline: float | None = None) -> Path:
    """Cross-compile the repair C source to a MIPS32 BE relocatable object."""
    workdir.mkdir(parents=True, exist_ok=True)
    source_path = workdir / "repair.c"
    source_path.write_text(source, encoding="utf-8")
    object_path = workdir / "repair.o"
    argv = [CLANG, *COMPILE_FLAGS, str(source_path), "-o", str(object_path)]
    compile_timeout = 60.0
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RepairError("infrastructure_failed",
                              "firmware.total_timeout_seconds exceeded")
        compile_timeout = min(compile_timeout, remaining)
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=compile_timeout)
    except FileNotFoundError as exc:
        raise RepairError("infrastructure_failed",
                          "clang not available for cross compilation") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepairError("infrastructure_failed", "clang timed out") from exc
    if result.returncode != 0:
        raise RepairError("repair_invalid",
                          f"Repair source failed to compile: {result.stderr[:400]}")
    return object_path


def validate_repair_object(object_path: Path) -> dict:
    """The object must be a leaf: one function, no undefined symbols, and the
    only allowed relocations are R_MIPS_26 branch/jump entries against the
    object's own .text section (rebased to the implant address at build
    time). Everything else is rejected."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    with open(object_path, "rb") as stream:
        elf = ELFFile(stream)
        if elf.header["e_machine"] != "EM_MIPS" or elf.elfclass != 32 \
                or elf.little_endian or elf.header["e_type"] != "ET_REL":
            raise RepairError("repair_invalid",
                              "Repair object must be an ELF32 big-endian "
                              "MIPS ET_REL object")
        for section in elf.iter_sections():
            if section.header["sh_flags"] & 0x2 and section.name != ".text":
                if section.name in {".data", ".bss"} \
                        and int(section.header["sh_size"]) == 0:
                    continue
                if section.header["sh_type"] in {
                        "SHT_MIPS_REGINFO", "SHT_MIPS_ABIFLAGS"}:
                    continue
                raise RepairError(
                    "repair_invalid",
                    f"Repair object has an unsupported allocated section: "
                    f"{section.name}; all executable code/data must be in .text")
        defined_functions = []
        undefined = []
        repair_entry_symbol = None
        for section in elf.iter_sections():
            if section.header["sh_type"] == "SHT_SYMTAB":
                for symbol in section.iter_symbols():
                    if symbol["st_info"]["type"] != "STT_FUNC":
                        continue
                    if symbol["st_shndx"] == "SHN_UNDEF":
                        undefined.append(symbol.name)
                    elif symbol.name:
                        defined_functions.append(symbol.name)
                        if symbol.name == "repair_entry":
                            repair_entry_symbol = symbol
        if defined_functions != ["repair_entry"]:
            raise RepairError("repair_invalid",
                              f"Object must define exactly repair_entry, got: "
                              f"{defined_functions or 'nothing'}")
        if repair_entry_symbol is None:
            raise RepairError("repair_invalid",
                              "repair_entry symbol is missing")
        if undefined:
            raise RepairError("repair_invalid",
                              f"Repair must be self-contained (no external refs): {undefined}")
        # Collect relocations. Allowed: R_MIPS_26 (type 4) against the
        # object's own .text (PC-region jumps) and anything in non-alloc
        # sections (.pdr debug records). All others make the implant
        # address-dependent in ways we cannot rebase.
        text = elf.get_section_by_name(".text")
        if text is None or not text.data():
            raise RepairError("repair_invalid", "Object has no .text")
        text_index = elf.get_section_index(".text")
        entry_value = int(repair_entry_symbol["st_value"])
        entry_size = int(repair_entry_symbol["st_size"])
        if repair_entry_symbol["st_shndx"] != text_index or entry_value != 0 \
                or entry_size <= 0 or entry_size % 4 or entry_size > len(text.data()):
            raise RepairError(
                "repair_invalid",
                "repair_entry must start at offset 0 in .text and be "
                "word-aligned")
        jumps: list[dict] = []
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            target = elf.get_section(section.header["sh_info"])
            if target is None or not (target.header["sh_flags"] & 0x2):  # SHF_ALLOC
                continue                                  # debug section: fine
            symtab = elf.get_section(section.header["sh_link"])
            for rel in section.iter_relocations():
                symbol = symtab.get_symbol(rel["r_info_sym"])
                # pyelftools reports STT_SECTION symbols with an empty name;
                # identify the object's own .text via st_shndx instead.
                own_text = (symbol["st_info"]["type"] == "STT_SECTION"
                            and symbol["st_shndx"] == text_index)
                if section.name == ".rel.text" and rel["r_info_type"] == 4 \
                        and own_text and target.name == ".text":
                    # J-type jump to the object's own .text: rebased at
                    # implant time (link-time .text base is 0).
                    offset = int(rel["r_offset"])
                    if offset < 0 or offset % 4 or offset + 4 > len(text.data()):
                        raise RepairError(
                            "repair_invalid",
                            "R_MIPS_26 relocation has an invalid text offset")
                    word = struct.unpack(">I", text.data()[offset:offset + 4])[0]
                    if word >> 26 not in (2, 3):
                        raise RepairError(
                            "repair_invalid",
                            "R_MIPS_26 relocation is not attached to J/JAL")
                    jumps.append({"offset": offset})
                    continue
                raise RepairError("repair_invalid",
                                  f"Object has an unsupported relocation "
                                  f"(type {rel['r_info_type']} against "
                                  f"'{symbol.name}' in {target.name}); "
                                  "leaf code must be position-independent")
        code = text.data()
        if len(code) > MAX_CODE_BYTES:
            raise RepairError("repair_invalid",
                              f"Repair code exceeds {MAX_CODE_BYTES} bytes")
        if len(code) % 4:
            raise RepairError("repair_invalid", "Repair code not word-aligned")
    return {"code_hex": code.hex(), "size": len(code),
            "function": "repair_entry", "jumps": jumps}


def build_candidate(target: Path, edits: list[dict], out_dir: Path, *,
                    code_hex_by_site: dict[int, str] | None = None,
                    deadline: float | None = None) -> dict:
    """Produce the patched candidate binary from validated edits.

    Multi-edit correctness: each edit's compiled code goes into its OWN
    padding region and each call site redirects to ITS implant -- edits are
    never silently merged. Placement is sequential: implant i+1 starts after
    implant i within the same padding block, moving to the next block when
    the current one is exhausted. code_hex_by_site lets tests inject the
    compiled code without invoking clang."""
    if not edits:
        raise RepairError("repair_invalid", "No edits to implant")
    out_dir.mkdir(parents=True, exist_ok=True)
    with MIPS32BE.analyze_elf(target) as analysis:
        # Verify each edit still matches the target bytes (stale proposal guard).
        for edit in edits:
            actual = analysis.bytes_at(edit["site"], CALL_SEQUENCE_SPAN)
            if actual.hex() != edit["expected_hex"]:
                raise RepairError("repair_invalid",
                                  f"Site {edit['site']:#x} bytes changed since evidence; "
                                  "proposal is stale")
        codes: list[bytes] = []
        jump_tables: list[list[dict]] = []
        artifacts: list[dict] = []
        for edit_index, edit in enumerate(edits, start=1):
            if code_hex_by_site is not None:
                code = bytes.fromhex(code_hex_by_site[edit["site"]])
                codes.append(code)
                jump_tables.append([])
                artifacts.append({
                    "site": edit["site"], "source": None, "object": None,
                    "source_sha256": hashlib.sha256(
                        edit["source"].encode("utf-8")).hexdigest(),
                    "object_sha256": None,
                    "code_sha256": hashlib.sha256(code).hexdigest(),
                    "sha256": hashlib.sha256(code).hexdigest(),
                })
            else:
                # Preserve every edit's source/object pair.  A single-edit
                # build keeps the historical top-level paths for compatibility.
                workdir = (out_dir if len(edits) == 1 else
                           out_dir / f"edit-{edit_index:03d}")
                object_path = compile_repair_object(edit["source"], workdir,
                                                   deadline=deadline)
                verdict = validate_repair_object(object_path)
                codes.append(bytes.fromhex(verdict["code_hex"]))
                jump_tables.append(verdict["jumps"])
                code = codes[-1]
                artifacts.append({
                    "site": edit["site"],
                    "source": str((workdir / "repair.c").relative_to(out_dir)),
                    "object": str(object_path.relative_to(out_dir)),
                    "source_sha256": sha(workdir / "repair.c"),
                    "object_sha256": sha(object_path),
                    "code_sha256": hashlib.sha256(code).hexdigest(),
                    "sha256": sha(object_path),
                })
            if len(code) > MAX_CODE_BYTES or len(code) % 4:
                raise RepairError("repair_invalid", "Implant code invalid size")
            if not code:
                raise RepairError("repair_invalid", "Implant code is empty")
        # Sequential placement: cursor walks the padding blocks in vaddr
        # order; every edit gets its own region (no shared implants).
        segments = sorted(analysis.executable_segments(), key=lambda s: s["vaddr"])
        blocks = analysis.executable_padding_regions(alignment=8)
        placements: list[dict] = []   # per-edit {vaddr, segment_index, file_off}
        cursor = {"block": None, "end": 0, "limit": 0, "next_index": 0}
        for code in codes:
            placed = False
            block = cursor["block"]
            if block is not None:
                # Try to continue in the current block, 8-byte aligned.
                start = (cursor["end"] + 7) & ~7
                if start + len(code) <= cursor["limit"]:
                    placements.append({"vaddr": start,
                                       "segment_index": block,
                                       "file_off": segments[block]["offset"] + (start - segments[block]["vaddr"])})
                    cursor["end"] = start + len(code)
                    placed = True
            if not placed:
                # Advance to the next block that can host this code.
                while cursor["next_index"] < len(blocks):
                    block_info = blocks[cursor["next_index"]]
                    index = block_info["segment_index"]
                    capacity = block_info["capacity"]
                    if len(code) <= capacity:
                        start = block_info["vaddr"]
                        placements.append({"vaddr": start, "segment_index": index,
                                           "file_off": block_info["offset"]})
                        cursor = {"block": index, "end": start + len(code),
                                  "limit": block_info["limit_vaddr"],
                                  "next_index": cursor["next_index"] + 1}
                        placed = True
                        break
                    cursor["next_index"] += 1
            if not placed:
                raise RepairError("repair_invalid",
                                  "No executable padding for all implants")
        data = bytearray(analysis.data)
        implants = []
        # 1. Write each implant and rebase its intra-section jumps.
        for edit, code, place, jumps in zip(edits, codes, placements, jump_tables):
            file_off, implant_vaddr = place["file_off"], place["vaddr"]
            if file_off + len(code) > len(data):
                raise RepairError("repair_invalid",
                                  "Implant would exceed file bounds")
            implant = bytearray(code)
            for jump in jumps:
                off = jump["offset"]
                word = struct.unpack(">I", implant[off:off + 4])[0]
                imm26 = word & 0x3FFFFFF
                new_target = implant_vaddr + imm26 * 4
                if imm26 * 4 >= len(implant):
                    raise RepairError(
                        "repair_invalid",
                        "Rebased jump target leaves the repair text")
                jump_pc = implant_vaddr + off
                if (new_target >> 28) != ((jump_pc + 4) >> 28):
                    raise RepairError("repair_invalid",
                                      "Rebased jump leaves the 256MB region")
                word = (word & 0xFC000000) | ((new_target >> 2) & 0x3FFFFFF)
                struct.pack_into(">I", implant, off, word)
            data[file_off:file_off + len(code)] = implant
            implants.append({"site": edit["site"], "vaddr": implant_vaddr,
                             "size": len(code), "hex": bytes(implant).hex(),
                             "rebased_jumps": len(jumps)})
        # 2. Extend each touched segment header (file + mem) to cover its
        #    implants; segment vaddr are unique keys for patch_phdr.
        touched: dict[int, int] = {}
        for place, code in zip(placements, codes):
            seg_vaddr = segments[place["segment_index"]]["vaddr"]
            end = place["vaddr"] + len(code)
            touched[seg_vaddr] = max(touched.get(seg_vaddr, end), end)
        for seg_vaddr, max_end in touched.items():
            seg = next(s for s in segments if s["vaddr"] == seg_vaddr)
            extend_by = max_end - (seg["vaddr"] + seg["filesz"])
            if extend_by > 0:
                patch_phdr(data, analysis, seg, filesz_delta=extend_by,
                           memsz_delta=extend_by)
        # 3. Redirect each call site to ITS OWN implant (edit i -> implant i).
        for edit, place in zip(edits, placements):
            redirect = analysis.redirect_words(edit["site"], place["vaddr"])
            site_off = analysis.vaddr_to_offset(edit["site"])
            data[site_off:site_off + CALL_SEQUENCE_SPAN] = redirect
        candidate = out_dir / "candidate"
        candidate.write_bytes(bytes(data))
        # qemu (and real firmware loaders) require the exec bit on the image;
        # qemu-mips silently exits 1 without it.
        candidate.chmod(0o755)
        record = {
            "target_sha256": sha(target),
            "candidate_sha256": sha(candidate),
            "implants": implants,
            "artifacts": artifacts,
            "edits": [{"site": e["site"], "expected_hex": e["expected_hex"],
                       "redirect_hex": analysis.redirect_words(
                           e["site"], place["vaddr"]).hex(),
                       "implant_vaddr": place["vaddr"]}
                      for e, place in zip(edits, placements)],
        }
        return {"candidate": candidate, "record": record}


def patch_phdr(data: bytearray, analysis: ElfAnalysis, segment: dict, *,
               filesz_delta: int, memsz_delta: int) -> None:
    """Extend one PT_LOAD header in place. Program headers live right after
    the ELF header; each entry is 32 bytes (ELF32). The patched values must
    stay within the containing page block (checked by the caller's bounds)."""
    phoff = analysis.elf.header["e_phoff"]
    phentsize = analysis.elf.header["e_phentsize"]
    index = 0
    for current in analysis.elf.iter_segments():
        if current.header["p_type"] == "PT_LOAD" \
                and current.header["p_vaddr"] == segment["vaddr"]:
            break
        index += 1
    entry = phoff + index * phentsize
    # ELF32 Phdr layout: p_type(4) p_offset(4) p_vaddr(4) p_paddr(4)
    #                    p_filesz(4) p_memsz(4) p_flags(4) p_align(4)
    filesz_off = entry + 16
    memsz_off = entry + 20
    filesz = struct.unpack(">I", data[filesz_off:filesz_off + 4])[0]
    memsz = struct.unpack(">I", data[memsz_off:memsz_off + 4])[0]
    struct.pack_into(">I", data, filesz_off, filesz + filesz_delta)
    struct.pack_into(">I", data, memsz_off, memsz + memsz_delta)
