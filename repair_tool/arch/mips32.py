"""MIPS32 (big-endian, o32) architecture backend.

Owns everything CPU-specific: ELF32 MIPS segment/symbol/GOT parsing, opcode
encoding (lw/jalr/lui/ori/nop), validation of a model-selected indirect call
site and the re-encoding used to redirect that call into implanted repair
code.
No device names, addresses or sizes appear here.

Encoding reference (verified against the DIR-825 httpd binary):
  lw  $t9, off($gp)  -> 0x8f99....  opcode 0x23, base 28, rt 25
  jalr $t9           -> 0x0320f809  SPECIAL (opcode 0) funct 0x09, rs 25, rd 31
  lui $t9, imm       -> 0x3c19....  opcode 0x0F, rs 0, rt 25
  ori $t9, $t9, imm  -> 0x3739....  opcode 0x0D, rs 25, rt 25
Call sequence at a site: [lw $t9,off($gp)][nop][jalr $t9][delay slot].
The delay slot executes before the jump and must be preserved by a redirect.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .names import (MIPS32BE, MIPS32BE_E_FLAGS_ABI_MASK,
                    MIPS32BE_E_FLAGS_ABI_O32, MIPS32BE_E_FLAGS_MICROMIPS)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

OPCODE_LW = 0x23
OPCODE_ORI = 0x0D
OPCODE_LUI = 0x0F
OPCODE_SPECIAL = 0x00
FUNCT_JALR = 0x09
REG_GP = 28
REG_T9 = 25
NOP = 0x00000000

# [lw][nop][jalr][delay slot] -- 16 bytes replaced by [lui][ori][jalr][delay].
CALL_SEQUENCE_SPAN = 16
EF_MIPS_ABI_MASK = MIPS32BE_E_FLAGS_ABI_MASK
EF_MIPS_ABI_O32 = MIPS32BE_E_FLAGS_ABI_O32
EF_MIPS_MICROMIPS = MIPS32BE_E_FLAGS_MICROMIPS


def encode_lw(rt: int, base: int, offset: int) -> int:
    return (OPCODE_LW << 26) | (base << 21) | (rt << 16) | (offset & 0xFFFF)


def encode_ori(rs: int, rt: int, imm: int) -> int:
    return (OPCODE_ORI << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def encode_lui(rt: int, imm: int) -> int:
    return (OPCODE_LUI << 26) | (rt << 16) | (imm & 0xFFFF)


def encode_jalr(rs: int, rd: int = 31, shamt: int = 0) -> int:
    return (OPCODE_SPECIAL << 26) | (rs << 21) | (rd << 11) | (shamt << 6) | FUNCT_JALR


def word_to_bytes(word: int) -> bytes:
    return struct.pack(">I", word & 0xFFFFFFFF)


def bytes_to_word(data: bytes) -> int:
    return struct.unpack(">I", data)[0]


class Mips32BigEndianBackend:
    """Capability and dispatch boundary for the existing MIPS32/o32 backend."""

    name = MIPS32BE
    elf_machine = "MIPS"
    elf_class = "ELF32"
    endianness = "big"
    abi = "o32"
    compiler_target = "mips-linux-gnu"
    compiler_flags = ("-march=mips32", "-mabi=32", "-EB", "-G0")
    call_sequence = "lw $t9; nop; jalr $t9; delay"
    redirect_sequence = "lui/ori/jalr/original delay"
    call_sequence_span = CALL_SEQUENCE_SPAN

    def capability_report(self) -> dict:
        return {
            "schema": "architecture-capability-v1",
            "architecture": self.name,
            "elf": {
                "machine": self.elf_machine,
                "class": self.elf_class,
                "endianness": self.endianness,
                "abi": self.abi,
            },
            "repair": {
                "call_sequences": [self.call_sequence],
                "redirect_encoder": True,
                "redirect_sequence": self.redirect_sequence,
                "implant_region": True,
                "leaf_function_abi": True,
            },
            "compiler": {
                "target": self.compiler_target,
                "flags": list(self.compiler_flags),
            },
            "unsupported": [],
        }

    def analyze_elf(self, path: Path) -> ElfAnalysis:
        return ElfAnalysis(path)

    def register_patch_site(self, analysis: ElfAnalysis, address: int) -> dict:
        return analysis.indirect_call_at(address)

    def encode_redirect(self, site: dict, implant_address: int) -> bytes:
        """Encode a redirect from a registered 16-byte site record."""
        if not isinstance(site, dict) or not isinstance(site.get("bytes_hex"), str):
            raise ValueError("patch site must contain bytes_hex")
        original = bytes.fromhex(site["bytes_hex"])
        if len(original) != self.call_sequence_span:
            raise ValueError("patch site has the wrong call-sequence size")
        lw, gap, jalr, _ = struct.unpack(">4I", original)
        if ((lw >> 26) != OPCODE_LW
                or ((lw >> 21) & 0x1F) != REG_GP
                or ((lw >> 16) & 0x1F) != REG_T9
                or gap != NOP
                or jalr != encode_jalr(REG_T9)):
            raise ValueError("patch site is not the supported MIPS32BE call sequence")
        if type(implant_address) is not int or implant_address <= 0 or implant_address % 4:
            raise ValueError("implant address must be a positive 4-byte-aligned address")
        hi = (implant_address >> 16) & 0xFFFF
        lo = implant_address & 0xFFFF
        words = [encode_lui(REG_T9, hi), encode_ori(REG_T9, REG_T9, lo),
                 encode_jalr(REG_T9)]
        return b"".join(word_to_bytes(word) for word in words) + original[12:16]

    def find_implant_region(self, analysis: ElfAnalysis, size: int) -> dict:
        return analysis.padding_region(size)

    def compile_repair(self, source: str, workdir: Path,
                       deadline: float | None = None) -> Path:
        # Compile execution remains in the firmware implant stage; the backend
        # owns its target and flags without duplicating subprocess handling.
        from ..firmware.implant import compile_repair_object
        return compile_repair_object(source, workdir, deadline=deadline)


MIPS32BE_BACKEND = Mips32BigEndianBackend()


def _sign_extend16(value: int) -> int:
    return value - 0x10000 if value >= 0x8000 else value


class ElfAnalysis:
    """Static view of an ELF32 MIPS BE executable used by the pipeline."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:6] != b"\x7fELF\x01\x02":
            raise ValueError("Target must be ELF32 big-endian")
        if self.data[18:20] != b"\x00\x08":
            raise ValueError("Target must be MIPS (e_machine=8)")
        e_flags = struct.unpack(">I", self.data[36:40])[0]
        if e_flags & EF_MIPS_MICROMIPS:
            raise ValueError("Target uses microMIPS; only MIPS32BE o32 is supported")
        if e_flags & EF_MIPS_ABI_MASK != EF_MIPS_ABI_O32:
            raise ValueError("Target ABI is not o32; only MIPS32BE o32 is supported")
        self.elf = ELFFile(open(self.path, "rb"))     # closed in close()
        self.sections = {s.name: s for s in self.elf.iter_sections()}
        # Prefer full symbols with values; fall back to dynamic symbols.
        self.symbols = {}
        self.symbol_records: list[dict] = []
        seen_symbols: set[tuple] = set()
        for section in self.elf.iter_sections():
            if section.header["sh_type"] in ("SHT_SYMTAB", "SHT_DYNSYM"):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol["st_value"]:
                        self.symbols.setdefault(symbol.name, symbol["st_value"])
                        record = {
                            "name": symbol.name,
                            "value": symbol["st_value"],
                            "size": symbol["st_size"],
                            "type": symbol["st_info"]["type"],
                            "bind": symbol["st_info"]["bind"],
                        }
                        identity = tuple(record.values())
                        if identity not in seen_symbols:
                            seen_symbols.add(identity)
                            self.symbol_records.append(record)
        self.symbol_records.sort(key=lambda item: (item["value"], item["name"]))

    def close(self):
        self.elf.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # -- segments ----------------------------------------------------------
    def load_segments(self) -> list[dict]:
        """All file-backed PT_LOAD mappings, without interpreting their use."""
        result = []
        for segment in self.elf.iter_segments():
            header = segment.header
            if header["p_type"] == "PT_LOAD":
                result.append({"vaddr": header["p_vaddr"],
                               "filesz": header["p_filesz"],
                               "memsz": header["p_memsz"],
                               "offset": header["p_offset"],
                               "flags": header["p_flags"]})
        return result

    def executable_segments(self) -> list[dict]:
        """PT_LOAD segments with execute permission."""
        return [segment for segment in self.load_segments()
                if segment["flags"] & 0x1]

    def _file_offset(self, vaddr: int) -> int | None:
        for segment in self.elf.iter_segments():
            header = segment.header
            if header["p_type"] != "PT_LOAD":
                continue
            base = header["p_vaddr"]
            if base <= vaddr < base + header["p_filesz"]:
                return header["p_offset"] + (vaddr - base)
        return None

    def vaddr_to_offset(self, vaddr: int) -> int:
        offset = self._file_offset(vaddr)
        if offset is None:
            raise ValueError(f"vaddr {vaddr:#x} not backed by file bytes")
        return offset

    def bytes_at(self, vaddr: int, size: int) -> bytes:
        if type(size) is not int or size < 0:
            raise ValueError("byte range size must be a non-negative integer")
        for segment in self.load_segments():
            if segment["vaddr"] <= vaddr and vaddr + size <= \
                    segment["vaddr"] + segment["filesz"]:
                offset = segment["offset"] + vaddr - segment["vaddr"]
                if offset + size <= len(self.data):
                    return self.data[offset:offset + size]
        raise ValueError("Requested range is not entirely file-backed in one LOAD segment")

    def read_word(self, vaddr: int) -> int | None:
        try:
            data = self.bytes_at(vaddr, 4)
        except ValueError:
            return None
        return struct.unpack(">I", data)[0]

    def symbol(self, name: str) -> int | None:
        return self.symbols.get(name)

    def matching_symbols(self, contains: str = "") -> list[dict]:
        """Return symbols matching model-provided text in stable address order."""
        return [dict(record) for record in self.symbol_records
                if contains in record["name"]]

    def ascii_matches(self, text: str) -> list[int]:
        """Virtual addresses of exact ASCII text in file-backed LOAD segments."""
        needle = text.encode("ascii")
        matches: list[int] = []
        for segment in self.load_segments():
            start = segment["offset"]
            end = min(start + segment["filesz"], len(self.data))
            cursor = start
            while True:
                found = self.data.find(needle, cursor, end)
                if found < 0:
                    break
                matches.append(segment["vaddr"] + found - start)
                cursor = found + 1
        return matches

    def relocations(self) -> list[dict]:
        result = []
        for section in self.elf.iter_sections():
            if isinstance(section, RelocationSection):
                for rel in section.iter_relocations():
                    result.append({"offset": rel["r_offset"],
                                   "type": rel["r_info_type"]})
        return result

    # -- $gp / GOT ---------------------------------------------------------
    def _gp_value(self) -> int:
        if "_gp" in self.symbols:
            return self.symbols["_gp"]
        # .reginfo ri_gp_value: authoritative for o32 executables.
        reginfo = self.sections.get(".reginfo")
        if reginfo is not None and reginfo["sh_size"] >= 24:
            offset = reginfo["sh_offset"] + 20
            value = struct.unpack(">I", self.data[offset:offset + 4])[0]
            if value:
                return value
        if "_GLOBAL_OFFSET_TABLE_" in self.symbols:
            return self.symbols["_GLOBAL_OFFSET_TABLE_"]
        # o32 linker convention: _gp = .got start + 0x7ff0 (mid-GOT, so
        # %call16 offsets stay positive 16-bit). Derive from the .got or
        # DT_PLTGOT when no _gp symbol exists (lld-built binaries).
        got = self.sections.get(".got")
        if got is not None and got["sh_addr"]:
            return got["sh_addr"] + 0x7FF0
        for segment in self.elf.iter_segments():
            if segment.header["p_type"] == "PT_DYNAMIC":
                for tag in segment.iter_tags():
                    if tag.entry.d_tag == "DT_PLTGOT" and tag.entry.d_val:
                        return tag.entry.d_val + 0x7FF0
        raise ValueError("Cannot locate $gp base for GOT addressing")

    def _dynsym_by_value(self) -> dict[int, str]:
        mapping: dict[int, str] = {}
        for section in self.elf.iter_sections():
            # Both .dynsym and .symtab: lld-built executables keep locally
            # defined callees only in .symtab, while .MIPS.stubs-style
            # firmware (real DIR-825 httpd) stores the stub address in the
            # st_value of an UNDEF dynsym entry -- both must map.
            if section.header["sh_type"] in ("SHT_DYNSYM", "SHT_SYMTAB"):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol["st_value"]:
                        mapping.setdefault(symbol["st_value"], symbol.name)
        return mapping

    def _relocation_got_map(self) -> dict[int, str]:
        got_map: dict[int, str] = {}
        for section in self.elf.iter_sections():
            if isinstance(section, RelocationSection):
                table = self.elf.get_section(section.header["sh_link"])
                for rel in section.iter_relocations():
                    got_map[rel["r_offset"]] = table.get_symbol(
                        rel["r_info_sym"]).name
        return got_map

    def indirect_call_at(self, vaddr: int) -> dict:
        """Validate and describe one model-selected redirectable call site.

        The caller supplies the address.  This method never searches for or
        ranks sites.  A valid site is the exact 16-byte o32 sequence used by
        the redirect encoder: ``lw $t9,off($gp); nop; jalr $t9; delay``.
        """
        if type(vaddr) is not int or vaddr <= 0 or vaddr % 4:
            raise ValueError("patch site must be a positive 4-byte-aligned address")
        home = [segment for segment in self.executable_segments()
                if segment["vaddr"] <= vaddr
                and vaddr + CALL_SEQUENCE_SPAN <=
                segment["vaddr"] + segment["filesz"]]
        if not home:
            raise ValueError("patch site is not a 16-byte file-backed executable range")
        original = self.bytes_at(vaddr, CALL_SEQUENCE_SPAN)
        lw, gap, jalr, delay = struct.unpack(">4I", original)
        if (lw >> 26) != OPCODE_LW \
                or ((lw >> 21) & 0x1F) != REG_GP \
                or ((lw >> 16) & 0x1F) != REG_T9:
            raise ValueError("patch site does not start with lw $t9,off($gp)")
        if gap != NOP:
            raise ValueError("patch site has no nop between lw and jalr")
        if jalr != encode_jalr(REG_T9):
            raise ValueError("patch site does not contain canonical jalr $t9")

        gp = self._gp_value()
        got_vaddr = gp + _sign_extend16(lw & 0xFFFF)
        callee = self._relocation_got_map().get(got_vaddr)
        slot_value = self.read_word(got_vaddr)
        if callee is None and slot_value is not None:
            callee = self._dynsym_by_value().get(slot_value)
        return {"vaddr": vaddr, "bytes_hex": original.hex(),
                "got_vaddr": got_vaddr, "got_value": slot_value,
                "callee": callee, "delay_slot_hex": word_to_bytes(delay).hex()}

    def indirect_calls(self, contains: str) -> list[dict]:
        """Resolved canonical indirect calls matching model-provided text.

        This is a neutral index, not a vulnerability candidate scan: callers
        choose the text and receive every matching resolved callee in address
        order. No built-in function names or ranking enter this path.
        """
        gp = self._gp_value()
        reloc_map = self._relocation_got_map()
        value_map = self._dynsym_by_value()
        sites = []
        for segment in self.executable_segments():
            start = segment["vaddr"]
            end = start + segment["filesz"]
            for vaddr in range(start, end - CALL_SEQUENCE_SPAN + 1, 4):
                lw, gap, jalr, delay = struct.unpack(
                    ">4I", self.bytes_at(vaddr, CALL_SEQUENCE_SPAN))
                if (lw >> 26) != OPCODE_LW \
                        or ((lw >> 21) & 0x1F) != REG_GP \
                        or ((lw >> 16) & 0x1F) != REG_T9 \
                        or gap != NOP \
                        or jalr != encode_jalr(REG_T9):
                    continue
                got_vaddr = gp + _sign_extend16(lw & 0xFFFF)
                callee = reloc_map.get(got_vaddr)
                if callee is None:
                    slot_value = self.read_word(got_vaddr)
                    if slot_value is not None:
                        callee = value_map.get(slot_value)
                if callee is None or contains not in callee:
                    continue
                sites.append({"vaddr": vaddr, "callee": callee,
                              "got_vaddr": got_vaddr,
                              "bytes_hex": self.bytes_at(
                                  vaddr, CALL_SEQUENCE_SPAN).hex(),
                              "delay_slot_hex": word_to_bytes(delay).hex()})
        return sites

    def direct_callers(self, target: int) -> list[dict]:
        """Direct MIPS JAL sites targeting a model-provided address."""
        if type(target) is not int or target <= 0 or target % 4:
            raise ValueError("target must be a positive 4-byte-aligned address")
        callers = []
        for segment in self.executable_segments():
            start = segment["vaddr"]
            end = start + segment["filesz"]
            for site in range(start, end - 7, 4):
                word = self.read_word(site)
                if word is None or word >> 26 != 0x03:  # JAL
                    continue
                resolved = ((site + 4) & 0xF0000000) \
                    | ((word & 0x03FFFFFF) << 2)
                if resolved == target:
                    callers.append({
                        "vaddr": site, "target": target,
                        "bytes_hex": self.bytes_at(site, 8).hex(),
                    })
        return callers

    # -- danger scan -------------------------------------------------------
    def call_sites(self, callee_names: tuple[str, ...] = ("strcat", "strcpy",
                                                          "sprintf", "vsprintf")) -> list[dict]:
        """Find `lw $t9,off($gp); nop; jalr $t9; <delay>` sequences and
        resolve the callee each GOT slot targets.

        Resolution order: a dynamic relocation at the slot address, else the
        slot's current value matched against dynamic symbol values (covers
        .MIPS.stubs-style binaries where the slot holds a stub address that
        the dynsym entry also points at). Sites with unresolvable callees are
        skipped: they cannot be safely named in evidence."""
        names = set(callee_names)
        return [site for site in self.indirect_calls("")
                if site["callee"] in names]

    # -- patch encoding ----------------------------------------------------
    def redirect_words(self, site_vaddr: int, target_vaddr: int) -> bytes:
        """Encode `lui $t9,hi; ori $t9,$t9,lo; jalr $t9; <original delay>`
        replacing the 16-byte call sequence at site_vaddr. The original delay
        slot word is preserved verbatim: it executes before the jump both
        before and after the redirect."""
        original = self.bytes_at(site_vaddr, CALL_SEQUENCE_SPAN)
        delay = original[12:16]
        hi = (target_vaddr >> 16) & 0xFFFF
        lo = target_vaddr & 0xFFFF
        # ori zero-extends: (hi<<16)|lo reconstructs target exactly.
        words = [encode_lui(REG_T9, hi), encode_ori(REG_T9, REG_T9, lo),
                 encode_jalr(REG_T9)]
        return b"".join(word_to_bytes(w) for w in words) + delay

    def padding_region(self, min_size: int) -> dict:
        """First executable PT_LOAD whose file padding after its data can host
        `min_size` bytes without moving anything (p_filesz/p_memsz grow to
        cover the implant; nothing else shifts)."""
        for region in self.executable_padding_regions():
            if min_size <= region["capacity"]:
                return region
        raise ValueError(f"No executable padding region >= {min_size} bytes")

    def executable_padding_regions(self, *, alignment: int = 8,
                                   page: int = 0x1000) -> list[dict]:
        """Safe, aligned file padding after executable load segments.

        Extending a segment must not consume another LOAD mapping, a real ELF
        section, the section-header table, or an existing zero-initialized
        tail (``p_memsz > p_filesz``).  The previous implementation considered
        only the next *executable* segment and calculated capacity before
        alignment, which could overrun the real boundary by up to seven bytes.
        """
        if alignment <= 0 or alignment & (alignment - 1):
            raise ValueError("alignment must be a positive power of two")
        loads = self.load_segments()
        executable = sorted(self.executable_segments(),
                            key=lambda item: item["vaddr"])
        regions: list[dict] = []
        section_ranges: list[tuple[int, int]] = []
        for section in self.elf.iter_sections():
            header = section.header
            if header["sh_type"] == "SHT_NOBITS" or not header["sh_size"]:
                continue
            start = int(header["sh_offset"])
            section_ranges.append((start, start + int(header["sh_size"])))
        shoff = int(self.elf.header["e_shoff"])
        shsize = (int(self.elf.header["e_shentsize"])
                  * int(self.elf.header["e_shnum"]))
        if shoff and shsize:
            section_ranges.append((shoff, shoff + shsize))

        for segment_index, segment in enumerate(executable):
            # Turning an existing BSS tail into file-backed executable bytes
            # changes program state.  Reject this segment instead of silently
            # consuming that zero-initialized range.
            if segment["memsz"] != segment["filesz"]:
                continue
            data_end = segment["offset"] + segment["filesz"]
            memory_end = segment["vaddr"] + segment["memsz"]
            file_limit = min(len(self.data),
                             ((data_end + page - 1) // page) * page)
            memory_limit = segment["vaddr"] + (file_limit - segment["offset"])

            for other in loads:
                if (other["offset"] == segment["offset"]
                        and other["vaddr"] == segment["vaddr"]):
                    continue
                start = other["offset"]
                end = start + other["filesz"]
                if end > data_end:
                    file_limit = min(file_limit,
                                     data_end if start <= data_end else start)
                vstart = other["vaddr"]
                vend = vstart + other["memsz"]
                if vend > memory_end:
                    memory_limit = min(
                        memory_limit,
                        memory_end if vstart <= memory_end else vstart)

            for start, end in section_ranges:
                if end > data_end:
                    file_limit = min(file_limit,
                                     data_end if start <= data_end else start)

            padding = (-memory_end) & (alignment - 1)
            start_vaddr = memory_end + padding
            start_offset = data_end + padding
            mapped_file_limit = (segment["vaddr"]
                                 + file_limit - segment["offset"])
            limit_vaddr = min(memory_limit, mapped_file_limit)
            capacity = min(file_limit - start_offset,
                           limit_vaddr - start_vaddr)
            if capacity > 0:
                regions.append({"vaddr": start_vaddr,
                                "offset": start_offset,
                                "capacity": capacity,
                                "limit_vaddr": start_vaddr + capacity,
                                "segment_index": segment_index})
        return regions
