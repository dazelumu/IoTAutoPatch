"""Structural ELF inspection. ASan association does not prove source instrumentation."""
from __future__ import annotations

import re
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


RUNTIME = re.compile(r"(?:libasan\.so(?:\.\d+)*|libclang_rt\.asan(?:_dynamic)?(?:-[\w]+)?\.so(?:\.\d+)*)\Z")


def elf_evidence(path: Path) -> dict:
    empty = {"elf_type": None, "runtime_target": False, "asan": False,
             "asan_evidence": {"needed": [], "symbols": []}, "asan_runtime": False}
    try:
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                return empty
            stream.seek(0)
            elf = ELFFile(stream)
            size = path.stat().st_size
            header = elf.header
            if header["e_version"] != "EV_CURRENT" or header["e_ehsize"] != elf.structs.Elf_Ehdr.sizeof():
                return empty
            for offset, count, entry_size, expected in (
                (header["e_phoff"], elf.num_segments(), header["e_phentsize"], elf.structs.Elf_Phdr.sizeof()),
                (header["e_shoff"], elf.num_sections(), header["e_shentsize"], elf.structs.Elf_Shdr.sizeof()),
            ):
                if count and (not offset or entry_size != expected or offset + count * entry_size > size):
                    return empty
            segments = list(elf.iter_segments())
            sections = list(elf.iter_sections())
            if any(s["p_offset"] + s["p_filesz"] > size or
                   (s["p_type"] == "PT_LOAD" and s["p_filesz"] > s["p_memsz"]) for s in segments):
                return empty
            if any(s["sh_type"] not in {"SHT_NOBITS", "SHT_NULL"} and
                   s["sh_offset"] + s["sh_size"] > size for s in sections):
                return empty

            symbols = set()
            defined = set()

            def collect(table):
                for symbol in table.iter_symbols():
                    name = symbol.name
                    if name == "__asan_init" or name.startswith("__asan_report_"):
                        # UND references are required for Clang instrumented DSOs.
                        symbols.add((name, str(symbol["st_shndx"])))
                        if symbol["st_shndx"] != "SHN_UNDEF":
                            defined.add(name)

            for section in sections:
                if isinstance(section, SymbolTableSection):
                    if section["sh_entsize"] != elf.structs.Elf_Sym.sizeof():
                        return empty
                    collect(section)
            needed, sonames = set(), set()
            for segment in segments:
                if isinstance(segment, DynamicSegment):
                    entry_size = elf.structs.Elf_Dyn.sizeof()
                    if segment["p_filesz"] % entry_size:
                        return empty
                    tags = []
                    for index in range(segment["p_filesz"] // entry_size):
                        tag = segment.get_tag(index)
                        tags.append(tag)
                        if tag["d_tag"] == "DT_NULL":
                            break
                    if not tags or tags[-1]["d_tag"] != "DT_NULL":
                        return empty
                    needed.update(t.needed for t in tags if t["d_tag"] == "DT_NEEDED" and RUNTIME.fullmatch(t.needed))
                    sonames.update(t.soname for t in tags if t["d_tag"] == "DT_SONAME")
                    if not any(isinstance(s, SymbolTableSection) for s in sections) and any(t["d_tag"] == "DT_SYMTAB" for t in tags):
                        collect(segment)
            kind = header["e_type"]
            target = kind in {"ET_EXEC", "ET_DYN"} and any(
                s["p_type"] == "PT_LOAD" and s["p_flags"] & 1 and s["p_filesz"] for s in segments)
            runtime = (kind == "ET_DYN" and bool(RUNTIME.fullmatch(path.name)) and
                       (not sonames or any(RUNTIME.fullmatch(n) for n in sonames)) and
                       "__asan_init" in defined and any(n.startswith("__asan_report_") for n in defined))
            return {"elf_type": kind, "runtime_target": bool(target), "asan": bool(needed or symbols),
                    "asan_evidence": {"needed": sorted(needed),
                                      "symbols": [{"name": n, "section": s} for n, s in sorted(symbols)]},
                    "asan_runtime": bool(runtime)}
    except (OSError, ELFError, ValueError, KeyError, IndexError, TypeError, AssertionError):
        # Malformed/truncated files are never accepted as runtime targets.
        return empty
