"""M4: MIPS32 backend, evidence ledger and query session tests."""
from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import pytest

from repair_tool.arch.mips32 import (ElfAnalysis, bytes_to_word,
                                     encode_jalr, encode_lui, encode_lw,
                                     encode_ori, word_to_bytes)
from repair_tool.arch.registry import architecture_backend
from repair_tool.config import RepairError
from repair_tool.firmware.evidence import EvidenceLedger
from repair_tool.firmware import query as query_module
from repair_tool.firmware.query import EvidenceSession

HTTPD = Path("/home/lumu/firmware-lab/dir825-b-2.03/work/rootfs-full/sbin/httpd")


# ------------------------------------------------------------ opcode encoding

def test_opcode_encoding_roundtrip():
    # Reference encodings verified against real DIR-825 httpd words.
    lw = encode_lw(25, 28, 0x862C)          # 0x8f99862c
    assert lw == 0x8F99862C
    assert bytes_to_word(word_to_bytes(lw)) == lw
    jalr = encode_jalr(25)                   # 0x0320f809
    assert jalr == 0x0320F809
    lui, ori = encode_lui(25, 0x1234), encode_ori(25, 25, 0xBEEF)
    assert lui == 0x3C191234 and ori == 0x3739BEEF


# ------------------------------------------------------------ synthetic ELF

SYNTHETIC_ASM = r"""
/* Classic o32 GOT call sequence written by hand with %call16, exactly
   matching the DIR-825 httpd pattern (`lw $t9,off($gp); nop; jalr $t9;
   delay`). concat_impl is defined in the same executable so the linker
   fills the GOT slot with its address. The exec segment is padded to a
   0x1000 file boundary, mimicking old-GNU-ld firmware layouts. */

    .set noreorder
    .set noat

    .text
    .globl entry
    .type entry, @function
entry:
    lui     $a0, %hi(marker)
    ori     $a0, $a0, %lo(marker)
    nop
    lw      $t9, %call16(concat_impl)($gp)
    nop
    jalr    $t9
    nop
    jr      $ra
     nop

    .globl concat_impl
    .type  concat_impl, @function
concat_impl:
    move    $v0, $a0
1:  lb      $t0, 0($a1)
    beqz    $t0, 2f
     nop
    sb      $t0, 0($a0)
    addiu   $a0, $a0, 1
    addiu   $a1, $a1, 1
    b       1b
     nop
2:  jr      $ra
     nop

tail_handler:
    addiu   $v0, $zero, 7
    jr      $ra
     nop

    /* padding inside the executable segment, as old GNU ld layouts leave */
    .space 0x100

    .section .rodata
marker:
    .asciz "NEUTRAL_QUERY_MARKER"

    .data
    .align 12
globvar:
    .word 0
marker_pointer:
    .word marker
handler_pointer:
    .word tail_handler
tail_pointer:
    .word tail_handler
"""

CALLEE = "concat_impl"
SPLIT_CALLEE = "split_impl"

SPLIT_SYNTHETIC_ASM = r"""
/* Mirrors the real firmware pattern where stack setup is inserted between
   %call16's lw and jalr.  The call must be visible as evidence, but the
   current redirect encoder cannot replace it. */
    .set noreorder
    .set noat

    .text
    .globl entry
    .type entry, @function
entry:
    lw      $t9, %call16(split_impl)($gp)
    addiu   $sp, $sp, -32
    sw      $ra, 28($sp)
    sw      $s0, 24($sp)
    move    $s0, $a0
    jalr    $t9
     nop
    lw      $ra, 28($sp)
    addiu   $sp, $sp, 32
    jr      $ra
     nop

    .globl split_impl
    .type split_impl, @function
split_impl:
    jr      $ra
     nop
"""


@pytest.fixture(scope="module")
def synthetic_elf(tmp_path_factory) -> Path:
    """Assemble a tiny big-endian MIPS32 dynamic-style executable with the
    classic GOT call sequence (clang + lld, both in WSL)."""
    try:
        probe = subprocess.run(
            ["sh", "-c", "command -v clang && clang --version | head -1"],
            capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("POSIX shell/clang not available for synthetic ELF")
    if probe.returncode != 0 or "lld" not in subprocess.run(
            ["sh", "-c", "command -v ld.lld || command -v ld.lld-18 || true"],
            capture_output=True, text=True).stdout + "ok":
        # clang exists check; lld availability is verified by the link itself
        pass
    if probe.returncode != 0:
        pytest.skip("clang not available for synthetic ELF")
    work = tmp_path_factory.mktemp("mips")
    source = work / "t.s"
    source.write_text(SYNTHETIC_ASM)
    binary = work / "t"
    try:
        result = subprocess.run(
            ["clang", "--target=mips-linux-gnu", "-march=mips32", "-mabi=32",
             "-EB", "-fuse-ld=lld", "-nostdlib", "-no-pie", "-Wl,-e,entry",
             str(source), "-o", str(binary)],
            capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("clang not available for synthetic ELF")
    if result.returncode != 0:
        pytest.skip(f"cross toolchain link failed: {result.stderr[:200]}")
    return binary


def test_synthetic_elf_analysis_and_scan(synthetic_elf):
    with ElfAnalysis(synthetic_elf) as analysis:
        segments = analysis.executable_segments()
        assert segments, "expected executable segment"
        sites = analysis.call_sites((CALLEE,))
        assert sites, "expected the %call16 site to be found"
        site = sites[0]
        # The classic 16-byte sequence: lw $t9,off($gp); nop; jalr $t9; delay.
        original = analysis.bytes_at(site["vaddr"], 16)
        words = struct.unpack(">4I", original)
        assert (words[0] >> 26) == 0x23                    # lw opcode
        assert ((words[0] >> 21) & 0x1F) == 28             # base $gp
        assert ((words[0] >> 16) & 0x1F) == 25             # rt $t9
        assert words[1] == 0                                # nop gap
        assert (words[2] & 0x3F) == 0x09                    # jalr funct
        assert site["callee"] == CALLEE
        # GOT slot must be backed by file bytes and hold a real symbol value.
        slot_value = analysis.read_word(site["got_vaddr"])
        assert slot_value and slot_value == analysis.symbol(CALLEE)
        # Redirect encoding replaces the site with lui/ori/jalr + original delay.
        redirect = analysis.redirect_words(site["vaddr"], 0x480000)
        assert len(redirect) == 16
        new_words = struct.unpack(">4I", redirect)
        assert (new_words[0] >> 26) == 0x0F                 # lui opcode
        assert (new_words[0] & 0xFFFF) == 0x0048            # hi of 0x480000
        assert (new_words[1] >> 26) == 0x0D                 # ori opcode
        assert (new_words[2] & 0x3F) == 0x09                # jalr funct
        assert redirect[12:] == original[12:]               # delay preserved
        # Padding region exists for implantation.
        padding = analysis.padding_region(64)
        assert padding["capacity"] >= 64


def test_split_indirect_call_is_evidence_but_not_redirectable(tmp_path_factory):
    try:
        probe = subprocess.run(
            ["sh", "-c", "command -v clang && clang --version | head -1"],
            capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("POSIX shell/clang not available for synthetic ELF")
    if probe.returncode != 0:
        pytest.skip("clang not available for synthetic ELF")
    work = tmp_path_factory.mktemp("mips-split")
    source = work / "split.s"
    source.write_text(SPLIT_SYNTHETIC_ASM)
    binary = work / "split"
    result = subprocess.run(
        ["clang", "--target=mips-linux-gnu", "-march=mips32", "-mabi=32",
         "-EB", "-fuse-ld=lld", "-nostdlib", "-no-pie", "-Wl,-e,entry",
         str(source), "-o", str(binary)],
        capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip(f"cross toolchain link failed: {result.stderr[:200]}")

    with ElfAnalysis(binary) as analysis:
        calls = analysis.indirect_calls(SPLIT_CALLEE)
        assert calls and len(calls) == 1
        call = calls[0]
        assert call["sequence"] == "split_t9_jalr"
        assert call["redirectable"] is False
        assert call["gap_instruction_count"] == 4
        assert call["jalr_vaddr"] == call["vaddr"] + 5 * 4
        function_calls = analysis.function_calls(call["vaddr"])
        evidence = next(item for item in function_calls
                        if item["vaddr"] == call["vaddr"])
        assert evidence["patch_site_eligible"] is False
        with pytest.raises(ValueError, match="nop between lw and jalr"):
            analysis.indirect_call_at(call["vaddr"])


def test_registry_dispatches_existing_mips32be_boundary(synthetic_elf):
    backend = architecture_backend("mips32be")
    with backend.analyze_elf(synthetic_elf) as analysis:
        site = analysis.call_sites((CALLEE,))[0]
        registered = backend.register_patch_site(analysis, site["vaddr"])

        assert registered["vaddr"] == site["vaddr"]
        assert backend.encode_redirect(registered, 0x480000) == (
            analysis.redirect_words(site["vaddr"], 0x480000))
        assert backend.find_implant_region(analysis, 8)["capacity"] >= 8


def test_data_reference_and_function_evidence_queries(synthetic_elf):
    with ElfAnalysis(synthetic_elf) as analysis:
        strings = analysis.ascii_matches("NEUTRAL_QUERY_MARKER")
        assert strings
        marker_address = strings[0]
        references = analysis.data_references(marker_address)
        assert references
        literal = next(item for item in references
                       if item["kind"] == "literal_pair")
        assert literal["low_instruction"] == "ori"
        assert analysis.bytes_at(literal["vaddr"], 8) == bytes.fromhex(
            literal["bytes_hex"])

        function = analysis.containing_function(literal["vaddr"])
        assert function is not None
        assert function["method"] == "symbol"
        assert function["start"] <= literal["vaddr"] < function["end"]
        calls = analysis.function_calls(literal["vaddr"])
        assert any(call["kind"] == "indirect_jalr"
                   and call["callee"] == CALLEE for call in calls)


def test_data_pointer_can_recover_stripped_function_start(synthetic_elf):
    with ElfAnalysis(synthetic_elf) as analysis:
        tail_address = analysis.symbol("tail_handler")
        assert tail_address
        # tail_handler intentionally has no STT_FUNC type.  A data word
        # pointing at its first instruction must still recover the start.
        tail = analysis.containing_function(tail_address)
        assert tail == {"start": tail_address,
                        "end": tail_address + 12,
                        "name": None,
                        "method": "start_candidate_heuristic"}


def test_data_table_context_decodes_pointer_table(synthetic_elf):
    with ElfAnalysis(synthetic_elf) as analysis:
        marker_address = analysis.ascii_matches("NEUTRAL_QUERY_MARKER")[0]
        references = analysis.data_references(marker_address)
        word_reference = next(item for item in references
                              if item["kind"] == "word")
        context = analysis.data_table_context(word_reference["vaddr"])

        assert context["address"] == word_reference["vaddr"]
        classifications = {item["classification"] for item in context["words"]}
        assert {"ascii_pointer", "executable_pointer"} <= classifications
        ascii_word = next(item for item in context["words"]
                          if item["classification"] == "ascii_pointer")
        executable_word = next(
            item for item in context["words"]
            if item["classification"] == "executable_pointer"
            and isinstance(item.get("function"), dict))
        assert ascii_word["value"] == marker_address
        assert executable_word["function"]["start"] <= executable_word["value"] \
            < executable_word["function"]["end"]


# ------------------------------------------------------------ evidence + query

def test_ledger_and_query_session(synthetic_elf, tmp_path):
    with ElfAnalysis(synthetic_elf) as analysis:
        sites = analysis.call_sites((CALLEE,))
        assert sites, "fixture must contain the GOT call site"
        ledger = EvidenceLedger(tmp_path / "evidence", synthetic_elf)
        assert not ledger.entries, "autonomous query path starts without candidates"
        session = EvidenceSession(ledger, analysis, trace_path=tmp_path / "trace.jsonl")

        # Neutral metadata, paged symbols, and model-provided ASCII searches
        # reveal facts without the controller generating a call-site shortlist.
        info = session.handle({"op": "elf_info"})
        assert info["machine"] == "MIPS" and info["load_segments"]
        assert info["entry_hex"] == f"0x{info['entry']:08x}"
        assert all("vaddr_hex" in segment for segment in info["load_segments"])
        symbols = session.handle({"op": "symbols", "contains": "concat", "limit": 1})
        assert symbols["total"] >= 1 and len(symbols["symbols"]) == 1
        assert symbols["symbols"][0]["value_hex"] == (
            f"0x{symbols['symbols'][0]['value']:08x}")
        calls = session.handle({"op": "indirect_calls", "contains": "concat"})
        assert calls["total"] >= 1
        assert calls["calls"][0]["vaddr"] == sites[0]["vaddr"]
        assert calls["calls"][0]["vaddr_hex"] == (
            f"0x{sites[0]['vaddr']:08x}")
        strings = session.handle({"op": "ascii_search",
                                  "text": "NEUTRAL_QUERY_MARKER"})
        assert strings["matches"]
        assert all("address_hex" in match for match in strings["matches"])
        references = session.handle({
            "op": "data_references", "address": strings["matches"][0]["address"],
        })
        assert references["total"] >= 1
        assert all(item["kind"] in {"literal_pair", "word"}
                   for item in references["references"])
        word_reference = next(
            (item for item in references["references"]
             if item["kind"] == "word"), None)
        assert word_reference is not None
        table = session.handle({
            "op": "data_table_context",
            "address": word_reference["vaddr"],
        })
        assert table["address"] == word_reference["vaddr"]
        assert any(item["classification"] == "ascii_pointer"
                   and item["value"] == strings["matches"][0]["address"]
                   for item in table["words"])
        assert any(item["classification"] == "executable_pointer"
                   and "function" in item for item in table["words"])
        assert any(item["op"] == "data_table_context"
                   for item in EvidenceSession.describe_static())
        containing = session.handle({
            "op": "containing_function",
            "address": references["references"][0]["vaddr"],
        })
        assert containing["found"] is True
        function_calls = session.handle({
            "op": "function_calls", "address": containing["function"]["start"],
        })
        assert function_calls["calls"]
        paged = session.handle({
            "op": "function_calls",
            "address": containing["function"]["start"], "offset": 0, "limit": 1,
        })
        assert paged["total"] == len(function_calls["calls"])
        assert paged["returned"] == 1
        if paged["total"] > 1:
            assert paged["next_offset"] == 1 and paged["truncated"] is True

        # disassemble around the site
        answer = session.handle({"op": "disassemble", "site": sites[0]["vaddr"], "around": 8})
        assert answer["window"]["instructions"]
        assert answer["address_hex"] == f"0x{sites[0]['vaddr']:08x}"
        assert answer["window"]["start_hex"] == (
            f"0x{answer['window']['start']:08x}")
        assert all("vaddr_hex" in instruction
                   for instruction in answer["window"]["instructions"])
        cached = session.handle({"op": "disassemble",
                                 "site": sites[0]["vaddr"], "around": 8})
        assert cached["cached"] is True
        assert cached["window"] == answer["window"]

        # Direct reads are possible before any site is registered.
        raw = session.handle({"op": "elf_bytes", "address": sites[0]["vaddr"],
                              "offset": 0, "size": 16})
        assert raw["hex"] == sites[0]["bytes_hex"]
        assert raw["address_hex"] == f"0x{sites[0]['vaddr']:08x}"

        # Only now, after the model supplies an address, does the controller
        # validate and register citeable patch-site evidence.
        registered = session.handle({"op": "register_patch_site",
                                     "address": sites[0]["vaddr"]})
        entry = ledger.get(registered["evidence"])
        assert entry["kind"] == "model_code_site"
        assert entry["site"] == sites[0]["vaddr"]
        assert entry["bytes_hex"] == sites[0]["bytes_hex"]
        assert set(registered) == {"op", "evidence", "site", "site_hex",
                                   "bytes_hex"}
        assert registered["site_hex"] == f"0x{sites[0]['vaddr']:08x}"
        assert "function" not in registered and "call" not in registered
        compacted = EvidenceSession.compact_answers([{
            "query": {"op": "register_patch_site", "address": sites[0]["vaddr"]},
            "answer": {**registered, "function": {"name": "hidden"},
                       "call": {"callee": "hidden", "got_vaddr": 1}},
        }])
        assert compacted[0]["answer"] == registered
        assert not ledger.by_kind("static_candidate")

        # Evidence-anchored reads remain available after registration.
        cited = session.handle({"op": "elf_bytes",
                                "evidence": registered["evidence"],
                                "offset": 0, "size": 16})
        assert cited["hex"] == sites[0]["bytes_hex"]
        # unknown evidence rejected
        with pytest.raises(RepairError):
            session.handle({"op": "elf_bytes", "evidence": "e999", "offset": 0, "size": 16})
        # oversized disassembly window rejected
        with pytest.raises(RepairError):
            session.handle({"op": "disassemble", "site": sites[0]["vaddr"], "around": 999})
        # budget accounting advanced
        assert session.used > 0
        assert session.describe()["budget_bytes"] >= session.used
        exposed = str(session.describe_static()).lower()
        assert "call_sites" not in exposed and "static_candidate" not in exposed


def test_register_patch_site_rejects_wrong_shape(synthetic_elf, tmp_path):
    with ElfAnalysis(synthetic_elf) as analysis:
        site = analysis.call_sites((CALLEE,))[0]["vaddr"]
        ledger = EvidenceLedger(tmp_path / "evidence", synthetic_elf)
        session = EvidenceSession(ledger, analysis)
        with pytest.raises(RepairError, match="Patch site rejected"):
            session.handle({"op": "register_patch_site", "address": site + 4})
        assert not ledger.by_kind("model_code_site")


def test_query_addresses_accept_decimal_and_strict_hexadecimal(
        synthetic_elf, tmp_path):
    with ElfAnalysis(synthetic_elf) as analysis:
        ledger = EvidenceLedger(tmp_path / "evidence", synthetic_elf)
        session = EvidenceSession(ledger, analysis)
        site = analysis.call_sites((CALLEE,))[0]["vaddr"]

        decimal = session.handle({"op": "disassemble", "site": site,
                                  "around": 2})
        hexadecimal = session.handle({"op": "disassemble",
                                       "site": hex(site), "around": 2})

        assert decimal["address"] == hexadecimal["address"] == site
        assert decimal["address_hex"] == hexadecimal["address_hex"] == (
            f"0x{site:08x}")
        with pytest.raises(RepairError, match="positive 4-byte-aligned"):
            session.handle({"op": "disassemble", "site": "0x" + "g" * 8,
                            "around": 2})


def test_query_history_strictly_compacts_all_historical_disassembly():
    instructions = [{"vaddr": 0x400000 + index * 4, "hex": "11223344",
                     "mnemonic": "nop", "operands": ""}
                    for index in range(128)]
    entries = []
    for index in range(4):
        entries.append({
            "query": {"op": "disassemble", "site": 0x400000,
                      "around": 128, "ignored": "not prompted"},
            "answer": {"op": "disassemble", "address": 0x400000 + index,
                       "window": {"start": 0x400000,
                                  "instructions": instructions}},
        })

    compacted = EvidenceSession.compact_answers(entries, max_bytes=24 * 1024)

    assert len(compacted) >= 2
    assert compacted[-1]["answer"]["truncated"] is True
    assert len(compacted[-1]["answer"]["window"]["instructions"]) \
        < len(instructions)
    assert compacted[0]["answer"]["truncated"] is True
    assert len(compacted[0]["answer"]["window"]["instructions"]) < len(instructions)
    assert all("ignored" not in entry["query"] for entry in compacted)
    encoded = json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
    assert len(encoded.encode("utf-8")) <= 24 * 1024


def test_query_history_byte_limit_holds_for_one_large_latest_answer():
    instructions = [{"vaddr": 0x400000 + index * 4,
                     "hex": "11223344", "mnemonic": "addiu",
                     "operands": "register operands " * 8}
                    for index in range(257)]
    compacted = EvidenceSession.compact_answers([{
        "query": {"op": "disassemble", "address": 0x400000,
                  "around": 128},
        "answer": {"op": "disassemble", "address": 0x400000,
                   "window": {"start": 0x3ffe00,
                              "instructions": instructions}},
    }])
    encoded = json.dumps(compacted, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= 16 * 1024
    assert compacted[0]["answer"]["truncated"] is True


def test_direct_callers_uses_only_model_provided_target():
    analysis = object.__new__(ElfAnalysis)
    target = 0x00401234
    site = 0x00400100
    jal = (0x03 << 26) | ((target >> 2) & 0x03FFFFFF)
    words = {site: jal, site + 4: 0}
    analysis.executable_segments = lambda: [{"vaddr": site, "filesz": 8}]
    analysis.read_word = lambda address: words.get(address)
    analysis.bytes_at = lambda address, size: b"\x0c\x10\x04\x8d" + b"\0" * 4

    assert analysis.direct_callers(target) == [{
        "vaddr": site, "target": target,
        "bytes_hex": "0c10048d00000000"}]
    assert analysis.direct_callers(target + 4) == []


def test_query_history_compacts_non_disassembly_answers():
    symbols = [{"name": f"symbol_with_a_much_longer_name_{index}",
                "value": 0x400000 + index * 4, "size": 0x100, "type": "STT_FUNC"}
               for index in range(100)]
    old = {"query": {"op": "symbols", "contains": "symbol_", "limit": 100},
           "answer": {"op": "symbols", "contains": "symbol_", "offset": 0,
                      "total": 100, "symbols": symbols}}

    compacted = EvidenceSession.compact_answers([
        old, {"query": {"op": "elf_info"}, "answer": {"op": "elf_info"}}])

    assert compacted[0]["answer"]["truncated"] is True
    assert len(compacted[0]["answer"]["symbols"]) < len(symbols)
    assert compacted[1]["answer"] == {"op": "elf_info"}


def test_objdump_disables_inherited_debuginfod(synthetic_elf, tmp_path,
                                                monkeypatch):
    real_run = subprocess.run
    observed = {}

    def recording_run(*args, **kwargs):
        if args and args[0] and args[0][0] == "llvm-objdump":
            observed["urls"] = kwargs.get("env", {}).get("DEBUGINFOD_URLS")
        return real_run(*args, **kwargs)

    monkeypatch.setenv("DEBUGINFOD_URLS", "https://should-not-be-contacted.invalid")
    monkeypatch.setattr(query_module.subprocess, "run", recording_run)
    with ElfAnalysis(synthetic_elf) as analysis:
        site = analysis.call_sites((CALLEE,))[0]["vaddr"]
        ledger = EvidenceLedger(tmp_path / "evidence", synthetic_elf)
        EvidenceSession(ledger, analysis).handle(
            {"op": "disassemble", "address": site, "around": 2})
    assert observed["urls"] == ""


def test_budget_enforced(synthetic_elf, tmp_path):
    with ElfAnalysis(synthetic_elf) as analysis:
        ledger = EvidenceLedger(tmp_path / "evidence", synthetic_elf)
        session = EvidenceSession(ledger, analysis, budget=1)
        with pytest.raises(RepairError):
            session.handle({"op": "elf_info"})


# ------------------------------------------------------------ real httpd

@pytest.mark.slow
@pytest.mark.skipif(not HTTPD.is_file(), reason="real httpd not present")
def test_real_httpd_static_candidates():
    """Static scan must find the known DIR-825 httpd danger call sites."""
    with ElfAnalysis(HTTPD) as analysis:
        sites = analysis.call_sites(("strcat", "strcpy", "sprintf", "vsprintf"))
        assert sites, "no danger call sites found in real httpd"
        assert len(sites) >= 100, "httpd is strcat/strcpy-heavy; expect many"
        # The known CVE-2025-6291 defect site (patch-report.json):
        # 0x40A624: lw $25,-0x79d4($gp) -> strcat(sp+0xCB0, uri).
        known = [s for s in sites if s["vaddr"] == 0x40A624]
        assert known and known[0]["callee"] == "strcat"
        # GOT slot 0x10003b4c holds the .MIPS.stubs strcat stub.
        assert known[0]["got_vaddr"] == 0x10003B4C
        # Redirect encoding against the real site: lui/ori/jalr + preserved delay.
        redirect = analysis.redirect_words(0x40A624, 0x46C200)
        new_words = struct.unpack(">4I", redirect)
        assert (new_words[0] >> 26) == 0x0F and (new_words[0] & 0xFFFF) == 0x0046
        assert (new_words[1] >> 26) == 0x0D and (new_words[1] & 0xFFFF) == 0xC200
        assert (new_words[2] & 0x3F) == 0x09
        original = analysis.bytes_at(0x40A624, 16)
        assert redirect[12:] == original[12:]
        # The real httpd layout has executable padding for implants.
        padding = analysis.padding_region(256)
        assert padding["capacity"] >= 256
