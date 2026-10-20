"""M5: repair proposal validation + cross-compile + implant tests."""
from __future__ import annotations

import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from repair_tool.arch.mips32 import ElfAnalysis
from repair_tool.config import RepairError
from repair_tool.firmware.evidence import (EvidenceLedger,
                                           register_model_code_site)
from repair_tool.firmware.implant import (build_candidate,
                                          compile_repair_object,
                                          validate_repair_object)
from repair_tool.firmware.propose import proposal_prompt, validate_proposal
from repair_tool.firmware import implant as implant_module

CALLEE = "concat_impl"


def _tool_ok() -> bool:
    try:
        probe = subprocess.run(
            ["sh", "-c", "command -v clang && command -v qemu-mips"],
            capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return probe.returncode == 0


# ------------------------------------------------------------ fixtures

RUNNER_ASM = r"""
/* Synthetic target whose entry() calls concat_impl() through the classic o32
   GOT sequence -- the same calling pattern the DIR-825 httpd uses for
   strcat/strcpy. The runner loads $gp (a static image has no ld.so to do
   it), builds a small frame with the saved $ra at sp+44, passes dst=sp+0
   (56 bytes below the saved $ra) and src=a 200-byte filler, calls entry()
   and exits with the byte count.

   The planted defect: concat_impl copies without any bound, so the filler
   overruns the 56-byte gap, smashes the saved $ra with 0x41 bytes and the
   returning entry() jumps to 0x41414141 -> SIGSEGV -- the same failure
   class as the CVE-2025-6291 httpd overflow, visible as a fatal exit. */

    .set noreorder
    .set noat

    .text
    .globl __start
__start:
    /* initialize $gp: static image, no ld.so */
    lui     $gp, %hi(_gp)
    addiu   $gp, $gp, %lo(_gp)
    /* frame: 64 bytes; saved $ra -> finish; dst buffer at sp+0 (44 bytes
       below the saved slot). __start JUMPS through the saved $ra at the
       end, so smashing it redirects control flow to 0x41414141. */
    addiu   $sp, $sp, -64
    lui     $t0, %hi(finish)
    addiu   $t0, $t0, %lo(finish)
    sw      $t0, 44($sp)
    sw      $zero, 0($sp)
    move    $a0, $sp                 /* dst = sp+0 */
    lui     $a1, %hi(filler)
    addiu   $a1, $a1, %lo(filler)
    lw      $t9, %call16(entry)($gp)
    nop
    jalr    $t9
    nop
    /* tail-jump through the frame slot: intact -> finish; smashed -> 0x41.. */
    lw      $t0, 44($sp)
    addiu   $sp, $sp, 64
    jr      $t0
     nop

    .type  finish, @function
finish:
    /* exit(total & 0xff) -- Linux o32 exit syscall is 4001 */
    move    $a0, $v0
    andi    $a0, $a0, 0xff
    li      $v0, 4001
    syscall
    nop
    /* unreachable fallback */
1:  b       1b
     nop

    .globl entry
    .type  entry, @function
entry:
    /* real function shape: save $ra, call, restore, return (the DIR-825
       httpd call sites live inside functions like do_file, not tail calls) */
    addiu   $sp, $sp, -16
    sw      $ra, 12($sp)
    sw      $a0, 0($sp)
    sw      $a1, 4($sp)
    lw      $t9, %call16(concat_impl)($gp)
    nop
    jalr    $t9
    nop
    /* second defect call site: same (dst, src) restored so its unbounded
       copy keeps targeting the small frame buffer (crash stays
       attributable) while giving multi-edit proposals a second site. */
    lw      $a0, 0($sp)
    lw      $a1, 4($sp)
    lw      $t9, %call16(concat_impl2)($gp)
    nop
    jalr    $t9
    nop
    lw      $ra, 12($sp)
    addiu   $sp, $sp, 16
    jr      $ra
     nop

    .globl concat_impl
    .type  concat_impl, @function
concat_impl:
    /* UNBOUNDED copy: 200 bytes into a 44-byte buffer smashes the saved
       $ra. (dst, src in $a0/$a1) -- this is the planted defect. */
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

    .globl concat_impl2
    .type  concat_impl2, @function
concat_impl2:
    /* Second unbounded copy (dst2, src2 in $a0/$a1): a second defect for
       multi-edit proposals. Returns 0; overwrites nothing when $a0 is 0. */
    beqz    $a0, 3f
     nop
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
3:  move    $v0, $zero
    jr      $ra
     nop

    .space 0x400

    .section .rodata,"a"
    .balign 0x1000
filler:
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .ascii "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    .byte 0

    /* data segment: page-aligned in the file image as well */
    .data
    .balign 0x1000
globvar:
    .word 0
"""

REPAIR_C = """
/* Bounded copy: never writes past the caller's 44-byte buffer, always
   NUL-terminates. The contract mirrors the original concat semantics for
   short inputs and truncates longer ones instead of smashing the frame. */
int repair_entry(char *dst, const char *src) {
    char *d = dst;
    int written = 0;
    if (!dst || !src) return 0;
    while (*src && written < 43) {
        *d++ = *src++;
        written++;
    }
    *d = 0;
    return written;
}
"""


def build_runner(workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / "runner.s"
    source.write_text(RUNNER_ASM)
    binary = workdir / "runner"
    try:
        result = subprocess.run(
            ["clang", "--target=mips-linux-gnu", "-march=mips32", "-mabi=32",
             "-EB", "-fuse-ld=lld", "-nostdlib", "-no-pie", "-static",
             "-Wl,-e,__start", str(source), "-o", str(binary)],
            capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("clang not available for synthetic implant runner")
    if result.returncode != 0:
        pytest.skip(f"cross toolchain unavailable: {result.stderr[:200]}")
    return binary


@pytest.fixture(scope="module")
def runner(tmp_path_factory) -> Path:
    return build_runner(tmp_path_factory.mktemp("implant"))


@pytest.mark.parametrize("flag_modifier", [
    lambda flags: (flags & ~0xF000) | 0x2000,  # O64
    lambda flags: flags | 0x02000000,          # microMIPS
])
def test_non_o32_mips_elf_is_rejected(runner: Path, tmp_path: Path,
                                      flag_modifier) -> None:
    data = bytearray(runner.read_bytes())
    flags = struct.unpack_from(">I", data, 36)[0]
    struct.pack_into(">I", data, 36, flag_modifier(flags))
    target = tmp_path / "non-o32"
    target.write_bytes(data)

    with pytest.raises(ValueError, match="only MIPS32BE o32 is supported"):
        ElfAnalysis(target)


@pytest.fixture(scope="module")
def ledger(runner, tmp_path_factory) -> tuple[EvidenceLedger, list[dict]]:
    with ElfAnalysis(runner) as analysis:
        sites = analysis.call_sites(("concat_impl", "concat_impl2"))
        assert len(sites) == 2, \
            f"runner must contain two GOT call sites, found {len(sites)}"
        book = EvidenceLedger(tmp_path_factory.mktemp("ledger"), runner)
        for site in sites:
            register_model_code_site(book, analysis, site["vaddr"])
        return book, sites


def qemu_run(binary: Path, *args: str, timeout: float = 20.0):
    argv = ["qemu-mips", str(binary), *args]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


# ------------------------------------------------------------ proposal validation

def make_edit(site: dict, site_index: int = 0, source: str = REPAIR_C,
              **overrides) -> dict:
    edit = {"site": site["vaddr"], "expected_hex": site["bytes_hex"],
            "evidence": [f"e{site_index + 1}"], "contract": {
                "abi": "a0=dst a1=src, v0=bytes written",
                "bounds": "stops at 8 bytes or NUL",
                "preserve": "copies src to dst, NUL-terminated",
                "invalid": "returns 0 when dst or src is NULL"},
            "source": source}
    edit.update(overrides)
    return edit


def test_proposal_roundtrip(ledger):
    book, sites = ledger
    proposal = {"edits": [make_edit(sites[0])],
                "rationale": "bound the copy"}
    clean = validate_proposal(proposal, book)
    assert clean["edits"][0]["site"] == sites[0]["vaddr"]


def test_model_code_site_authorizes_only_model_selected_site(runner, tmp_path):
    with ElfAnalysis(runner) as analysis:
        sites = analysis.call_sites(("concat_impl", "concat_impl2"))
    book = EvidenceLedger(tmp_path / "model-ledger", runner)
    legacy_id = book.add("runtime_exit", {
        "annotation": "observed fault; not a code edit authorization",
        "site": sites[0]["vaddr"], "bytes_hex": sites[0]["bytes_hex"]})
    model_id = book.add("model_code_site", {
        "annotation": "selected by the model after inspecting disassembly",
        "site": sites[0]["vaddr"], "bytes_hex": sites[0]["bytes_hex"]})

    edit = make_edit(sites[0], evidence=[model_id])
    clean = validate_proposal({"edits": [edit]}, book)
    assert clean["edits"][0]["evidence"] == [model_id]

    edit = make_edit(sites[0], evidence=[legacy_id])
    with pytest.raises(RepairError, match="model_code_site"):
        validate_proposal({"edits": [edit]}, book)


def test_proposal_prompt_exposes_only_model_selected_site():
    selected_site = 0x401000
    legacy_site = 0x402000
    prompt = proposal_prompt({
        "target_sha256": "a" * 64,
        "model_code_sites": [{
            "evidence": "e7", "site": selected_site,
            "bytes_hex": "11" * 16,
            "callee": "SENSITIVE_SELECTED_CALLEE",
            "function": {"name": "SENSITIVE_SELECTED_FUNCTION"},
        }],
        # Even if a caller still carries the old broad candidate list, it must
        # not reach the repair prompt.
        "static_candidates": [{
            "evidence": "e1", "site": legacy_site,
            "bytes_hex": "22" * 16,
            "callee": "SENSITIVE_LEGACY_CALLEE",
            "function": {"name": "SENSITIVE_LEGACY_FUNCTION"},
        }],
    }, {
        "request": {"method": "POST", "path": "/probe"},
        "signal": "SIGSEGV", "exit_record": {"pid": 321},
    }, rounds_left=2)

    assert f'"site":{selected_site}' in prompt
    assert '"evidence":"e7"' in prompt
    assert "11" * 16 in prompt
    assert str(legacy_site) not in prompt
    for secret in ("SENSITIVE_SELECTED_CALLEE", "SENSITIVE_SELECTED_FUNCTION",
                   "SENSITIVE_LEGACY_CALLEE", "SENSITIVE_LEGACY_FUNCTION"):
        assert secret not in prompt
    assert '"callee"' not in prompt
    assert '"function"' not in prompt
    assert "int repair_entry(" not in prompt
    assert "char *dst" not in prompt
    assert "$a0" not in prompt
    assert "bounded copy" not in prompt.lower()
    assert "exactly one function named `repair_entry`" in prompt


@pytest.mark.parametrize("mutate,reason", [
    (lambda e: e.update(site=e["site"] + 4), "misaligned or invented site"),
    (lambda e: e.update(expected_hex="00" * 16), "fabricated bytes"),
    (lambda e: e.update(evidence=["e999"]), "unknown evidence"),
    (lambda e: e.update(evidence=[]), "empty evidence"),
    (lambda e: e.update(source="int x;"), "not a function"),
    (lambda e: e["contract"].update(bounds=""), "empty contract field"),
    (lambda e: e.pop("contract"), "missing contract"),
])
def test_proposal_rejections(ledger, mutate, reason):
    book, sites = ledger
    edit = make_edit(sites[0])
    mutate(edit)
    with pytest.raises(RepairError):
        validate_proposal({"edits": [edit]}, book)


def test_proposal_runtime_evidence_cannot_authorize(ledger):
    book, sites = ledger
    book.add("runtime_exit", {"annotation": "runtime", "signal": "SIGSEGV"})
    edit = make_edit(sites[0])
    edit["evidence"] = ["e2"]          # only the runtime exit
    with pytest.raises(RepairError):
        validate_proposal({"edits": [edit]}, book)


# ------------------------------------------------------------ object validation

def test_compiler_interface_uses_registered_mips32be_target(monkeypatch, tmp_path):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(implant_module.subprocess, "run", fake_run)
    object_path = compile_repair_object(REPAIR_C, tmp_path)

    argv = captured["argv"]
    assert object_path == tmp_path / "repair.o"
    assert argv[:6] == [
        "clang", "--target=mips-linux-gnu", "-march=mips32",
        "-mabi=32", "-EB", "-G0",
    ]
    assert argv[6:] == ["-O0", "-fno-pic", "-fno-builtin", "-ffreestanding",
                        "-c", str(tmp_path / "repair.c"), "-o",
                        str(tmp_path / "repair.o")]


def test_compile_and_validate_repair_object(tmp_path):
    if not _tool_ok():
        pytest.skip("clang/qemu-mips not available")
    object_path = compile_repair_object(REPAIR_C, tmp_path)
    result = validate_repair_object(object_path)
    assert result["function"] == "repair_entry"
    assert result["size"] % 4 == 0
    assert result["size"] > 0


def test_object_with_external_call_rejected(tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    source = """
extern int external_helper(int len);
int repair_entry(char *dst, const char *src) {
    (void)dst;
    int n = 0;
    while (src[n]) n++;
    return external_helper(n);
}
"""
    object_path = compile_repair_object(source, tmp_path)
    with pytest.raises(RepairError):
        validate_repair_object(object_path)


def test_object_with_allocated_rodata_dependency_rejected(tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    source = """
static const char prefix[] = "x";
int repair_entry(char *dst, const char *src) {
    (void)src;
    return prefix[0] + (dst != 0);
}
"""
    object_path = compile_repair_object(source, tmp_path)
    with pytest.raises(RepairError, match="unsupported allocated section"):
        validate_repair_object(object_path)


def test_object_with_two_functions_rejected(tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    source = """
static int helper(int x) { return x + 1; }
int repair_entry(char *dst, const char *src) {
    (void)dst; (void)src; return helper(1);
}
"""
    object_path = compile_repair_object(source, tmp_path)
    with pytest.raises(RepairError):
        validate_repair_object(object_path)


# ------------------------------------------------------------ end-to-end implant + qemu

def test_implant_redirect_changes_behavior(runner, ledger, tmp_path):
    """Acceptance: qemu-mips executes the patched binary and the implants
    bound BOTH copies (original runs off the frame and faults)."""
    if not _tool_ok():
        pytest.skip("clang/qemu-mips not available")
    book, sites = ledger
    clean = validate_proposal({"edits": [make_edit(sites[0], site_index=0),
                                         make_edit(sites[1], site_index=1)]}, book)
    built = build_candidate(runner, clean["edits"], tmp_path / "build")
    candidate = built["candidate"]
    record = built["record"]
    assert len(record["implants"]) == 2
    assert all(i["size"] > 0 for i in record["implants"])
    # Baseline: unpatched runner smashes the saved $ra -> jumps to 0x41414141
    # -> SIGSEGV (Python returncode < 0 means killed by signal).
    baseline = qemu_run(runner)
    assert baseline.returncode < 0, \
        f"defective runner unexpectedly survived (rc={baseline.returncode})"
    # Candidate: both redirects activate -> copies bounded, frame intact
    # -> exit(43) (the first bounded copy's return value).
    patched = qemu_run(candidate)
    assert patched.returncode == 43, \
        f"patched runner rc={patched.returncode} (want 43), stderr: {patched.stderr[:200]}"


def test_multi_edit_implants_are_independent(runner, ledger, tmp_path):
    """The audit's core reproduction: two DIFFERENT repair functions must
    produce two distinct implants; each call site redirects to its own
    code, and the second code is never discarded."""
    if not _tool_ok():
        pytest.skip("clang/qemu-mips not available")
    book, sites = ledger
    # Two different sources: a bounded copy and a "copy nothing" variant
    # whose observable effect differs (writes no bytes, returns 7).
    bounded = REPAIR_C
    lazy = """
int repair_entry(char *dst, const char *src) {
    (void)src;
    if (!dst) return 7;
    ((char*)dst)[0] = 0;
    return 7;
}
"""
    clean = validate_proposal({"edits": [make_edit(sites[0], site_index=0, source=bounded),
                                         make_edit(sites[1], site_index=1, source=lazy)]}, book)
    built = build_candidate(runner, clean["edits"], tmp_path / "build")
    record = built["record"]
    implants = record["implants"]
    assert len(implants) == 2
    # Distinct code -> distinct implants (hex differs, sizes may differ).
    assert implants[0]["hex"] != implants[1]["hex"]
    # Every call site redirects to ITS OWN implant (not the first one).
    for edit, implant in zip(record["edits"], implants):
        assert edit["implant_vaddr"] == implant["vaddr"]
        redirect = bytes.fromhex(edit["redirect_hex"])
        words = struct.unpack(">4I", redirect)
        assert (words[0] >> 26) == 0x0F                   # lui $t9, hi
        assert (words[0] & 0xFFFF) == (implant["vaddr"] >> 16)
        assert (words[1] >> 26) == 0x0D                   # ori $t9, lo
        assert (words[1] & 0xFFFF) == (implant["vaddr"] & 0xFFFF)
        assert (words[2] & 0x3F) == 0x09                  # jalr $t9
    # Non-overlapping implant regions.
    regions = sorted(implants, key=lambda i: i["vaddr"])
    assert regions[0]["vaddr"] + regions[0]["size"] <= regions[1]["vaddr"]
    # Executable under qemu: lazy second implant still terminates the buffer
    # and returns 7; exit value = second call's return (& 0xff) = 7.
    patched = qemu_run(built["candidate"])
    assert patched.returncode == 7, \
        f"multi-implant candidate rc={patched.returncode}, stderr: {patched.stderr[:200]}"


def test_implant_stale_edit_rejected(runner, ledger, tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    _, sites = ledger
    stale = make_edit(sites[0])
    stale["expected_hex"] = ("ff" * 16)
    with pytest.raises(RepairError):
        build_candidate(runner, [stale], tmp_path / "build",
                        code_hex_by_site={stale["site"]: "0000000c"})


def test_code_hex_injection_produces_real_candidate(runner, ledger, tmp_path):
    """The test-only machine-code path must exercise placement and redirect."""
    _, sites = ledger
    edit = make_edit(sites[0])
    # jr $ra; nop -- sufficient for build/record validation without clang.
    code = "03e0000800000000"
    built = build_candidate(
        runner, [edit], tmp_path / "hex-build",
        code_hex_by_site={edit["site"]: code})
    record = built["record"]
    assert record["candidate_sha256"] != record["target_sha256"]
    assert record["implants"] == [{
        "site": edit["site"],
        "vaddr": record["implants"][0]["vaddr"],
        "size": 8,
        "hex": code,
        "rebased_jumps": 0,
    }]
    assert record["edits"][0]["implant_vaddr"] == record["implants"][0]["vaddr"]
    assert record["artifacts"][0]["code_sha256"]


def test_multi_edit_keeps_distinct_build_artifacts(runner, ledger, tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    book, sites = ledger
    clean = validate_proposal({"edits": [
        make_edit(sites[0], site_index=0),
        make_edit(sites[1], site_index=1, source="""
int repair_entry(char *dst, const char *src) {
    (void)dst; (void)src; return 7;
}
"""),
    ]}, book)
    built = build_candidate(runner, clean["edits"], tmp_path / "artifacts")
    artifacts = built["record"]["artifacts"]
    assert [Path(item["source"]).as_posix() for item in artifacts] == [
        "edit-001/repair.c", "edit-002/repair.c"]
    assert artifacts[0]["object_sha256"] != artifacts[1]["object_sha256"]
    for item in artifacts:
        assert (tmp_path / "artifacts" / item["source"]).is_file()
        assert (tmp_path / "artifacts" / item["object"]).is_file()


def test_candidate_patch_record(runner, ledger, tmp_path):
    if not _tool_ok():
        pytest.skip("clang not available")
    book, sites = ledger
    clean = validate_proposal({"edits": [make_edit(sites[0], site_index=0),
                                         make_edit(sites[1], site_index=1)]}, book)
    built = build_candidate(runner, clean["edits"], tmp_path / "build")
    record = built["record"]
    assert record["target_sha256"] != record["candidate_sha256"]
    edit = record["edits"][0]
    implant_vaddr = edit["implant_vaddr"]
    redirect = bytes.fromhex(edit["redirect_hex"])
    words = struct.unpack(">4I", redirect)
    assert (words[0] >> 26) == 0x0F                       # lui $t9, hi(implant)
    assert (words[0] & 0xFFFF) == (implant_vaddr >> 16)
    assert (words[1] >> 26) == 0x0D                       # ori $t9, lo
    assert (words[1] & 0xFFFF) == (implant_vaddr & 0xFFFF)
    assert (words[2] & 0x3F) == 0x09                      # jalr $t9
    with ElfAnalysis(runner) as analysis:
        original = analysis.bytes_at(edit["site"], 16)
    assert redirect[12:] == original[12:]                 # delay preserved
