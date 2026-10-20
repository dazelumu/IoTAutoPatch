"""Architecture backend registry contracts (W6)."""
from __future__ import annotations

import pytest

from repair_tool.arch.mips32 import MIPS32BE_BACKEND
from repair_tool.arch.registry import (ARCHITECTURE_CAPABILITY_SCHEMA,
                                      architecture_backend, architecture_names,
                                      capability_report,
                                      get_architecture_backend,
                                      supports_architecture,
                                      validate_capability_report)
from repair_tool.config import RepairError


def test_only_mips32be_is_registered() -> None:
    assert architecture_names() == ("mips32be",)
    assert architecture_backend("mips32be") is MIPS32BE_BACKEND
    assert get_architecture_backend("mips32be") is MIPS32BE_BACKEND


def test_mips32be_capability_report_is_explicit() -> None:
    report = capability_report("mips32be")

    assert report == {
        "schema": ARCHITECTURE_CAPABILITY_SCHEMA,
        "architecture": "mips32be",
        "elf": {
            "machine": "MIPS",
            "class": "ELF32",
            "endianness": "big",
            "abi": "o32",
        },
        "repair": {
            "call_sequences": ["lw $t9; nop; jalr $t9; delay"],
            "redirect_encoder": True,
            "redirect_sequence": "lui/ori/jalr/original delay",
            "implant_region": True,
            "leaf_function_abi": True,
        },
        "compiler": {
            "target": "mips-linux-gnu",
            "flags": ["-march=mips32", "-mabi=32", "-EB", "-G0"],
        },
        "unsupported": [],
    }


@pytest.mark.parametrize(
    "architecture", ["mips32le", "arm32", "aarch64", "mips", "MIPS32BE", ""]
)
def test_unregistered_architectures_fail_explicitly(architecture: str) -> None:
    with pytest.raises(RepairError) as caught:
        architecture_backend(architecture)

    assert caught.value.status == "unsupported_architecture"
    assert architecture not in capability_report("mips32be")["unsupported"]


def test_supports_architecture_does_not_register_or_dispatch() -> None:
    assert supports_architecture("mips32be")
    assert not any(supports_architecture(name)
                   for name in ("mips32le", "arm32", "aarch64"))
    assert not supports_architecture(None)


def test_registry_is_closed_for_mutation() -> None:
    from repair_tool.arch.registry import ARCHITECTURE_BACKENDS

    with pytest.raises(TypeError):
        ARCHITECTURE_BACKENDS["arm32"] = object()
    assert architecture_names() == ("mips32be",)


def test_capability_reports_are_detached_and_validated() -> None:
    report = capability_report("mips32be")
    report["repair"]["redirect_encoder"] = False

    with pytest.raises(RepairError, match="Architecture capability mismatch"):
        validate_capability_report(report)
    assert capability_report("mips32be")["repair"]["redirect_encoder"] is True
