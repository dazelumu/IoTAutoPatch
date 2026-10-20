"""Architecture backend registry and capability contracts.

The registry is intentionally closed in phase one: only the existing
MIPS32 big-endian repair backend is registered.  Unknown names fail before
they can reach architecture-specific analysis, compilation, or implant code.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Protocol

from ..config import RepairError
from .mips32 import MIPS32BE_BACKEND, Mips32BigEndianBackend
from .names import MIPS32BE, architecture_names


ARCHITECTURE_CAPABILITY_SCHEMA = "architecture-capability-v1"


class ArchitectureBackend(Protocol):
    """Minimal phase-one interface wrapped around the existing MIPS code."""

    name: str
    elf_machine: str
    elf_class: str
    endianness: str
    abi: str

    def capability_report(self) -> dict: ...

    def analyze_elf(self, path) -> object: ...

    def register_patch_site(self, analysis, address: int) -> dict: ...

    def encode_redirect(self, site: dict, implant_address: int) -> bytes: ...

    def compile_repair(self, source: str, workdir, deadline: float | None = None): ...

    def find_implant_region(self, analysis, size: int) -> dict: ...


ARCHITECTURE_BACKENDS: MappingProxyType[str, Mips32BigEndianBackend] = MappingProxyType({
    MIPS32BE: MIPS32BE_BACKEND,
})


def architecture_backend(architecture: str) -> Mips32BigEndianBackend:
    try:
        return ARCHITECTURE_BACKENDS[architecture]
    except (KeyError, TypeError) as exc:
        raise RepairError(
            "unsupported_architecture",
            f"Unsupported firmware architecture: {architecture!r}; "
            f"registered architectures: {list(ARCHITECTURE_BACKENDS)}",
        ) from exc


# Alias kept for callers that prefer an explicit lookup verb.
get_architecture_backend = architecture_backend


def capability_report(architecture: str) -> dict:
    return architecture_backend(architecture).capability_report()


def supports_architecture(architecture: str) -> bool:
    try:
        return architecture in ARCHITECTURE_BACKENDS
    except TypeError:
        return False


def validate_capability_report(report: dict) -> dict:
    if not isinstance(report, dict) or report.get("schema") != ARCHITECTURE_CAPABILITY_SCHEMA:
        raise RepairError("preparation_failed",
                          f"Expected {ARCHITECTURE_CAPABILITY_SCHEMA}")
    architecture = report.get("architecture")
    expected = capability_report(architecture)
    if report != expected:
        raise RepairError("preparation_failed",
                          f"Architecture capability mismatch: {architecture}")
    return report
