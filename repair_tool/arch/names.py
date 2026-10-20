"""Stable architecture identifiers shared without pulling ELF dependencies."""

MIPS32BE = "mips32be"
MIPS32BE_E_FLAGS_ABI_MASK = 0x0000F000
MIPS32BE_E_FLAGS_ABI_O32 = 0x00001000
MIPS32BE_E_FLAGS_MICROMIPS = 0x02000000


def architecture_names() -> tuple[str, ...]:
    """Phase-one architecture names without importing ELF analysis code."""
    return (MIPS32BE,)
