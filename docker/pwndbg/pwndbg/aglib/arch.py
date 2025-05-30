from __future__ import annotations

from typing import Literal

import pwnlib

import pwndbg
from pwndbg.lib.arch import PWNLIB_ARCH_MAPPINGS
from pwndbg.lib.arch import Arch


def read_thumb_bit() -> int | None:
    """
    Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

    Return None if the Thumb bit is not relevent to the current architecture
    """
    if pwndbg.aglib.arch.name == "arm":
        # When program initially starts, cpsr may not be readable
        if (cpsr := pwndbg.aglib.regs.cpsr) is not None:
            return (cpsr >> 5) & 1
    elif pwndbg.aglib.arch.name == "armcm":
        # ARM Cortex-M procesors only suport Thumb mode. However, there is still a bit
        # that represents the Thumb mode (which is currently architecturally defined to be 1)
        if (xpsr := pwndbg.aglib.regs.xpsr) is not None:
            return (xpsr >> 24) & 1
    # AArch64 does not have a Thumb bit
    return None


def get_thumb_mode_string() -> Literal["arm", "thumb"] | None:
    thumb_bit = read_thumb_bit()
    return None if thumb_bit is None else "thumb" if thumb_bit == 1 else "arm"


arch: Arch = Arch("i386", 4, "little")


def update() -> None:
    a = pwndbg.dbg.selected_inferior().arch()

    pwnlib.context.context.arch = PWNLIB_ARCH_MAPPINGS.get(a.name, "none")
    pwnlib.context.context.bits = a.ptrsize * 8

    arch.update(a.name, a.ptrsize, a.endian)
