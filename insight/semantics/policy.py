"""The policy lists of the flip tests: which inputs are dropped, held fixed or flipped specially.

They come from the policy, never from the rule under test, so a wrong rule cannot hide a flow.
The flags and system registers are not policy locations. Address inputs (bases, indexes, indirect
branch targets) are held fixed and excluded for the data, except a write-back base, flipped in its
low bits.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from capstone.arm64 import ARM64_OP_MEM

from insight.dsl.locations import Reg
from insight.semantics.operands import address, gregs
from insight.semantics.rules import STORE_EXCLUSIVE_PAIRS, STORE_EXCLUSIVES, size_of

if TYPE_CHECKING:
    from capstone import CsInsn


@dataclass(frozen=True)
class Flag:
    """An input or output that is not a policy location: NZCV, a system register."""

    name: str

    def __str__(self) -> str:
        return self.name


NZCV = Flag("NZCV")
TPIDR_EL0 = Flag("TPIDR_EL0")
NON_LOCATIONS = frozenset({NZCV, TPIDR_EL0})
STM_REGISTER = Reg(18)
INDIRECT_BRANCHES = frozenset({"br", "blr", "ret"})


@dataclass(frozen=True)
class Inputs:
    """An instruction's address inputs, its write-back base, and how its base may be flipped."""

    address: frozenset[Reg]
    writeback: Reg | None
    lowest_bit: int  # of the write-back base's flips: alignment

    def excluded_for(self, out: object) -> frozenset[object]:
        """The inputs whose flows into out are dropped."""
        excluded: set[object] = set(NON_LOCATIONS) | set(self.address)
        if out == self.writeback:
            excluded.discard(out)
        return frozenset(excluded)


def inputs(insn: CsInsn) -> Inputs:
    if insn.mnemonic in INDIRECT_BRANCHES:
        regs = gregs(insn)
        target = regs[0].loc if regs else Reg(30)
        return Inputs(frozenset({target}) if target else frozenset(), None, 0)
    if not any(op.type == ARM64_OP_MEM for op in insn.operands):
        return Inputs(frozenset(), None, 0)
    addr = address(insn)
    writeback = addr.base.loc if addr.mode != "offset" else None
    lowest = 0
    if addr.base.kind == "sp":
        lowest = 4  # SP alignment check (SCTLR_EL1.SA0 under Linux)
    if insn.mnemonic in STORE_EXCLUSIVES or insn.mnemonic in STORE_EXCLUSIVE_PAIRS:
        size = size_of(STORE_EXCLUSIVES.get(insn.mnemonic), gregs(insn)[1])
        if insn.mnemonic in STORE_EXCLUSIVE_PAIRS:
            size *= 2
        lowest = max(lowest, (size - 1).bit_length())  # exclusives fault when unaligned
    return Inputs(addr.registers, writeback, lowest)
