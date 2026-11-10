"""Checking each group's send lines against its instruction.

x18 holds the STM address: a send is a store of X registers to [x18], with no offset, index or
write-back. 'str xn, [x18]' sends Xn; 'stp a, b, [x18]' sends b, then a (the STM emits the higher
address first). Every other instruction sends nothing, and no instruction may otherwise access
memory through x18 or write it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from capstone.arm64 import ARM64_INS_STP, ARM64_INS_STR, ARM64_OP_MEM, ARM64_OP_REG

from insight.annotations.pairing import register_number, register_writes
from insight.dsl.transfer import ZERO

if TYPE_CHECKING:
    from collections.abc import Sequence

    from capstone import CsInsn

    from insight.annotations.framing import Block

STM_REGISTER = 18


def x_number(insn: CsInsn, reg: int) -> int | None:
    """The number of an X register as encoded, XZR being 31 (not W, not SP)."""
    name = insn.reg_name(reg)
    if name == "xzr":
        return ZERO.n
    return register_number(name) if name.startswith("x") or name in {"fp", "lr"} else None


def instruction_sends(insn: CsInsn) -> tuple[int, ...] | None:
    """The registers an instruction sends, in the order the STM emits them; None when it accesses
    memory through x18 or writes x18 without being a send."""
    memory = [op.mem for op in insn.operands if op.type == ARM64_OP_MEM]
    if not any(insn.reg_name(mem.base) == f"x{STM_REGISTER}" for mem in memory):
        return None if STM_REGISTER in register_writes(insn) else ()
    (mem,) = memory
    data = [op.reg for op in insn.operands if op.type == ARM64_OP_REG]
    numbers = [n for reg in data if (n := x_number(insn, reg)) is not None]
    plain = mem.index == 0 and mem.disp == 0 and not insn.writeback and len(insn.operands) == len(data) + 1
    if not plain or len(numbers) != len(data):
        return None
    if insn.id == ARM64_INS_STR and len(numbers) == 1:
        return (numbers[0],)
    if insn.id == ARM64_INS_STP and len(numbers) == 2:
        return (numbers[1], numbers[0])
    return None


def sends_text(numbers: Sequence[int]) -> str:
    return ", ".join("send XZR" if n == ZERO.n else f"send X{n}" for n in numbers) or "no send"


def check_sends(block: Block, insns: Sequence[CsInsn]) -> list[tuple[int, str]]:
    """(group offset, message) for each group whose send lines do not match its instruction."""
    if len(insns) != len(block.groups):
        msg = f"{len(insns)} instructions for {len(block.groups)} groups"
        raise ValueError(msg)
    issues: list[tuple[int, str]] = []
    for group, insn in zip(block.groups, insns, strict=True):
        text = f"{insn.mnemonic} {insn.op_str}"
        expected = instruction_sends(insn)
        listed = [reg.n for reg in group.form.sends]
        if expected is None:
            issues.append((group.offset, f"{text}: accesses or writes x18 without being a send"))
        elif listed != list(expected):
            issues.append(
                (group.offset, f"{text} makes {sends_text(expected)}, the group lists {sends_text(listed)}")
            )
    return issues
