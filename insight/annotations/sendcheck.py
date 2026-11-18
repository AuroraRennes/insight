"""Checking each group's send lines against its instructions: a send is a store to the channel page."""

from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone.arm64 import (
    ARM64_INS_ADRP,
    ARM64_INS_STP,
    ARM64_INS_STR,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.sections import SymbolTableSection

from insight.annotations.pairing import register_number, register_writes

if TYPE_CHECKING:
    from collections.abc import Sequence

    from capstone import CsInsn
    from elftools.elf.elffile import ELFFile

    from insight.annotations.framing import Block, Group

CHANNEL_SYMBOL = "__hbng_chan"
PAGE_MASK = ~0xFFF

# Where the page in a send's base register comes from, when it is not an adrp in the block: not
# followed here, the send is counted by its origin, and the replay checks its address.
PAGE_ORIGINS = ("from entry", "reloaded from the stack", "copied by a mov")


def channel_page(elf: ELFFile) -> int:
    """The address of the page the sends store to."""
    symtab = elf.get_section_by_name(".symtab")
    symbols = symtab.get_symbol_by_name(CHANNEL_SYMBOL) if isinstance(symtab, SymbolTableSection) else None
    if not symbols:
        msg = f"no {CHANNEL_SYMBOL} symbol: not linked with the HBNG C library"
        raise ValueError(msg)
    address: int = symbols[0]["st_value"]
    return address & PAGE_MASK


def x_number(insn: CsInsn, reg: int) -> int | None:
    """The number of an X register as encoded (not W, not SP, not XZR)."""
    name = insn.reg_name(reg)
    if name == "xzr":
        return None
    return register_number(name) if name.startswith("x") or name in {"fp", "lr"} else None


def send_shape(insn: CsInsn) -> tuple[int, tuple[int, ...]] | None:
    """(base register, registers sent in channel order) when insn has the shape of a send:
    'str xn, [xT]' or 'stp xa, xb, [xT]', no offset, index or write-back."""
    if insn.id not in (ARM64_INS_STR, ARM64_INS_STP) or insn.writeback:
        return None
    memory = [op.mem for op in insn.operands if op.type == ARM64_OP_MEM]
    data = [op.reg for op in insn.operands if op.type == ARM64_OP_REG]
    if len(memory) != 1 or memory[0].index != 0 or memory[0].disp != 0 or len(insn.operands) != len(data) + 1:
        return None
    numbers = [x_number(insn, reg) for reg in data]
    base = x_number(insn, memory[0].base)
    if base is None or any(n is None for n in numbers):
        return None
    sent = tuple(n for n in numbers if n is not None)
    if insn.id == ARM64_INS_STR and len(sent) == 1:
        return base, sent
    if insn.id == ARM64_INS_STP and len(sent) == 2:
        return base, (sent[1], sent[0])  # the channel receives the higher address first
    return None


def page_origin(insns: Sequence[CsInsn], k: int, base: int, page: int) -> str | None:
    """Where the page in the base register of the send insns[k] comes from: 'adrp' when an adrp
    of the page in the block, one of PAGE_ORIGINS, or None when something else wrote it last."""
    for prev in reversed(insns[:k]):
        if base not in register_writes(prev):
            continue
        if prev.id == ARM64_INS_ADRP:
            imm = [op.imm for op in prev.operands if op.type == ARM64_OP_IMM]
            return "adrp" if imm == [page] else None
        if prev.mnemonic == "ldr" and "[sp" in prev.op_str:
            return "reloaded from the stack"  # spilled, not rematerialized
        if prev.mnemonic == "mov":
            return "copied by a mov"  # the copy's source is not followed
        return None
    return "from entry"


def sends_text(numbers: Sequence[int]) -> str:
    return ", ".join(f"send X{n}" for n in numbers) or "no send"


@dataclass
class SendCheck:
    """Per block: the issues (offset, message), the instructions that are sends, and where their
    page came from when not from an adrp in the block."""

    issues: list[tuple[int, str]] = field(default_factory=list)
    sends: set[int] = field(default_factory=set)  # indices into the block's instructions
    origins: Counter[str] = field(default_factory=Counter)


def check_sends(block: Block, insns: Sequence[CsInsn], page: int) -> SendCheck:
    """The send lines of every group against its instructions, page being the channel's."""
    if len(insns) != block.size // 4:
        msg = f"{len(insns)} instructions for a block of {block.size // 4}"
        raise ValueError(msg)
    result = SendCheck()
    start = 0
    for group in block.groups:
        listed = [reg.n for reg in group.form.sends]
        span = range(start, start + group.count)
        start += group.count
        if not listed:
            continue  # a store that is not a send is memory, compared with R
        if group.count > 1:
            check_span(result, insns, group, listed=listed, page=page)
        else:
            check_one(result, insns, span[0], offset=group.offset, listed=listed, page=page)
    return result


def check_one(
    result: SendCheck, insns: Sequence[CsInsn], k: int, *, offset: int, listed: list[int], page: int
) -> None:
    insn = insns[k]
    text = f"{insn.mnemonic} {insn.op_str}"
    shape = send_shape(insn)
    if shape is None:
        result.issues.append((offset, f"{text}: lists {sends_text(listed)} but is not a send"))
        return
    base, sent = shape
    if list(sent) != listed:
        result.issues.append(
            (offset, f"{text} makes {sends_text(sent)}, the group lists {sends_text(listed)}")
        )
        return
    origin = page_origin(insns, k, base, page)
    if origin is None:
        result.issues.append((offset, f"{text}: x{base} does not hold the channel page"))
        return
    result.sends.add(k)
    if origin != "adrp":
        result.origins[origin] += 1


def check_span(
    result: SendCheck, insns: Sequence[CsInsn], group: Group, *, listed: list[int], page: int
) -> None:
    """A block form's sends against the instructions the block table gives, in order."""
    at = [offset // 4 for offset in group.send_at]
    named_insns = []
    i = 0
    while i < len(listed):
        k = at[i]
        named_insns.append(k)
        insn = insns[k]
        shape = send_shape(insn)
        count = len(shape[1]) if shape else 1
        named = listed[i : i + count]
        if shape is None or list(shape[1]) != named or at[i : i + count] != [k] * count:
            text = f"{insn.mnemonic} {insn.op_str}"
            result.issues.append(
                (
                    4 * k,
                    f"{text}: named by {sends_text(named)}, sends {sends_text(shape[1] if shape else ())}",
                )
            )
            i += count
            continue
        origin = page_origin(insns, k, shape[0], page)
        if origin is None:
            result.issues.append(
                (4 * k, f"{insn.mnemonic} {insn.op_str}: x{shape[0]} does not hold the channel page")
            )
        else:
            result.sends.add(k)
            if origin != "adrp":
                result.origins[origin] += 1
        i += count
    if any(a >= b for a, b in itertools.pairwise(named_insns)):
        result.issues.append((group.offset, "the sends are not in the order of their instructions"))
