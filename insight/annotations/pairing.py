"""Pairing each register value <Xn> of a block's groups with the send that carries it, S<i>.

<Xn> pairs with the nearest preceding send of Xn with no write of Xn in between, otherwise with the
nearest following one, as grammar.ebnf describes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from insight.annotations.framing import INSTRUCTION_SIZE
from insight.dsl.terms import Term
from insight.dsl.transfer import Transfer

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from capstone import CsInsn
    from elftools.elf.elffile import ELFFile

    from insight.annotations.framing import Block
    from insight.dsl.locations import Reg
    from insight.dsl.terms import Sym

REGISTER_RE = re.compile(r"[xw]([0-9]|[12][0-9]|30)")
REGISTER_ALIASES = {"fp": 29, "lr": 30}
# A call may change every caller-saved register; svc writes X0 and not LR (capstone lists LR).
CALL_WRITES = frozenset([*range(18), 30])
SVC_WRITES = frozenset({0})
# Compares write only NZCV (they are subs, adds and ands into XZR); capstone lists their first
# operand as written.
COMPARES = frozenset({"cmp", "cmn", "tst"})


class PairingError(Exception):
    def __init__(self, message: str, address: int, offset: int) -> None:
        super().__init__(f"block {address:#x} @{offset}: {message}")
        self.message = message
        self.address = address
        self.offset = offset


@dataclass(frozen=True)
class Send:
    index: int  # S<index>
    group: int  # the index of the instruction that sends it
    reg: Reg


@dataclass(frozen=True)
class PairedBlock:
    block: Block
    sends: tuple[Send, ...]
    forms: tuple[Transfer, ...]  # each group's form, <Xn> replaced by S<i>


# Register writes
# \________________


def register_number(name: str) -> int | None:
    """The number of a general register from capstone's name (x0, w0, fp, lr), None for others."""
    if match := REGISTER_RE.fullmatch(name):
        return int(match.group(1))
    return REGISTER_ALIASES.get(name)


def register_writes(insn: CsInsn) -> frozenset[int]:
    """The X registers (by number) an instruction writes, write-backs included."""
    if insn.mnemonic in COMPARES:
        return frozenset()
    written: set[int] = set()
    for reg in insn.regs_access()[1]:
        n = register_number(insn.reg_name(reg))
        if n is not None:
            written.add(n)
    if insn.mnemonic in {"bl", "blr"}:
        written |= CALL_WRITES
    elif insn.mnemonic == "svc":
        written = set(SVC_WRITES)
    return frozenset(written)


def decode(code: bytes, address: int) -> list[CsInsn]:
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    insns = list(disassembler.disasm(code, address))
    if sum(insn.size for insn in insns) != len(code):
        msg = f"cannot decode every instruction from {address:#x}"
        raise ValueError(msg)
    return insns


def code_at(elf: ELFFile, address: int, size: int) -> bytes:
    """The bytes at an address, from the allocated section that holds them."""
    for section in elf.iter_sections():
        start = section["sh_addr"]
        if (
            section["sh_type"] == "SHT_PROGBITS"
            and start <= address
            and address + size <= start + section["sh_size"]
        ):
            data: bytes = section.data()
            return data[address - start : address - start + size]
    msg = f"no section holds {size} bytes at {address:#x}"
    raise ValueError(msg)


def block_writes(elf: ELFFile, block: Block) -> list[frozenset[int]]:
    """The registers each group's instruction writes."""
    return [register_writes(insn) for insn in decode(code_at(elf, block.address, block.size), block.address)]


# Pairing
# \________


def pair_sends(block: Block, writes: Sequence[frozenset[int]], *, strict: bool = True) -> PairedBlock:
    """Every <Xn> of the block paired with its send; writes gives each instruction's register
    writes. The pairing runs over instructions, each send at the instruction the block table gives:
    a block form's writes keep their order with its sends. A group of several instructions has no
    <Xn> left to pair; not strict, an <Xn> without a send stays."""
    if len(writes) != block.size // INSTRUCTION_SIZE:
        msg = f"{len(writes)} instructions for a block of {block.size // INSTRUCTION_SIZE}"
        raise ValueError(msg)
    units = [Transfer() for _ in writes]
    for group in block.groups:
        first = group.offset // INSTRUCTION_SIZE
        if group.count == 1:
            units[first] = group.form
            continue
        if strict and any(sym.is_register for sym in group.form.symbols()):
            msg = "an <Xn> in a group of several instructions"
            raise PairingError(msg, block.address, group.offset)
        for offset, reg in zip(group.send_at, group.form.sends, strict=True):
            k = offset // INSTRUCTION_SIZE
            units[k] = Transfer(sends=(*units[k].sends, reg))
    try:
        sends, paired = pair_forms(units, writes, strict=strict)
    except UnpairedError as error:
        raise PairingError(error.message, block.address, INSTRUCTION_SIZE * error.unit) from error
    forms = tuple(
        paired[group.offset // INSTRUCTION_SIZE] if group.count == 1 else group.form for group in block.groups
    )
    return PairedBlock(block, sends, forms)


class UnpairedError(Exception):
    def __init__(self, message: str, unit: int) -> None:
        super().__init__(message)
        self.message = message
        self.unit = unit


def pair_forms(
    forms: Sequence[Transfer], writes: Sequence[frozenset[int]], *, strict: bool = True
) -> tuple[tuple[Send, ...], tuple[Transfer, ...]]:
    """The sends of a sequence of forms (groups or instructions), numbered in order, and each form
    with its <Xn> replaced by the send that carries it; not strict, an <Xn> without one stays."""
    sends = tuple(
        Send(index, unit, reg)
        for index, (unit, reg) in enumerate(
            (unit, reg) for unit, form in enumerate(forms) for reg in form.sends
        )
    )
    paired: list[Transfer] = []
    for k, form in enumerate(forms):
        mapping: dict[Sym, Term] = {}
        for sym in sorted(form.symbols(), key=str):
            if not sym.is_register:
                continue
            send = find_send(int(sym.name[2:-1]), k, sends, writes.__getitem__)
            if send is None:
                if not strict:
                    continue
                msg = f"{sym}: no send of X{sym.name[2:-1]} in the block without a write in between"
                raise UnpairedError(msg, k)
            mapping[sym] = Term.sym(f"S{send.index}")
        paired.append(form.subst(mapping))
    return sends, tuple(paired)


def find_send(
    n: int, k: int, sends: tuple[Send, ...], writes: Callable[[int], frozenset[int]]
) -> Send | None:
    """The send that carries Xn at group k's entry: nearest preceding, else nearest following."""
    candidates = [send for send in sends if send.reg.n == n]
    before = [send for send in candidates if send.group <= k]
    if before:
        send = before[-1]
        if not any(n in writes(m) for m in range(send.group + 1, k)):
            return send
    after = [send for send in candidates if send.group > k]
    if after:
        send = after[0]
        if not any(n in writes(m) for m in range(k, send.group)):
            return send
    return None
