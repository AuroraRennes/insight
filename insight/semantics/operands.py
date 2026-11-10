"""Operands of a capstone-decoded instruction, in the terms R needs.

Which operands are read or written is decided by R per mnemonic, never by capstone's access
flags, which are wrong for some forms (capstone 5 marks x0 as written by 'cmp x0, #3').
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from capstone.arm64 import (
    ARM64_EXT_INVALID,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
    ARM64_SFT_INVALID,
    ARM64_SFT_LSL,
)

from insight.dsl.locations import SP_INDEX, Reg
from insight.dsl.terms import Term

if TYPE_CHECKING:
    from capstone import CsInsn

FP_INDEX = 29
EXT_KINDS = {3: "uxtw", 4: "uxtx", 7: "sxtw", 8: "sxtx"}


class UnsupportedFormError(Exception):
    """An instruction R has no rule for: R fails closed, naming it."""

    def __init__(self, insn: CsInsn, reason: str = "no rule") -> None:
        super().__init__(f"{insn.mnemonic} {insn.op_str}: {reason}")
        self.text = f"{insn.mnemonic} {insn.op_str}"
        self.reason = reason


@dataclass(frozen=True)
class GReg:
    """A general register operand: X or W view of 0-30, SP, or the zero register."""

    kind: Literal["x", "w", "sp", "xzr", "wzr"]
    n: int  # 0-30, SP_INDEX for SP and the zero register

    @property
    def is_zero(self) -> bool:
        return self.kind in {"xzr", "wzr"}

    @property
    def loc(self) -> Reg | None:
        """Its tag location; the zero register has none."""
        return None if self.is_zero else Reg(self.n)

    @property
    def width(self) -> int:
        """In bytes."""
        return 4 if self.kind in {"w", "wzr"} else 8

    def value(self) -> Term:
        """Its value at the instruction's entry, as a DSL term. x29's is <FP>, the tracked FP: by
        the compiler's convention every write of x29 is followed by an update of <FP>, so the two
        are equal; the convention rules and the replay's audit check it, not R."""
        if self.is_zero:
            return Term.of(0)
        if self.kind == "sp":
            return Term.sym("<SP>")
        if self.n == FP_INDEX:
            return Term.sym("<FP>")
        return Term.sym(f"<X{self.n}>")


def greg(insn: CsInsn, reg: int) -> GReg | None:
    """The general register capstone calls reg, or None when it is not one (V, FP, system)."""
    name = insn.reg_name(reg)
    if name in {"sp", "wsp"}:
        return GReg("sp", SP_INDEX)
    if name in {"xzr", "wzr"}:
        return GReg("xzr" if name == "xzr" else "wzr", SP_INDEX)
    if name == "fp":
        return GReg("x", 29)
    if name == "lr":
        return GReg("x", 30)
    if name[0] in "xw" and name[1:].isdigit() and 0 <= int(name[1:]) <= 30:
        return GReg("x" if name[0] == "x" else "w", int(name[1:]))
    return None


def gregs(insn: CsInsn) -> list[GReg]:
    """The register operands, in order; UnsupportedFormError if one is not a general register."""
    found: list[GReg] = []
    for op in insn.operands:
        if op.type != ARM64_OP_REG:
            continue
        reg = greg(insn, op.reg)
        if reg is None:
            raise UnsupportedFormError(insn, f"operand {insn.reg_name(op.reg)} is not a general register")
        found.append(reg)
    return found


def immediates(insn: CsInsn) -> list[int]:
    return [op.imm for op in insn.operands if op.type == ARM64_OP_IMM]


@dataclass(frozen=True)
class Address:
    """A memory operand: base, then an immediate or an extended index, and the write-back."""

    base: GReg
    disp: int
    index: GReg | None
    ext: str | None  # uxtw, sxtw, uxtx (also for 'lsl'), sxtx
    shift: int
    mode: Literal["offset", "pre", "post"]
    post: int  # the post-index immediate

    @property
    def registers(self) -> frozenset[Reg]:
        """The address inputs: base and index, held fixed by the flip tests and excluded for the data."""
        regs = {self.base.loc, self.index.loc if self.index else None}
        return frozenset(reg for reg in regs if reg is not None)

    def base_value(self) -> Term:
        return self.base.value()

    def start(self) -> Term:
        """The address of the first byte accessed."""
        if self.mode == "post":
            return self.base_value()
        term = self.base_value() + self.disp
        if self.index is not None and self.ext is not None:
            term = term + self.index.value().ext(self.ext, self.shift)
        return term

    def written_back(self) -> Term:
        """The base's value after the instruction (pre: base + disp, post: base + imm)."""
        return self.base_value() + (self.post if self.mode == "post" else self.disp)


def address(insn: CsInsn) -> Address:
    mems = [op for op in insn.operands if op.type == ARM64_OP_MEM]
    if len(mems) != 1:
        raise UnsupportedFormError(insn, "not one memory operand")
    op = mems[0]
    base = greg(insn, op.mem.base)
    if base is None or base.kind not in {"x", "sp"}:
        raise UnsupportedFormError(insn, "base is not an X register or SP")
    index = greg(insn, op.mem.index) if op.mem.index else None
    ext: str | None = None
    shift = 0
    if index is not None:
        if op.ext != ARM64_EXT_INVALID:
            if op.ext not in EXT_KINDS:
                raise UnsupportedFormError(insn, f"index extension {op.ext}")
            ext = EXT_KINDS[op.ext]
        else:
            ext = "uxtx"
        if op.shift.type == ARM64_SFT_LSL:
            shift = op.shift.value
        elif op.shift.type != ARM64_SFT_INVALID:
            raise UnsupportedFormError(insn, "index shift other than lsl")
    mode: Literal["offset", "pre", "post"] = "offset"
    post = 0
    if insn.writeback:
        last = insn.operands[-1]
        if last.type == ARM64_OP_IMM and insn.operands[-2].type == ARM64_OP_MEM:
            mode, post = "post", last.imm
        else:
            mode = "pre"
    return Address(base, op.mem.disp, index, ext, shift, mode, post)
