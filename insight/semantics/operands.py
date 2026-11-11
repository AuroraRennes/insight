"""Operands of a capstone-decoded instruction, in the terms R needs.

Which operands are read or written is decided by R per mnemonic, never by capstone's access
flags, which are wrong for some forms (capstone 5 marks x0 as written by 'cmp x0, #3').
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from capstone import arm64_const
from capstone.arm64 import (
    ARM64_EXT_INVALID,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
    ARM64_SFT_INVALID,
    ARM64_SFT_LSL,
)

from insight.dsl.locations import SP_INDEX, Reg, VByte
from insight.dsl.terms import Term

if TYPE_CHECKING:
    from capstone import CsInsn

FP_INDEX = 29
EXT_KINDS = {3: "uxtw", 4: "uxtx", 7: "sxtw", 8: "sxtx"}
V_BYTES = 16
LANE_BYTES = {"b": 1, "h": 2, "s": 4, "d": 8, "q": 16}
# capstone's vector arrangement specifiers (ARM64_VAS_4S...): (lane bytes, lanes)
ARRANGEMENTS = {
    getattr(arm64_const, name): (LANE_BYTES[m[2].lower()], int(m[1]))
    for name in dir(arm64_const)
    if (m := re.fullmatch(r"ARM64_VAS_(\d+)([BHSDQ])", name))
}


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


@dataclass(frozen=True)
class VReg:
    """An FP/SIMD register operand, as the bytes of V<n> it names: a scalar (b0-q0: lanes 1,
    index None), a vector (v0.4s: its arrangement), or one element (v0.s[1]: lanes 1, an index).
    A scalar or vector write clears the bytes of V<n> above it; an element write keeps them."""

    n: int
    lane: int  # bytes per element
    lanes: int
    index: int | None = None

    @property
    def width(self) -> int:
        """Bytes named, in bytes."""
        return self.lane * self.lanes

    @property
    def offset(self) -> int:
        return (self.index or 0) * self.lane

    @property
    def clears_rest(self) -> bool:
        return self.index is None

    def byte(self, i: int) -> VByte:
        """Byte i of the named bytes."""
        return VByte(self.n, self.offset + i)

    def bytes(self) -> list[VByte]:
        return [self.byte(i) for i in range(self.width)]

    def rest(self) -> list[VByte]:
        """The bytes of V<n> a write clears besides the named ones."""
        return [VByte(self.n, b) for b in range(self.width, V_BYTES)] if self.clears_rest else []

    def element(self, j: int) -> list[VByte]:
        return [self.byte(j * self.lane + i) for i in range(self.lane)]


def vreg(insn: CsInsn, op: object) -> VReg | None:
    """The FP/SIMD register an operand names, or None. Capstone leaves the arrangement out of
    some element operands ('fmov x0, v1.d[1]', 'mov d0, v0.d[1]'): the lane comes from the text."""
    name = insn.reg_name(op.reg)  # type: ignore[attr-defined]
    if not name or name[0] not in "bhsdqv" or not name[1:].isdigit() or not 0 <= int(name[1:]) <= 31:
        return None
    n = int(name[1:])
    if name[0] != "v":
        return VReg(n, LANE_BYTES[name[0]], 1)
    index = op.vector_index if op.vector_index >= 0 else None  # type: ignore[attr-defined]
    if op.vas in ARRANGEMENTS:  # type: ignore[attr-defined]
        lane, lanes = ARRANGEMENTS[op.vas]  # type: ignore[attr-defined]
        return VReg(n, lane, 1 if index is not None else lanes, index)
    match = re.search(rf"\bv{n}\.(\d*)([bhsd])\b", insn.op_str)
    if match is None:
        return None
    lane = LANE_BYTES[match[2]]
    if index is not None:
        return VReg(n, lane, 1, index)
    lanes = int(match[1]) if match[1] else 1
    return VReg(n, lane, lanes)


Operand = GReg | VReg


def regs(insn: CsInsn) -> list[Operand]:
    """The register operands, general or FP/SIMD, in order; UnsupportedFormError for any other
    (system, SVE, SME)."""
    found: list[Operand] = []
    for op in insn.operands:
        if op.type != ARM64_OP_REG:
            continue
        reg = greg(insn, op.reg) or vreg(insn, op)
        if reg is None:
            raise UnsupportedFormError(insn, f"operand {insn.reg_name(op.reg)}: no rule for this register")
        found.append(reg)
    return found


def fp_simd_unsupported(insn: CsInsn) -> UnsupportedFormError:
    """No rule for an instruction with FP/SIMD operands (counted apart by the checks)."""
    return UnsupportedFormError(insn, "FP/SIMD form without a rule")


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
    post_reg: GReg | None = None  # or register (structure loads and stores: 'ld1 {...}, [x0], x2')

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
        """The base's value after the instruction (pre: base + disp, post: base + imm or + Xm)."""
        if self.post_reg is not None:
            return self.base_value() + self.post_reg.value()
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
    mode, post, post_reg = writeback(insn)
    return Address(base, op.mem.disp, index, ext, shift, mode, post, post_reg)


def writeback(insn: CsInsn) -> tuple[Literal["offset", "pre", "post"], int, GReg | None]:
    """The addressing mode, and the post-index immediate or register."""
    if not insn.writeback:
        return "offset", 0, None
    last = insn.operands[-1]
    if insn.operands[-2].type != ARM64_OP_MEM:
        return "pre", 0, None
    if last.type == ARM64_OP_IMM:
        return "post", last.imm, None
    reg = greg(insn, last.reg) if last.type == ARM64_OP_REG else None
    if reg is None or reg.kind != "x":
        raise UnsupportedFormError(insn, "post-index by a register that is not an X register")
    return "post", 0, reg
