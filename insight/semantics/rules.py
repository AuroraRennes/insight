"""R, the reference semantics: rule(insn) gives an instruction's transfer in the DSL.

The policy is built in: one tag per X register, per V-register byte and per memory byte, none on
the flags, no pointer tainting. The general-register instructions have a rule, and of the FP/SIMD
ones the loads and stores (byte for byte, structures included), the moves (an X register has one
tag: it gives it to every byte it writes, and gets the union of the bytes it reads) and the
families of data processing below; others raise UnsupportedFormError. R gives no <FP> updates: the
tracked FP is a convention of the compiler.

FP/SIMD data processing works on lanes: an arithmetic result lane gets the union of its source
lanes (the bytes of a lane mix, lanes do not), a bitwise one byte for byte, a permute moves bytes.
As for the flags, a comparison's result carries no tag (its sources are listed as 'excl'), nor does
a select's mask or a table lookup's index (no pointer tainting).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64 import ARM64_EXT_INVALID, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_SFT_INVALID, ARM64_SFT_LSL

from insight.annotations.sendcheck import instruction_sends
from insight.dsl.locations import SP_INDEX, Loc, Mem, Reg, VByte
from insight.dsl.transfer import EMPTY, ZERO, Dep, Opaque, Transfer
from insight.semantics.operands import (
    GReg,
    UnsupportedFormError,
    VReg,
    address,
    fp_simd_unsupported,
    gregs,
    immediates,
    regs,
)

if TYPE_CHECKING:
    from capstone import CsInsn

    from insight.dsl.terms import Term
    from insight.dsl.transfer import ValueReg
    from insight.semantics.operands import Address, Operand

LR = Reg(30)
SP = Reg(SP_INDEX)

# The destination (the first operand) gets the union of the other register operands.
UNION = frozenset([
    "add", "adds", "sub", "subs", "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs", "neg", "negs",
    "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "mvn",
    "lsl", "lsr", "asr", "ror", "extr",
    "mul", "madd", "msub", "mneg", "smaddl", "smsubl", "umaddl", "umsubl", "smull", "umull",
    "smnegl", "umnegl", "smulh", "umulh", "sdiv", "udiv",
    "clz", "cls", "rbit", "rev", "rev16", "rev32",
    "sxtb", "sxth", "sxtw", "uxtb", "uxth", "ubfx", "sbfx", "ubfiz", "sbfiz", "ubfm", "sbfm",
    "mov",
    "csel", "csinc", "csinv", "csneg", "cinc", "cinv", "cneg", "cset", "csetm",
])  # fmt: skip
# With both sources the same register, x - x, x ^ x, x & ~x (0), x ^ ~x, x | ~x (all ones) and
# x - x - !C (the carry's value) do not depend on it: the destination gets no tag.
CANCELLING = frozenset({"sub", "subs", "sbc", "sbcs", "eor", "eon", "bic", "bics", "orn"})
# The destination keeps the bits the instruction does not write: it is also a source.
KEEP = frozenset({"movk", "bfi", "bfxil", "bfm", "bfc"})
# The destination gets a constant (an immediate, an address computed from the PC).
CONSTANT = frozenset({"adr", "adrp", "movz", "movn"})
# Flags only: no tag written, the flags carry none.
FLAGS_ONLY = frozenset({"cmp", "cmn", "tst", "ccmp", "ccmn"})
NOTHING = frozenset({"nop", "dmb", "dsb", "isb", "clrex", "yield", "prfm", "prfum", "hint"})
# System registers carry no tag: reading one gives a clean value, writing one drops the tag.
SYSTEM_READ = frozenset({"tpidr_el0", "fpcr", "fpsr", "ctr_el0", "dczid_el0"})
SYSTEM_WRITE = frozenset({"tpidr_el0", "fpcr", "fpsr"})

# Loads and stores: bytes per register, from the mnemonic (None: from the register's width).
LOADS = {
    "ldr": None, "ldur": None, "ldar": None, "ldapr": None, "ldapur": None, "ldxr": None, "ldaxr": None,
    "ldrb": 1, "ldurb": 1, "ldarb": 1, "ldaprb": 1, "ldapurb": 1, "ldxrb": 1, "ldaxrb": 1,
    "ldrh": 2, "ldurh": 2, "ldarh": 2, "ldaprh": 2, "ldapurh": 2, "ldxrh": 2, "ldaxrh": 2,
    "ldrsb": 1, "ldursb": 1, "ldapursb": 1,
    "ldrsh": 2, "ldursh": 2, "ldapursh": 2,
    "ldrsw": 4, "ldursw": 4, "ldapursw": 4,
}  # fmt: skip
LOAD_PAIRS = {"ldp": None, "ldnp": None, "ldxp": None, "ldaxp": None, "ldpsw": 4}
STORES = {
    "str": None, "stur": None, "stlr": None, "stlur": None,
    "strb": 1, "sturb": 1, "stlrb": 1, "stlurb": 1,
    "strh": 2, "sturh": 2, "stlrh": 2, "stlurh": 2,
}  # fmt: skip
STORE_PAIRS = {"stp": None, "stnp": None}
STORE_EXCLUSIVES = {"stxr": None, "stlxr": None, "stxrb": 1, "stlxrb": 1, "stxrh": 2, "stlxrh": 2}
STORE_EXCLUSIVE_PAIRS = {"stxp": None, "stlxp": None}
# FP/SIMD: the structure loads and stores ('ld3r' is (ld, 3, r)), and the moves.
STRUCTURE = re.compile(r"(ld|st)([1-4])(r?)")
V_CONSTANT = frozenset({"movi", "mvni"})
V_MOVES = frozenset({"fmov", "mov", "umov", "smov", "ins", "dup"})
# FP/SIMD data processing, by family ('2' forms, on the upper half, under their base name).
# Lane i of the result from lane i of each source, or from an element ('mul v0.4s, v1.4s, v2.s[1]').
V_LANEWISE = frozenset([
    "add", "sub", "mul", "mla", "mls", "neg", "abs", "sqabs", "sqneg", "pmul", "sqdmulh", "sqrdmulh",
    "smax", "smin", "umax", "umin", "sabd", "uabd", "saba", "uaba",
    "shadd", "uhadd", "srhadd", "urhadd", "shsub", "uhsub", "sqadd", "uqadd", "sqsub", "uqsub",
    "suqadd", "usqadd",
    "shl", "ushr", "sshr", "urshr", "srshr", "usra", "ssra", "ursra", "srsra", "sli", "sri",
    "ushl", "sshl", "urshl", "srshl", "uqshl", "sqshl", "sqshlu", "uqrshl", "sqrshl",
    "cnt", "clz", "cls", "rbit", "urecpe", "ursqrte",
    "fadd", "fsub", "fmul", "fmulx", "fdiv", "fmla", "fmls", "fmadd", "fmsub", "fnmadd", "fnmsub",
    "fnmul", "fneg", "fabs", "fsqrt", "fmax", "fmin", "fmaxnm", "fminnm", "fabd",
    "frecpe", "frsqrte", "frecps", "frsqrts", "frecpx",
    "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz",
    "fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvtns", "fcvtnu", "fcvtps", "fcvtpu",
    "scvtf", "ucvtf", "fcsel",
])  # fmt: skip
# Byte for byte (lanes of one byte, whatever the arrangement).
V_BITWISE = frozenset({"and", "orr", "orn", "eor", "bic", "mvn", "not"})
# With both sources the same register: 0 (x - x, x ^ x, x & ~x) or all ones (x | ~x).
V_CANCELLING = frozenset({"sub", "eor", "bic", "orn"})
# Lane-wise, the result clean: its sources are 'excl'.
V_COMPARE = frozenset([
    "cmeq", "cmge", "cmgt", "cmhi", "cmhs", "cmle", "cmlt", "cmtst",
    "fcmeq", "fcmge", "fcmgt", "fcmle", "fcmlt", "facge", "facgt",
])  # fmt: skip
V_FLAGS_ONLY = frozenset({"fcmp", "fcmpe", "fccmp", "fccmpe"})
# Lanes twice as wide as the source's ('2': from its upper half), or a wide source lane-wise.
V_WIDENING = frozenset([
    "ushll", "sshll", "shll", "uxtl", "sxtl", "fcvtl", "umull", "smull", "pmull", "sqdmull",
    "uaddl", "saddl", "usubl", "ssubl", "uaddw", "saddw", "usubw", "ssubw", "uabdl", "sabdl",
    "umlal", "smlal", "umlsl", "smlsl", "sqdmlal", "sqdmlsl", "uabal", "sabal",
])  # fmt: skip
# Lanes half as wide as the source's ('2': into the upper half, the lower one kept).
V_NARROWING = frozenset([
    "xtn", "sqxtn", "uqxtn", "sqxtun", "shrn", "rshrn", "sqshrn", "uqshrn", "sqrshrn", "uqrshrn",
    "sqshrun", "sqrshrun", "addhn", "raddhn", "subhn", "rsubhn", "fcvtn", "fcvtxn",
])  # fmt: skip
# Lane i from the sources' lanes 2i and 2i + 1, taken one source after the other.
V_PAIRWISE = frozenset([
    "addp", "faddp", "smaxp", "sminp", "umaxp", "uminp", "fmaxp", "fminp", "fmaxnmp", "fminnmp",
    "uaddlp", "saddlp", "uadalp", "sadalp",
])  # fmt: skip
# Every byte written from every byte read (fcvt: one scalar to another of another size).
V_REDUCTION = frozenset([
    "addv", "smaxv", "sminv", "umaxv", "uminv", "saddlv", "uaddlv", "fmaxv", "fminv", "fmaxnmv",
    "fminnmv", "fcvt",
])  # fmt: skip
V_PERMUTE = frozenset({"zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2", "ext", "rev16", "rev32", "rev64"})
# The destination is also a source: accumulations, shift-and-insert.
V_ACCUMULATE = frozenset([
    "mla", "mls", "saba", "uaba", "usra", "ssra", "ursra", "srsra", "sli", "sri", "fmla", "fmls",
    "umlal", "smlal", "umlsl", "smlsl", "sqdmlal", "sqdmlsl", "uabal", "sabal", "uadalp", "sadalp",
])  # fmt: skip
# Byte by byte from the data or a table, the mask or index 'excl' (see v_untagged).
V_SELECT = frozenset({"bsl", "bit", "bif", "tbl", "tbx"})
# An FP/SIMD register from or to a general register, converted.
V_CONVERT_GPR = frozenset([
    "fcvtzs", "fcvtzu", "fcvtas", "fcvtau", "fcvtms", "fcvtmu", "fcvtns", "fcvtnu", "fcvtps", "fcvtpu",
    "scvtf", "ucvtf", "fjcvtzs",
])  # fmt: skip


def rule(insn: CsInsn) -> Transfer:
    """The instruction's transfer, or UnsupportedFormError."""
    mnemonic = insn.mnemonic
    if mnemonic == "svc":
        return Transfer(opaque=(Opaque("svc"),))
    if mnemonic in NOTHING:
        return Transfer()
    if mnemonic in {"mrs", "msr"}:
        return system(insn)
    if is_branch(insn):
        return branch(insn)
    if any(op.type == ARM64_OP_MEM for op in insn.operands):
        return memory(insn)
    return data_processing(insn)


def is_branch(insn: CsInsn) -> bool:
    return any(insn.group(group) for group in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET))


# Data processing
# \________________


def data_processing(insn: CsInsn) -> Transfer:
    mnemonic = insn.mnemonic
    operands = regs(insn)
    if any(isinstance(op, VReg) for op in operands):
        return fp_simd(insn, operands)
    if mnemonic in FLAGS_ONLY:
        return Transfer()
    general = gregs(insn)
    if not general:
        raise UnsupportedFormError(insn)
    dest, sources = general[0], general[1:]
    if mnemonic in CONSTANT or (mnemonic == "mov" and not sources):
        srcs: frozenset[Loc] = frozenset()
    elif mnemonic in UNION:
        srcs = frozenset() if cancels(insn, sources) else locs(sources)
    elif mnemonic in KEEP:
        srcs = locs([dest, *sources])
    else:
        raise UnsupportedFormError(insn)
    return written(insn, dest, srcs, sources)


def fp_simd(insn: CsInsn, operands: list[Operand]) -> Transfer:
    """The FP/SIMD data processing R has a rule for: constants, moves, the families above."""
    mnemonic = insn.mnemonic
    if mnemonic in V_FLAGS_ONLY:
        return Transfer()
    if mnemonic in V_CONSTANT or (mnemonic == "fmov" and len(operands) == 1):
        (dest,) = operands
        if not isinstance(dest, VReg):
            raise fp_simd_unsupported(insn)
        return Transfer(v_written(dest, [EMPTY] * dest.width))
    if mnemonic in {"orr", "bic"} and len(operands) == 1 and isinstance(operands[0], VReg):
        return masked(insn, operands[0])
    if mnemonic in V_MOVES and len(operands) == 2:
        return move(insn, *operands)
    if any(isinstance(op, GReg) for op in operands):
        return converted(insn, operands)
    return v_data(insn, [op for op in operands if isinstance(op, VReg)])


def v_data(insn: CsInsn, data: list[VReg]) -> Transfer:
    """The families of FP/SIMD data processing on FP/SIMD registers only."""
    mnemonic = insn.mnemonic
    base = base_name(mnemonic)
    dest, sources = data[0], data[1:]
    untagged = frozenset(v_untagged(insn, data))
    if dest.index is not None:
        raise fp_simd_unsupported(insn)
    if base in V_SELECT:
        return selected(insn, dest, [reg for reg in sources if reg not in untagged], untagged)
    if base in V_ACCUMULATE:
        sources = [dest, *sources]
    if base in V_CANCELLING and len(sources) == 2 and sources[0] == sources[1]:
        return Transfer(v_written(dest, [EMPTY] * dest.width))
    if base in V_LANEWISE or base in V_BITWISE or base in V_COMPARE or base in V_WIDENING:
        return lanes(insn, dest, sources, untagged, byte_lanes=base in V_BITWISE, wide=base in V_WIDENING)
    if base in V_NARROWING:
        return narrowed(insn, dest, sources, upper=mnemonic != base)
    if base in V_PAIRWISE or base in V_REDUCTION:
        return pairwise(insn, dest, sources, reduction=base in V_REDUCTION or dest.lanes == 1)
    if base in V_PERMUTE:
        return permuted(insn, dest, sources)
    raise fp_simd_unsupported(insn)


def base_name(mnemonic: str) -> str:
    """The mnemonic without the '2' of a form on the upper half ('ushll2' is 'ushll')."""
    if mnemonic.endswith("2") and mnemonic not in V_PERMUTE and mnemonic[:-1] in V_WIDENING | V_NARROWING:
        return mnemonic[:-1]
    return mnemonic


def v_untagged(insn: CsInsn, data: list[VReg]) -> list[VReg]:
    """The policy's FP/SIMD inputs whose flows carry no tag: a comparison's sources, a table
    lookup's index (no pointer tainting), a select's mask (BSL: the destination's old value; BIT
    and BIF: the last register)."""
    base = base_name(insn.mnemonic)
    if base in V_COMPARE:
        return data[1:]
    if base in {"tbl", "tbx", "bit", "bif"}:
        return data[-1:]
    if base == "bsl":
        return data[:1]
    return []


def masked(insn: CsInsn, dest: VReg) -> Transfer:
    """orr and bic of an immediate, repeated in every lane: a byte of the immediate that is all
    ones sets or clears its byte of dest, which gets no tag; the others keep theirs."""
    (op,) = [op for op in insn.operands if op.type == ARM64_OP_IMM]
    value = op.imm << op.shift.value if op.shift.type == ARM64_SFT_LSL else op.imm
    deps = [
        Dep(EMPTY if (value >> 8 * (k % dest.lane)) & 0xFF == 0xFF else frozenset({dest.byte(k)}))
        for k in range(dest.width)
    ]
    return Transfer(v_written_deps(dest, deps))


def lane_sources(insn: CsInsn, dest: VReg, reg: VReg, *, wide: bool) -> list[list[VByte]]:
    """The bytes of reg each lane of dest reads: its lane i (from its upper half for a '2'
    widening form), or the same element for every lane."""
    if reg.index is not None:
        return [reg.element(0)] * dest.lanes
    offset = reg.lanes - dest.lanes
    if reg.lane == dest.lane and offset == 0:
        return [reg.element(i) for i in range(dest.lanes)]
    if wide and 2 * reg.lane == dest.lane and offset in {0, dest.lanes}:
        return [reg.element(offset + i) for i in range(dest.lanes)]
    raise fp_simd_unsupported(insn)


def lanes(
    insn: CsInsn,
    dest: VReg,
    sources: list[VReg],
    untagged: frozenset[VReg],
    *,
    byte_lanes: bool,
    wide: bool,
) -> Transfer:
    """Each lane of dest from its lane of every source; the untagged sources (a comparison's)
    as 'excl'. Bitwise forms work on lanes of one byte."""
    unit = VReg(dest.n, 1, dest.width) if byte_lanes else dest
    per_lane: list[tuple[set[Loc], set[Loc]]] = [(set(), set()) for _ in range(unit.lanes)]
    for reg in sources:
        src = VReg(reg.n, 1, reg.width) if byte_lanes and reg.index is None else reg
        if byte_lanes and src.width != unit.width:
            raise fp_simd_unsupported(insn)
        for lane, read in zip(per_lane, lane_sources(insn, unit, src, wide=wide), strict=True):
            lane[1 if reg in untagged else 0].update(read)
    deps = [Dep(frozenset(srcs), frozenset(excl)) for srcs, excl in per_lane for _ in range(unit.lane)]
    return Transfer(v_written_deps(dest, deps))


def narrowed(insn: CsInsn, dest: VReg, sources: list[VReg], *, upper: bool) -> Transfer:
    """Lane i of the result from lane i of every source, lanes twice as wide: the whole of a
    64-bit dest (the upper bytes cleared), or the upper half of the register ('2', the lower kept)."""
    count = sources[0].lanes if sources else 0
    if any(reg.lanes != count or reg.lane != 2 * dest.lane or reg.index is not None for reg in sources):
        raise fp_simd_unsupported(insn)
    if dest.lanes != (2 * count if upper else count):
        raise fp_simd_unsupported(insn)
    first = count if upper else 0
    tags: dict[Loc, Dep] = {}
    for i in range(count):
        srcs = frozenset(byte for reg in sources for byte in reg.element(i))
        tags.update((byte, Dep(srcs)) for byte in dest.element(first + i))
    if not upper:
        tags.update((byte, Dep(EMPTY)) for byte in dest.rest())
    return Transfer(tags)


def pairwise(insn: CsInsn, dest: VReg, sources: list[VReg], *, reduction: bool) -> Transfer:
    """Lane i from lanes 2i and 2i + 1 of the sources' lanes taken one source after the other;
    an accumulating form (uadalp) adds dest's own lane i. A reduction (and a scalar pairwise
    form, of two lanes): every byte from every byte read."""
    if reduction:
        srcs = frozenset(byte for reg in sources for byte in reg.bytes())
        return Transfer(v_written(dest, [srcs] * dest.width))
    accumulates = base_name(insn.mnemonic) in V_ACCUMULATE  # sources[0] is dest
    pairs = [reg.element(j) for reg in sources[accumulates:] for j in range(reg.lanes)]
    if len(pairs) != 2 * dest.lanes or any(reg.index is not None for reg in sources):
        raise fp_simd_unsupported(insn)
    deps = []
    for i in range(dest.lanes):
        lane = set(pairs[2 * i]) | set(pairs[2 * i + 1])
        if accumulates:
            lane |= set(dest.element(i))
        deps += [Dep(frozenset(lane))] * dest.lane
    return Transfer(v_written_deps(dest, deps))


def permuted(insn: CsInsn, dest: VReg, sources: list[VReg]) -> Transfer:
    """Byte k of dest from one byte of the sources (taken one after the other for ext)."""
    mnemonic = insn.mnemonic
    n, e = dest.lanes, dest.lane
    if any(reg.index is not None or reg.width != dest.width for reg in sources):
        raise fp_simd_unsupported(insn)
    if mnemonic.startswith("rev"):
        (a,) = sources
        container = int(mnemonic[3:]) // 8
        k_bytes = [
            a.byte(k // container * container + (container // e - 1 - k % container // e) * e + k % e)
            for k in range(dest.width)
        ]
        return Transfer(v_written(dest, [frozenset({b}) for b in k_bytes]))
    a, b = sources
    elems: list[list[VByte]] = []
    if mnemonic == "ext":
        (imm,) = immediates(insn)
        both = a.bytes() + b.bytes()
        elems = [[both[imm + k]] for k in range(dest.width)]
    elif mnemonic in {"zip1", "zip2"}:
        half = n // 2 if mnemonic == "zip2" else 0
        for i in range(n // 2):
            elems += [a.element(half + i), b.element(half + i)]
    elif mnemonic in {"uzp1", "uzp2"}:
        both_elems = [a.element(j) for j in range(n)] + [b.element(j) for j in range(n)]
        elems = [both_elems[2 * i + (mnemonic == "uzp2")] for i in range(n)]
    else:  # trn1, trn2
        odd = mnemonic == "trn2"
        for i in range(n // 2):
            elems += [a.element(2 * i + odd), b.element(2 * i + odd)]
    return Transfer(v_written(dest, [frozenset({byte}) for elem in elems for byte in elem]))


def selected(insn: CsInsn, dest: VReg, data: list[VReg], untagged: frozenset[VReg]) -> Transfer:
    """Byte k of dest from byte k of the data (bsl: the two sources; bit, bif: dest's old value and
    the first source), or from any byte of the tables (tbl; tbx also keeps dest's byte k); the
    mask's or index's byte k 'excl'."""
    (control,) = untagged
    if control.width != dest.width or any(reg.index is not None for reg in data):
        raise fp_simd_unsupported(insn)
    mnemonic = insn.mnemonic
    tables = frozenset(byte for reg in data for byte in reg.bytes())
    deps = []
    for k in range(dest.width):
        if mnemonic == "tbl":
            srcs = tables
        elif mnemonic == "tbx":
            srcs = tables | {dest.byte(k)}
        else:
            srcs = frozenset(reg.byte(k) for reg in ([dest, data[0]] if mnemonic in {"bit", "bif"} else data))
        deps.append(Dep(srcs, frozenset({control.byte(k)})))
    return Transfer(v_written_deps(dest, deps))


def converted(insn: CsInsn, operands: list[Operand]) -> Transfer:
    """A conversion between an FP/SIMD and a general register: X <- the bytes read, or each byte
    written <- X."""
    if insn.mnemonic not in V_CONVERT_GPR or len(operands) != 2:
        raise fp_simd_unsupported(insn)
    dest, source = operands
    if isinstance(dest, GReg) and isinstance(source, VReg) and source.index is None:
        return Transfer({dest.loc: Dep(frozenset(source.bytes()))}) if dest.loc is not None else Transfer()
    if isinstance(dest, VReg) and isinstance(source, GReg) and dest.index is None:
        return Transfer(v_written(dest, [locs([source])] * dest.width))
    raise fp_simd_unsupported(insn)


def move(insn: CsInsn, dest: Operand, source: Operand) -> Transfer:
    """A copy between registers: X <- the union of the bytes read; each byte written <- X, or
    <- its byte of the source (a dup repeats the source element in every lane)."""
    if isinstance(dest, GReg) and isinstance(source, VReg):
        return Transfer({dest.loc: Dep(frozenset(source.bytes()))}) if dest.loc is not None else Transfer()
    if isinstance(dest, VReg) and isinstance(source, GReg):
        return Transfer(v_written(dest, [locs([source])] * dest.width))
    if isinstance(dest, VReg) and isinstance(source, VReg):
        same = source.width == dest.width
        repeated = insn.mnemonic == "dup" and source.index is not None and dest.width % source.width == 0
        if same or repeated:
            return Transfer(
                v_written(dest, [frozenset({source.byte(k % source.width)}) for k in range(dest.width)])
            )
    raise fp_simd_unsupported(insn)


def v_written(dest: VReg, srcs: list[frozenset[Loc]]) -> dict[Loc, Dep]:
    """Byte k of dest <- srcs[k]; the bytes of the register above dest cleared when it is not an
    element."""
    return v_written_deps(dest, [Dep(src) for src in srcs])


def v_written_deps(dest: VReg, deps: list[Dep]) -> dict[Loc, Dep]:
    tags: dict[Loc, Dep] = dict(zip(dest.bytes(), deps, strict=True))
    tags.update((byte, Dep(EMPTY)) for byte in dest.rest())
    return tags


def cancels(insn: CsInsn, sources: list[GReg]) -> bool:
    """Both sources are the same register, the second neither shifted nor extended."""
    if insn.mnemonic not in CANCELLING or len(sources) != 2:
        return False
    last = insn.operands[-1]
    plain = last.ext == ARM64_EXT_INVALID and (last.shift.type == ARM64_SFT_INVALID or last.shift.value == 0)
    return sources[0] == sources[1] and plain


def locs(general: list[GReg]) -> frozenset[Loc]:
    return frozenset(reg.loc for reg in general if reg.loc is not None)


def written(insn: CsInsn, dest: GReg, srcs: frozenset[Loc], sources: list[GReg]) -> Transfer:
    """dest <- srcs; when dest is SP, its new value too."""
    if dest.loc is None:
        return Transfer()
    if dest.kind != "sp":
        return Transfer({dest.loc: Dep(srcs)})
    return Transfer({SP: Dep(srcs)}, {"SP": sp_value(insn, sources)})


def sp_value(insn: CsInsn, sources: list[GReg]) -> Term:
    """SP's new value, for the forms that write it: add/sub of an immediate, mov, and with a mask."""
    imms = immediates(insn)
    if len(sources) != 1:
        raise UnsupportedFormError(insn, "SP written from more than one register")
    source = sources[0].value()
    match insn.mnemonic, imms:
        case "mov", []:
            return source
        case "add", [imm]:
            return source + shifted(insn, imm)
        case "sub", [imm]:
            return source - shifted(insn, imm)
        case "and", [imm]:
            return source & imm
    raise UnsupportedFormError(insn, "SP written by an unknown computation")


def shifted(insn: CsInsn, imm: int) -> int:
    """An add/sub immediate with its optional 'lsl #12'."""
    op = insn.operands[-1]
    return imm << op.shift.value if op.shift.value else imm


# Memory
# \_______


def data_registers(insn: CsInsn, addr: Address) -> list[GReg]:
    """The register operands of a load or store besides its address (data, then status), as many
    as its family has: capstone does not list every operand as a register ('str za[w15, 0], [x16]')."""
    data = gregs(insn)  # the memory operand's base and index are not register operands
    if addr.post_reg is not None:
        data = data[:-1]  # a post-index register is
    mnemonic = insn.mnemonic
    expected = 0
    if mnemonic in LOADS or mnemonic in STORES:
        expected = 1
    elif mnemonic in LOAD_PAIRS or mnemonic in STORE_PAIRS or mnemonic in STORE_EXCLUSIVES:
        expected = 2
    elif mnemonic in STORE_EXCLUSIVE_PAIRS:
        expected = 3
    if expected and len(data) != expected:
        raise UnsupportedFormError(insn, f"{len(data)} general register operands, {expected} expected")
    return data


def memory(insn: CsInsn) -> Transfer:
    sends = instruction_sends(insn)
    if sends:
        return Transfer(sends=tuple(ZERO if n == ZERO.n else Reg(n) for n in sends))
    mnemonic = insn.mnemonic
    addr = address(insn)
    operands = regs(insn)
    if addr.post_reg is not None:
        operands = operands[:-1]
    if any(isinstance(op, VReg) for op in operands):
        return v_memory(insn, operands, addr)
    data = data_registers(insn, addr)
    tags: dict[Loc, Dep] = {}
    if mnemonic in LOADS:
        (dest,) = data
        load(tags, dest, addr.start(), size_of(LOADS[mnemonic], dest))
    elif mnemonic in LOAD_PAIRS:
        first, second = data
        size = size_of(LOAD_PAIRS[mnemonic], first)
        load(tags, first, addr.start(), size)
        load(tags, second, addr.start() + size, size)
    elif mnemonic in STORES:
        (source,) = data
        store(tags, source, addr.start(), size_of(STORES[mnemonic], source))
    elif mnemonic in STORE_PAIRS:
        first, second = data
        size = size_of(STORE_PAIRS[mnemonic], first)
        store(tags, first, addr.start(), size)
        store(tags, second, addr.start() + size, size)
    elif mnemonic in STORE_EXCLUSIVES:
        status, source = data
        store(tags, source, addr.start(), size_of(STORE_EXCLUSIVES[mnemonic], source), may_fail=True)
        clear(tags, status)
    elif mnemonic in STORE_EXCLUSIVE_PAIRS:
        status, first, second = data
        size = size_of(None, first)
        store(tags, first, addr.start(), size, may_fail=True)
        store(tags, second, addr.start() + size, size, may_fail=True)
        clear(tags, status)
    else:
        raise UnsupportedFormError(insn)
    return with_writeback(insn, addr, tags)


def with_writeback(insn: CsInsn, addr: Address, tags: dict[Loc, Dep]) -> Transfer:
    """The transfer of a load or store with its base's write-back: SP's new value; a base
    post-indexed by a register gets that register's tag too, as an add would."""
    values: dict[ValueReg, Term] = {}
    if addr.mode != "offset" and Reg(addr.base.n) in tags:
        raise UnsupportedFormError(insn, "write-back to a register the instruction also loads")
    if addr.mode != "offset" and addr.base.kind == "sp":
        if addr.post_reg is not None:
            raise UnsupportedFormError(insn, "SP post-indexed by a register")
        values["SP"] = addr.written_back()
    elif addr.post_reg is not None and addr.base.loc is not None:
        tags[addr.base.loc] = Dep(locs([addr.base, addr.post_reg]))
    return Transfer(tags, values)


def v_memory(insn: CsInsn, operands: list[Operand], addr: Address) -> Transfer:
    """FP/SIMD loads and stores, byte for byte: each register byte with its memory byte. A load
    clears the bytes of the register above the ones it writes, except into an element."""
    mnemonic = insn.mnemonic
    data = [op for op in operands if isinstance(op, VReg)]
    if len(data) != len(operands):
        raise fp_simd_unsupported(insn)
    start = addr.start()
    is_load = mnemonic in LOADS or mnemonic in LOAD_PAIRS or mnemonic.startswith("ld")
    placed: list[tuple[VReg, list[Term]]] = []
    plain = LOADS | LOAD_PAIRS | STORES | STORE_PAIRS
    if mnemonic in plain and plain[mnemonic] is None:
        expected = 2 if mnemonic in LOAD_PAIRS or mnemonic in STORE_PAIRS else 1
        if len(data) != expected or any(reg.index is not None or reg.lanes != 1 for reg in data):
            raise fp_simd_unsupported(insn)
        offset = 0
        for reg in data:
            placed.append((reg, [start + offset + k for k in range(reg.width)]))
            offset += reg.width
    elif match := STRUCTURE.fullmatch(mnemonic):
        placed = structure(insn, data, start, int(match[2]), replicate=bool(match[3]))
    else:
        raise fp_simd_unsupported(insn)
    tags: dict[Loc, Dep] = {}
    for reg, addrs in placed:
        if is_load:
            tags.update(v_written(reg, [frozenset({Mem(a)}) for a in addrs]))
        else:
            tags.update((Mem(a), Dep(frozenset({byte}))) for a, byte in zip(addrs, reg.bytes(), strict=True))
    return with_writeback(insn, addr, tags)


def structure(
    insn: CsInsn, data: list[VReg], start: Term, n: int, *, replicate: bool
) -> list[tuple[VReg, list[Term]]]:
    """The address of each byte of each register of an ldN/stN: one register's elements in a row
    (n = 1, registers one after the other), n registers' elements interleaved, one element per
    register (a lane), or one element per register repeated in every lane (ldNr)."""
    first = data[0]
    if any((reg.lane, reg.lanes, reg.index) != (first.lane, first.lanes, first.index) for reg in data):
        raise fp_simd_unsupported(insn)
    if (n > 1 and len(data) != n) or not 1 <= len(data) <= 4:
        raise fp_simd_unsupported(insn)
    e = first.lane
    placed: list[tuple[VReg, list[Term]]] = []
    for r, reg in enumerate(data):
        if replicate:
            addrs = [start + r * e + k % e for k in range(reg.width)]
        elif reg.index is not None or n > 1:
            addrs = [start + ((k // e) * n + r) * e + k % e for k in range(reg.width)]
        else:
            addrs = [start + r * reg.width + k for k in range(reg.width)]
        placed.append((reg, addrs))
    return placed


def size_of(size: int | None, reg: GReg) -> int:
    return reg.width if size is None else size


def mem_range(start: Term, size: int) -> list[Mem]:
    return [Mem(start + i) for i in range(size)]


def load(tags: dict[Loc, Dep], dest: GReg, start: Term, size: int) -> None:
    """dest <- the bytes read; a load into the zero register writes nothing."""
    if dest.loc is not None:
        tags[dest.loc] = Dep(frozenset(mem_range(start, size)))


def store(tags: dict[Loc, Dep], source: GReg, start: Term, size: int, *, may_fail: bool = False) -> None:
    """Each byte written <- the source register (one tag for the whole register). A
    store-exclusive may fail and leave the bytes as they were: each byte keeps its tag or takes
    the register's, whichever happens at run time."""
    srcs = locs([source])
    for loc in mem_range(start, size):
        tags[loc] = Dep(srcs | {loc} if may_fail else srcs)


def clear(tags: dict[Loc, Dep], dest: GReg) -> None:
    if dest.loc is not None:
        tags[dest.loc] = Dep(frozenset())


# Branches and system
# \____________________


def branch(insn: CsInsn) -> Transfer:
    """Control flow only, except that a call writes LR, the return address: a constant."""
    if insn.mnemonic in {"bl", "blr"}:
        return Transfer({LR: Dep(frozenset())})
    if insn.mnemonic in {"b", "br", "ret", "cbz", "cbnz", "tbz", "tbnz"} or insn.mnemonic.startswith("b."):
        return Transfer()
    raise UnsupportedFormError(insn)


def system(insn: CsInsn) -> Transfer:
    name = insn.op_str.split(",")[0 if insn.mnemonic == "msr" else 1].strip().lower()
    if insn.mnemonic == "mrs":
        if name not in SYSTEM_READ:
            raise UnsupportedFormError(insn, f"system register {name}")
        (dest,) = gregs(insn)
        return written(insn, dest, frozenset(), [])
    if name not in SYSTEM_WRITE:
        raise UnsupportedFormError(insn, f"system register {name}")
    return Transfer()
