"""R, the reference semantics: rule(insn) gives an instruction's transfer in the DSL.

The policy is built in: one tag per X register and per memory byte, none on the flags, no pointer
tainting. Only the general-register instructions have a rule; others raise UnsupportedFormError.
R gives no <FP> updates: the tracked FP is a convention of the compiler.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64 import ARM64_EXT_INVALID, ARM64_OP_MEM, ARM64_SFT_INVALID

from insight.annotations.sendcheck import instruction_sends
from insight.dsl.locations import SP_INDEX, Loc, Mem, Reg
from insight.dsl.transfer import ZERO, Dep, Opaque, Transfer
from insight.semantics.operands import UnsupportedFormError, address, gregs, immediates

if TYPE_CHECKING:
    from capstone import CsInsn

    from insight.dsl.terms import Term
    from insight.dsl.transfer import ValueReg
    from insight.semantics.operands import GReg

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
    regs = gregs(insn)
    if mnemonic in FLAGS_ONLY:
        return Transfer()
    if not regs:
        raise UnsupportedFormError(insn)
    dest, sources = regs[0], regs[1:]
    if mnemonic in CONSTANT or (mnemonic == "mov" and not sources):
        srcs: frozenset[Loc] = frozenset()
    elif mnemonic in UNION:
        srcs = frozenset() if cancels(insn, sources) else locs(sources)
    elif mnemonic in KEEP:
        srcs = locs([dest, *sources])
    else:
        raise UnsupportedFormError(insn)
    return written(insn, dest, srcs, sources)


def cancels(insn: CsInsn, sources: list[GReg]) -> bool:
    """Both sources are the same register, the second neither shifted nor extended."""
    if insn.mnemonic not in CANCELLING or len(sources) != 2:
        return False
    last = insn.operands[-1]
    plain = last.ext == ARM64_EXT_INVALID and (last.shift.type == ARM64_SFT_INVALID or last.shift.value == 0)
    return sources[0] == sources[1] and plain


def locs(regs: list[GReg]) -> frozenset[Loc]:
    return frozenset(reg.loc for reg in regs if reg.loc is not None)


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


def data_registers(insn: CsInsn) -> list[GReg]:
    """The register operands of a load or store besides its address (data, then status), as many
    as its family has: capstone does not list every operand as a register ('str za[w15, 0], [x16]')."""
    data = gregs(insn)  # the memory operand's base and index are not register operands
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
    data = data_registers(insn)
    addr = address(insn)
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
    values: dict[ValueReg, Term] = {}
    if addr.mode != "offset" and addr.base.kind == "sp":
        values["SP"] = addr.written_back()
    elif addr.mode != "offset" and Reg(addr.base.n) in tags:
        raise UnsupportedFormError(insn, "write-back to a register the instruction also loads")
    return Transfer(tags, values)


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
