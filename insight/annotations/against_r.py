"""The static check of each instruction's annotation, or each block form, against R."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone.arm64 import ARM64_OP_MEM, ARM64_SFT_INVALID, ARM64_SFT_LSL

from insight.annotations.framing import INSTRUCTION_SIZE
from insight.annotations.pairing import pair_forms, pair_sends, register_writes
from insight.annotations.sendcheck import send_shape
from insight.dsl.errors import DslError
from insight.dsl.locations import Reg
from insight.dsl.terms import Sym, Term
from insight.dsl.transfer import Dep, Opaque, Transfer, compose
from insight.semantics.operands import FP_INDEX, GReg, UnsupportedFormError, address, gregs
from insight.semantics.rules import rule, sp_value

if TYPE_CHECKING:
    from collections.abc import Sequence

    from capstone import CsInsn

    from insight.annotations.framing import Block
    from insight.dsl.locations import Loc
    from insight.dsl.transfer import ValueReg

LO12 = Sym("LO12")


@dataclass
class Comparison:
    """Per block: the mismatches (offset, message) and the instructions R has no rule for."""

    mismatches: list[tuple[int, str]] = field(default_factory=list)
    unsupported: list[tuple[int, str]] = field(default_factory=list)
    jump_table_loads: int = 0  # loads compared with the jump-table convention, not R


def encoded_offset(insn: CsInsn) -> int:
    for op in insn.operands:
        if op.type == ARM64_OP_MEM:
            disp: int = op.mem.disp
            return disp
    return 0


def comparable(
    transfer: Transfer,
) -> tuple[
    dict[Loc, tuple[frozenset[Loc], frozenset[Loc]]],
    Term | None,
    tuple[Opaque, ...],
    tuple[Reg, ...],
]:
    """The parts compared: tags without over, <SP>, opaque statements, sends."""
    normal = transfer.normalized()
    tags = {loc: (dep.srcs, dep.excl) for loc, dep in normal.tags.items()}
    return tags, normal.values.get("SP"), normal.opaque, normal.sends


def describe(loc: Loc, dep: tuple[frozenset[Loc], frozenset[Loc]] | None) -> str:
    if dep is None:
        return f"{loc} kept"
    srcs, excl = dep
    text = " | ".join(sorted(map(str, srcs))) or "0"
    if excl:
        text += " excl " + " | ".join(sorted(map(str, excl)))
    return f"{loc} <- {text}"


def differences(annotation: Transfer, reference: Transfer) -> list[str]:
    a_tags, a_sp, a_opaque, a_sends = comparable(annotation)
    r_tags, r_sp, r_opaque, r_sends = comparable(reference)
    found = [
        f"annotation {describe(loc, a_tags.get(loc))}, R {describe(loc, r_tags.get(loc))}"
        for loc in sorted(set(a_tags) | set(r_tags), key=str)
        if a_tags.get(loc) != r_tags.get(loc)
    ]
    if a_sp != r_sp:
        found.append(f"annotation <SP> <- {a_sp or '<SP>'}, R <SP> <- {r_sp or '<SP>'}")
    if a_opaque != r_opaque:
        found.append(f"annotation {list(map(str, a_opaque))}, R {list(map(str, r_opaque))}")
    if a_sends != r_sends:
        found.append(f"annotation sends {list(map(str, a_sends))}, R {list(map(str, r_sends))}")
    return found


def without_fp(transfer: Transfer) -> Transfer:
    values: dict[ValueReg, Term] = {reg: term for reg, term in transfer.values.items() if reg != "FP"}
    return Transfer(dict(transfer.tags), values, transfer.opaque, transfer.sends)


# The entry load of a dispatch: the view of the register loaded, the index's shift, then the
# add's shift of the entry.
JUMP_TABLE_ENTRIES = {"ldrb": ("w", 0, 2), "ldrh": ("w", 1, 2), "ldrsw": ("x", 2, 0)}


def shift_of(insn: CsInsn) -> int | None:
    """The lsl of the last operand (0 without one), None for another shift or an extension."""
    op = insn.operands[-1]
    if op.shift.type == ARM64_SFT_INVALID:
        return 0
    return op.shift.value if op.shift.type == ARM64_SFT_LSL else None


def jump_table_load(adr: CsInsn, load: CsInsn, add: CsInsn) -> Transfer | None:
    """The convention's transfer of load, Ws <- 0, when the three are a jump-table dispatch: the
    table is read-only and starts untagged."""
    if (adr.mnemonic, add.mnemonic) != ("adr", "add") or load.mnemonic not in JUMP_TABLE_ENTRIES:
        return None
    view, index_shift, entry_shift = JUMP_TABLE_ENTRIES[load.mnemonic]
    try:
        (dest,), (entry,), addr = gregs(adr), gregs(load), address(load)
        sums = gregs(add)
    except (UnsupportedFormError, ValueError):
        return None
    dispatch = (
        dest.kind == "x"
        and sums == [dest, dest, GReg("x", entry.n)]
        and shift_of(add) == entry_shift
        and addr.mode == "offset"
        and addr.disp == 0
        and addr.index is not None
        and addr.index.kind == "x"
        and addr.ext == "uxtx"
        and addr.shift == index_shift
        and entry.kind == view
        and entry.n != dest.n
    )
    return Transfer({Reg(entry.n): Dep(frozenset())}) if dispatch else None


def send_transfer(insn: CsInsn) -> Transfer:
    """What a send does: its registers go to the channel, which is not tracked memory."""
    shape = send_shape(insn)
    if shape is None:
        msg = f"{insn.mnemonic} {insn.op_str} is not a send"
        raise ValueError(msg)
    return Transfer(sends=tuple(Reg(n) for n in shape[1]))


def reference(insns: Sequence[CsInsn], i: int, sends: set[int] | None) -> tuple[Transfer, bool]:
    """R's transfer of insns[i], or the convention's for a send or a jump-table load (then True)."""
    insn = insns[i]
    if sends and i in sends:
        return send_transfer(insn), True
    convention = jump_table_load(insns[i - 1], insn, insns[i + 1]) if 0 < i < len(insns) - 1 else None
    return (rule(insn), False) if convention is None else (convention, True)


# Block forms
# \____________


def fp_update(insn: CsInsn, sent: tuple[int, ...]) -> Term | None:
    """The compiler's convention for the tracked FP, which R does not give; None when unchanged."""
    # A send of x29 gives it.
    if 29 in sent:
        return Term.sym("<X29>")
    if 29 not in register_writes(insn):
        return None
    try:
        dests, addr = gregs(insn), None
        # An add, sub or mov from SP or FP computes it.
        if (
            dests
            and dests[0].kind == "x"
            and dests[0].n == FP_INDEX
            and insn.mnemonic in {"add", "sub", "mov"}
        ):
            sources = dests[1:]
            if len(sources) == 1 and (sources[0].kind == "sp" or sources[0].n == FP_INDEX):
                return sp_value(insn, sources)
        # So does a write-back of an FP base.
        if insn.op_str.count("[") == 1:
            addr = address(insn)
        if addr is not None and addr.mode != "offset" and addr.base.n == FP_INDEX and addr.post_reg is None:
            return addr.written_back()
    except (UnsupportedFormError, ValueError):
        pass
    # Any other write of x29 (a reload, say) leaves it until x29 is sent.
    return None


def compare_block(block: Block, insns: Sequence[CsInsn], sends: set[int] | None = None) -> Comparison:
    """Each group against R, sends being the indices of the instructions that are sends."""
    sends = sends or set()
    result = Comparison()
    refs: list[Transfer | None] = []
    for i, insn in enumerate(insns):
        try:
            ref, convention = reference(insns, i, sends)
        except UnsupportedFormError as error:
            refs.append(None)
            result.unsupported.append(
                (INSTRUCTION_SIZE * i, f"{insn.mnemonic} {insn.op_str}: {error.reason}")
            )
            continue
        result.jump_table_loads += convention and i not in sends
        fp = fp_update(insn, tuple(reg.n for reg in ref.sends))
        values = dict(ref.values) | ({"FP": fp} if fp is not None else {})
        refs.append(
            Transfer(ref.tags, values, ref.opaque, ref.sends).subst({LO12: Term.of(encoded_offset(insn))})
        )
    # Both sides are paired with the sends first.
    writes = [register_writes(insn) for insn in insns]
    _, paired_refs = pair_forms([Transfer() if ref is None else ref for ref in refs], writes, strict=False)
    forms = pair_sends(block, writes, strict=False).forms
    start = 0
    for group, form in zip(block.groups, forms, strict=True):
        span = range(start, start + group.count)
        start += group.count
        if any(refs[k] is None for k in span):
            continue  # counted as unsupported
        # R reads the offset the linker encoded in the instruction.
        offsets = {Sym(f"LO12@{INSTRUCTION_SIZE * k}"): Term.of(encoded_offset(insns[k])) for k in span}
        offsets[LO12] = Term.of(encoded_offset(insns[span[0]]))
        annotation = form.subst(offsets)
        # One instruction against its rule, FP aside: a convention of the compiler.
        if group.count == 1:
            insn = insns[span[0]]
            result.mismatches.extend(
                (group.offset, f"{insn.mnemonic} {insn.op_str}: {diff}")
                for diff in differences(without_fp(annotation), paired_refs[span[0]])
            )
            continue
        # A block form against R composed over its instructions, FP included (fp_update).
        try:
            composed = compose(
                Transfer(paired_refs[k].tags, paired_refs[k].values, paired_refs[k].opaque) for k in span
            )
        except DslError as error:
            result.mismatches.append((group.offset, f"R over {group.count} instructions: {error}"))
            continue
        result.mismatches.extend(
            (group.offset, f"{group.count} instructions: {diff}")
            for diff in form_differences(annotation, composed)
        )
    return result


def form_differences(annotation: Transfer, reference: Transfer) -> list[str]:
    """differences() for block forms: the sends set aside, FP compared."""
    found = differences(
        Transfer(annotation.tags, annotation.values, annotation.opaque),
        Transfer(reference.tags, reference.values, reference.opaque),
    )
    a_fp, r_fp = annotation.normalized().values.get("FP"), reference.normalized().values.get("FP")
    if a_fp != r_fp:
        found.append(f"annotation <FP> <- {a_fp or '<FP>'}, R <FP> <- {r_fp or '<FP>'}")
    return found
