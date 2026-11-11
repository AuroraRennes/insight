"""The static check of each instruction's annotation against R.

<FP> updates are not compared (a convention of the compiler), and LO12 is replaced by the
instruction's encoded offset, which is what R reads. The entry load of a jump-table dispatch
(adr, ldr, add) is compared with a clear: the table is read-only and starts untagged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone.arm64 import ARM64_OP_MEM, ARM64_SFT_INVALID, ARM64_SFT_LSL

from insight.dsl.locations import Reg
from insight.dsl.terms import Sym, Term
from insight.dsl.transfer import Dep, Opaque, Transfer, ZeroReg
from insight.semantics.operands import GReg, UnsupportedFormError, address, gregs
from insight.semantics.rules import rule

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
    tuple[Reg | ZeroReg, ...],
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
    """The convention's transfer of load, Ws <- 0, when the three are a jump-table dispatch."""
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


def compare_block(block: Block, insns: Sequence[CsInsn]) -> Comparison:
    result = Comparison()
    for i, (group, insn) in enumerate(zip(block.groups, insns, strict=True)):
        text = f"{insn.mnemonic} {insn.op_str}"
        convention = jump_table_load(insns[i - 1], insn, insns[i + 1]) if 0 < i < len(insns) - 1 else None
        try:
            reference = rule(insn) if convention is None else convention
        except UnsupportedFormError as error:
            result.unsupported.append((group.offset, f"{text}: {error.reason}"))
            continue
        annotation = without_fp(group.form.subst({LO12: Term.of(encoded_offset(insn))}))
        result.mismatches.extend(
            (group.offset, f"{text}: {diff}") for diff in differences(annotation, reference)
        )
        result.jump_table_loads += convention is not None
    return result
