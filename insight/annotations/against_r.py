"""The static check of each instruction's annotation against R.

<FP> updates are not compared (a convention of the compiler), and LO12 is replaced by the
instruction's encoded offset, which is what R reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone.arm64 import ARM64_OP_MEM

from insight.dsl.terms import Sym, Term
from insight.dsl.transfer import Opaque, Transfer, ZeroReg
from insight.semantics.operands import UnsupportedFormError
from insight.semantics.rules import rule

if TYPE_CHECKING:
    from collections.abc import Sequence

    from capstone import CsInsn

    from insight.annotations.framing import Block
    from insight.dsl.locations import Loc, Reg
    from insight.dsl.transfer import ValueReg

LO12 = Sym("LO12")


@dataclass
class Comparison:
    """Per block: the mismatches (offset, message) and the instructions R has no rule for."""

    mismatches: list[tuple[int, str]] = field(default_factory=list)
    unsupported: list[tuple[int, str]] = field(default_factory=list)


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


def compare_block(block: Block, insns: Sequence[CsInsn]) -> Comparison:
    result = Comparison()
    for group, insn in zip(block.groups, insns, strict=True):
        text = f"{insn.mnemonic} {insn.op_str}"
        try:
            reference = rule(insn)
        except UnsupportedFormError as error:
            result.unsupported.append((group.offset, f"{text}: {error.reason}"))
            continue
        annotation = without_fp(group.form.subst({LO12: Term.of(encoded_offset(insn))}))
        result.mismatches.extend(
            (group.offset, f"{text}: {diff}") for diff in differences(annotation, reference)
        )
    return result
