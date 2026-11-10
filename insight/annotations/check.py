"""Checking every annotated block of an executable: framing, send lines, and pairing.

Each block is read on its own, so one block's issue does not hide another's. A block in the old
format stops the check: the whole executable is then in the old format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from insight.annotations.against_r import compare_block
from insight.annotations.framing import (
    ANNOTATION_SECTION,
    BLOCK_TABLE_SECTION,
    FramingError,
    OldFormatError,
    block_table,
    block_texts,
    read_block,
)
from insight.annotations.pairing import PairingError, code_at, decode, pair_sends, register_writes
from insight.annotations.sendcheck import check_sends

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile

    from insight.annotations.framing import Block


@dataclass(frozen=True)
class Issue:
    address: int
    offset: int | None
    message: str

    def __str__(self) -> str:
        where = (
            f"block {self.address:#x}" if self.offset is None else f"block {self.address:#x} @{self.offset}"
        )
        return f"{where}: {self.message}"


@dataclass(frozen=True)
class Report:
    blocks: int
    groups: int
    sends: int
    issues: tuple[Issue, ...]
    old_format: bool = False
    unsupported: dict[str, int] = field(default_factory=dict)  # R's missing rules, by reason

    @property
    def ok(self) -> bool:
        return not self.issues


def check_block(elf: ELFFile, block: Block, unsupported: dict[str, int] | None = None) -> list[Issue]:
    """The issues of a framed block: its send lines, then the pairing of its values, then, when
    unsupported is given, each instruction against R (counting R's missing rules there)."""
    try:
        insns = decode(code_at(elf, block.address, block.size), block.address)
    except ValueError as error:
        return [Issue(block.address, None, str(error))]
    issues = [Issue(block.address, offset, message) for offset, message in check_sends(block, insns)]
    try:
        pair_sends(block, [register_writes(insn) for insn in insns])
    except PairingError as error:
        issues.append(Issue(error.address, error.offset, error.message))
    if unsupported is not None:
        comparison = compare_block(block, insns)
        issues += [Issue(block.address, offset, f"R: {message}") for offset, message in comparison.mismatches]
        for _, message in comparison.unsupported:
            reason = message.split(": ", 1)[1]
            reason = (
                "operands outside the general registers (FP/SIMD)"
                if "general register" in reason
                else message
            )
            unsupported[reason] = unsupported.get(reason, 0) + 1
    return issues


def check_elf(elf: ELFFile, *, against_r: bool = False) -> Report:
    table_section = elf.get_section_by_name(BLOCK_TABLE_SECTION)
    annotation_section = elf.get_section_by_name(ANNOTATION_SECTION)
    if table_section is None or annotation_section is None:
        msg = f"no {BLOCK_TABLE_SECTION} or {ANNOTATION_SECTION} section: not built with the HBNG compiler"
        raise ValueError(msg)
    table = block_table(table_section.data())
    texts = block_texts(table, annotation_section.data(), annotation_section["sh_addr"])

    groups = sends = 0
    issues: list[Issue] = []
    unsupported: dict[str, int] | None = {} if against_r else None
    for address, text in texts:
        try:
            block = read_block(text, address)
        except OldFormatError as error:
            return Report(len(texts), 0, 0, (Issue(error.address, None, error.message),), old_format=True)
        except FramingError as error:
            issues.append(Issue(error.address, error.offset, error.message))
            continue
        groups += len(block.groups)
        sends += sum(len(group.form.sends) for group in block.groups)
        issues += check_block(elf, block, unsupported)
    return Report(len(texts), groups, sends, tuple(issues), unsupported=unsupported or {})
