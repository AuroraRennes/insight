"""Checking every annotated block of an executable: the table, framing, send lines, and pairing.

Each block is read on its own, so one block's issue does not hide another's. A block in the old
format stops the check: the whole executable is then in the old format.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from insight.annotations.against_r import compare_block
from insight.annotations.framing import (
    ANNOTATION_SECTION,
    BLOCK_TABLE_SECTION,
    INDEX_SECTION,
    INSTRUCTION_SIZE,
    FramingError,
    OldFormatError,
    block_table,
    block_texts,
    format_version,
    read_block,
    table_issues,
)
from insight.annotations.pairing import PairingError, code_at, decode, pair_sends, register_writes
from insight.annotations.sendcheck import channel_page, check_sends

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile

    from insight.annotations.framing import Block, Entry


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
    instructions: int = 0  # as many as groups, unless there are block forms
    unsupported: dict[str, int] = field(default_factory=dict)  # R's missing rules, by reason
    jump_table_loads: int = 0  # compared with the jump-table convention instead of R
    page_origins: dict[str, int] = field(default_factory=dict)  # sends whose page is not followed

    @property
    def ok(self) -> bool:
        return not self.issues


@dataclass
class RTally:
    """What the comparison with R counts besides its issues."""

    unsupported: dict[str, int] = field(default_factory=dict)  # R's missing rules, by reason
    jump_table_loads: int = 0


# The instructions the trace emits an atom for: branches, calls, returns and isb.
WAYPOINTS = frozenset(
    (
        *("b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz", "isb", "retaa", "retab"),
        *(f"{op}{key}{zero}" for op in ("br", "blr") for key in "ab" for zero in ("", "z")),
    )
)


def is_waypoint(mnemonic: str) -> bool:
    return mnemonic in WAYPOINTS or mnemonic.startswith(("b.", "bc."))


def waypoint_issue(elf: ELFFile, entry: Entry) -> Issue | None:
    """An issue when the entry's waypoint bit does not match its last instruction."""
    last = entry.end - INSTRUCTION_SIZE
    try:
        (insn,) = decode(code_at(elf, last, INSTRUCTION_SIZE), last)
    except ValueError as error:
        return Issue(entry.address, None, str(error))
    if is_waypoint(insn.mnemonic) == entry.waypoint:
        return None
    bit = "the waypoint bit" if entry.waypoint else "no waypoint bit"
    last_insn = f"{insn.mnemonic} {insn.op_str}".rstrip()
    return Issue(entry.address, None, f"{bit}, but the block ends in {last_insn}")


def check_block(
    elf: ELFFile,
    block: Block,
    page: int,
    tally: RTally | None = None,
    origins: Counter[str] | None = None,
) -> list[Issue]:
    """The issues of a framed block, page being the channel's: its send lines, then the pairing
    of its values, then, when tally is given, each instruction against R (counting R's missing
    rules and the jump-table loads there). origins counts the sends whose page is not followed."""
    try:
        insns = decode(code_at(elf, block.address, block.size), block.address)
    except ValueError as error:
        return [Issue(block.address, None, str(error))]
    sends = check_sends(block, insns, page)
    if origins is not None:
        origins.update(sends.origins)
    issues = [Issue(block.address, offset, message) for offset, message in sends.issues]
    try:
        pair_sends(block, [register_writes(insn) for insn in insns])
    except PairingError as error:
        issues.append(Issue(error.address, error.offset, error.message))
    if tally is not None:
        comparison = compare_block(block, insns, sends.sends)
        tally.jump_table_loads += comparison.jump_table_loads
        issues += [Issue(block.address, offset, f"R: {message}") for offset, message in comparison.mismatches]
        for _, message in comparison.unsupported:
            text, reason = message.split(": ", 1)
            if reason == "FP/SIMD form without a rule":  # by mnemonic: what R lacks
                reason = f"FP/SIMD without a rule: {text.split()[0]}"
            elif "general register" not in reason:
                reason = message
            tally.unsupported[reason] = tally.unsupported.get(reason, 0) + 1
    return issues


def check_elf(elf: ELFFile, *, against_r: bool = False) -> Report:
    table_section = elf.get_section_by_name(BLOCK_TABLE_SECTION)
    annotation_section = elf.get_section_by_name(ANNOTATION_SECTION)
    if table_section is None or annotation_section is None:
        msg = f"no {BLOCK_TABLE_SECTION} or {ANNOTATION_SECTION} section: not built with the HBNG compiler"
        raise ValueError(msg)
    try:
        format_version(elf)
        table = block_table(table_section.data())
    except ValueError as error:
        return Report(0, 0, 0, (Issue(table_section["sh_addr"], None, str(error)),), old_format=True)
    texts = block_texts(table, annotation_section.data(), annotation_section["sh_addr"])
    page: int | None = None  # looked up at the first block in the current format

    groups = sends = instructions = 0
    index = elf.get_section_by_name(INDEX_SECTION)
    issues = [
        Issue(address, None, message)
        for address, message in table_issues(table_section.data(), None if index is None else index.data())
    ]
    tally = RTally() if against_r else None
    origins: Counter[str] = Counter()
    for entry, text in texts:
        try:
            block = read_block(text, entry.address, entry)
        except OldFormatError as error:
            return Report(len(texts), 0, 0, (Issue(error.address, None, error.message),), old_format=True)
        except FramingError as error:
            issues.append(Issue(error.address, error.offset, error.message))
            continue
        if page is None:
            page = channel_page(elf)
        if issue := waypoint_issue(elf, entry):
            issues.append(issue)
        groups += len(block.groups)
        instructions += block.size // INSTRUCTION_SIZE
        sends += sum(len(group.form.sends) for group in block.groups)
        issues += check_block(elf, block, page, tally, origins)
    if tally is None:
        return Report(
            len(texts), groups, sends, tuple(issues), instructions=instructions, page_origins=dict(origins)
        )
    return Report(
        len(texts),
        groups,
        sends,
        tuple(issues),
        instructions=instructions,
        unsupported=tally.unsupported,
        jump_table_loads=tally.jump_table_loads,
        page_origins=dict(origins),
    )
