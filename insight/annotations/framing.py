"""The framing of the annotation section: each block's '@<offset>' groups, closed by END.

The block table (.hbngbbt) locates each block's text in .hbngannot, and gives its instructions
and the instruction of each send: one group per instruction, in order, empty groups included,
each holding one DSL transfer. A block not starting with '@0' is in the old format.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from insight.dsl.errors import DslSyntaxError
from insight.dsl.syntax import parse

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile

    from insight.dsl.transfer import Transfer

ANNOTATION_SECTION = ".hbngannot"
BLOCK_TABLE_SECTION = ".hbngbbt"
INSTRUCTION_SIZE = 4
HEADER_SIZE = 20  # of a block table entry, before its sends

GROUP_RE = re.compile(r"@(0|[1-9][0-9]*)")


class FramingError(Exception):
    def __init__(self, message: str, address: int, offset: int | None = None) -> None:
        where = f"block {address:#x}" if offset is None else f"block {address:#x} @{offset}"
        super().__init__(f"{where}: {message}")
        self.message = message
        self.address = address
        self.offset = offset


class OldFormatError(FramingError):
    """A block in the annotation format from before the DSL."""


@dataclass(frozen=True)
class Group:
    offset: int
    form: Transfer


@dataclass(frozen=True)
class Block:
    address: int
    groups: tuple[Group, ...]

    @property
    def size(self) -> int:
        return INSTRUCTION_SIZE * len(self.groups)


@dataclass(frozen=True)
class Entry:
    """A block's entry in the table: its address, its text's, its instructions, and the index of
    the instruction of each send (an stp's twice)."""

    address: int
    annotation: int
    count: int
    sends: tuple[int, ...]


# One block
# \__________


def split_groups(text: str, address: int) -> list[tuple[int, list[tuple[int, str]]]]:
    """The groups of one block's text: (offset, [(line number, line)]), checked for framing."""
    lines = [(lineno, raw.split("#", 1)[0].strip()) for lineno, raw in enumerate(text.splitlines(), 1)]
    lines = [(lineno, line) for lineno, line in lines if line]
    if not lines or lines[0][1] != "@0":
        first = lines[0][1] if lines else "nothing"
        if first.startswith("@"):
            msg = f"the first group is {first}, not @0"
            raise FramingError(msg, address)
        msg = f"starts with {first!r}, not @0: old annotation format, rebuild with hbng-23.x at the new pin"
        raise OldFormatError(msg, address)

    groups: list[tuple[int, list[tuple[int, str]]]] = []
    for index, (lineno, line) in enumerate(lines):
        if line == "END":
            if index != len(lines) - 1:
                msg = f"line {lines[index + 1][0]} after END"
                raise FramingError(msg, address)
            return groups
        if match := GROUP_RE.fullmatch(line):
            offset = int(match.group(1))
            expected = INSTRUCTION_SIZE * len(groups)
            if offset != expected:
                msg = f"line {lineno}: group @{offset} where @{expected} was expected"
                raise FramingError(msg, address)
            groups.append((offset, []))
        else:
            groups[-1][1].append((lineno, line))
    msg = "no END"
    raise FramingError(msg, address)


def read_block(text: str, address: int, entry: Entry | None = None) -> Block:
    """One block's text, framed and each group parsed; its table entry, when given, must list as
    many instructions, and each group's sends."""
    framed = split_groups(text, address)
    if entry is not None and entry.count != len(framed):
        msg = f"{len(framed)} groups, the block table gives {entry.count} instructions"
        raise FramingError(msg, address)
    groups: list[Group] = []
    for k, (offset, lines) in enumerate(framed):
        try:
            form = parse("\n".join(line for _, line in lines))
        except DslSyntaxError as error:
            raise FramingError(str(error), address, offset) from error
        if entry is not None and len(form.sends) != entry.sends.count(k):
            msg = f"{len(form.sends)} send lines, the block table lists {entry.sends.count(k)} sends here"
            raise FramingError(msg, address, offset)
        groups.append(Group(offset, form))
    return Block(address, tuple(groups))


# The sections
# \_____________


def block_table(data: bytes) -> list[Entry]:
    """The entries, each 8-aligned: block and annotation addresses (64 bits), the number of
    instructions and of sends (16 bits), then each send's instruction index (16 bits)."""
    entries: list[Entry] = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < HEADER_SIZE:
            msg = f"block table entry at {pos} truncated: an old table? rebuild"
            raise ValueError(msg)
        address, annotation, count, sends = struct.unpack_from("<QQHH", data, pos)
        end = pos + HEADER_SIZE + 2 * sends
        if not count or sends > 2 * count or end > len(data):
            msg = f"block table entry at {pos}: {count} instructions, {sends} sends: an old table? rebuild"
            raise ValueError(msg)
        indices = struct.unpack_from(f"<{sends}H", data, pos + HEADER_SIZE)
        if any(index >= count for index in indices):
            msg = f"block table entry at {pos}: a send past the block's {count} instructions"
            raise ValueError(msg)
        entries.append(Entry(address, annotation, count, indices))
        pos = (end + 7) & ~7
    return entries


def block_texts(table: list[Entry], annotations: bytes, base: int) -> list[tuple[Entry, str]]:
    """Each entry with its text, which runs to the next one's in the section."""
    starts = sorted({entry.annotation for entry in table})
    ends = dict(zip(starts, [*starts[1:], base + len(annotations)], strict=True))
    texts: list[tuple[Entry, str]] = []
    for entry in table:
        if not base <= entry.annotation < base + len(annotations):
            msg = f"annotations at {entry.annotation:#x}, outside {ANNOTATION_SECTION}"
            raise FramingError(msg, entry.address)
        chunk = annotations[entry.annotation - base : ends[entry.annotation] - base]
        texts.append((entry, chunk.decode("ascii")))
    return texts


def read_blocks(elf: ELFFile) -> list[Block]:
    """Every annotated block of an executable."""
    return [read_block(text, address, entry) for address, (entry, text) in annotation_texts(elf).items()]


def annotation_texts(elf: ELFFile) -> dict[int, tuple[Entry, str]]:
    """Every annotated block's entry and text, by address, not parsed yet."""
    table_section = elf.get_section_by_name(BLOCK_TABLE_SECTION)
    annotation_section = elf.get_section_by_name(ANNOTATION_SECTION)
    if table_section is None or annotation_section is None:
        msg = f"no {BLOCK_TABLE_SECTION} or {ANNOTATION_SECTION} section: not built with the HBNG compiler"
        raise ValueError(msg)
    table = block_table(table_section.data())
    texts = block_texts(table, annotation_section.data(), annotation_section["sh_addr"])
    return {entry.address: (entry, text) for entry, text in texts}
