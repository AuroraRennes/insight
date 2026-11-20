"""The framing of the annotation section: each block's '@<offset>' groups, closed by END."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from itertools import pairwise
from typing import TYPE_CHECKING

from insight.dsl.errors import DslSyntaxError
from insight.dsl.syntax import parse

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile

    from insight.dsl.transfer import Transfer

ANNOTATION_SECTION = ".hbngannot"
BLOCK_TABLE_SECTION = ".hbngbbt"
INDEX_SECTION = ".hbngidx"
INFO_SECTION = ".hbnginfo"
FORMAT_VERSION = 1  # of the table, its index and the annotations, in .hbnginfo
INSTRUCTION_SIZE = 4
HEADER_SIZE = 12  # of a block table entry, before its sends
ENTRY_ALIGN = 4
WAYPOINT_BIT = 0x8000  # in the instruction count: the block ends in a branch, call, return or isb
INDEX_RECORD = struct.Struct("<II")  # block address, offset of its entry in the table

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
    count: int = 1  # the instructions it describes, from offset on
    send_at: tuple[int, ...] = ()  # the offset of each send's instruction


@dataclass(frozen=True)
class Block:
    """Its groups: one per instruction, or block forms, each describing the instructions up to the
    next group, its <Xn> already paired (S<i>)."""

    address: int
    groups: tuple[Group, ...]

    @property
    def size(self) -> int:
        return INSTRUCTION_SIZE * sum(group.count for group in self.groups)

    @property
    def block_forms(self) -> bool:
        return any(group.count > 1 for group in self.groups)


@dataclass(frozen=True)
class Entry:
    """A block's entry in the table: its address, its text's, its instructions, the index of the
    instruction of each send (an stp's twice), and whether its last instruction is a waypoint."""

    address: int
    annotation: int
    count: int
    sends: tuple[int, ...]
    waypoint: bool = False

    @property
    def end(self) -> int:
        return self.address + INSTRUCTION_SIZE * self.count


# One block
# \__________


def split_groups(text: str, address: int) -> list[tuple[int, list[tuple[int, str]]]]:
    """The groups of one block's text: (offset, [(line number, line)]), with increasing offsets."""
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
            if groups and (offset <= groups[-1][0] or offset % INSTRUCTION_SIZE):
                msg = f"line {lineno}: group @{offset} after @{groups[-1][0]}"
                raise FramingError(msg, address)
            groups.append((offset, []))
        else:
            groups[-1][1].append((lineno, line))
    msg = "no END"
    raise FramingError(msg, address)


def read_block(text: str, address: int, entry: Entry | None = None) -> Block:
    """One block's text, framed and each group parsed. The entry gives the block's instructions and
    sends; without one, there is a group per instruction and each send is its group's."""
    framed = split_groups(text, address)
    offsets = [offset for offset, _ in framed]
    size = INSTRUCTION_SIZE * (len(framed) if entry is None else entry.count)
    if entry is None:
        for k, offset in enumerate(offsets):
            if offset != INSTRUCTION_SIZE * k:
                msg = f"group @{offset} where @{INSTRUCTION_SIZE * k} was expected"
                raise FramingError(msg, address)
    if offsets[-1] >= size:
        msg = f"group @{offsets[-1]} past the block's {size // INSTRUCTION_SIZE} instructions"
        raise FramingError(msg, address)
    groups: list[Group] = []
    for (offset, lines), end in zip(framed, [*offsets[1:], size], strict=True):
        try:
            form = parse("\n".join(line for _, line in lines))
        except DslSyntaxError as error:
            raise FramingError(str(error), address, offset) from error
        if entry is None:
            send_at = (offset,) * len(form.sends)
        else:
            send_at = tuple(INSTRUCTION_SIZE * k for k in entry.sends if offset <= INSTRUCTION_SIZE * k < end)
            if len(send_at) != len(form.sends):
                msg = f"{len(form.sends)} send lines, the block table lists {len(send_at)} sends here"
                raise FramingError(msg, address, offset)
        groups.append(Group(offset, form, (end - offset) // INSTRUCTION_SIZE, send_at))
    return Block(address, tuple(groups))


# The sections
# \_____________


def block_table(data: bytes) -> list[Entry]:
    """The entries, in table order."""
    return [entry for _, entry in table_entries(data)]


def table_entries(data: bytes) -> list[tuple[int, Entry]]:
    """Each entry with its offset in the table. An entry is 4-aligned: block and annotation
    addresses (32 bits), the number of instructions with the waypoint bit and the number of sends
    (16 bits), then each send's instruction index (16 bits)."""
    entries: list[tuple[int, Entry]] = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < HEADER_SIZE:
            msg = f"block table entry at {pos} truncated: an old table? rebuild"
            raise ValueError(msg)
        address, annotation, raw_count, sends = struct.unpack_from("<IIHH", data, pos)
        count = raw_count & ~WAYPOINT_BIT
        end = pos + HEADER_SIZE + 2 * sends
        if not count or sends > 2 * count or end > len(data):
            msg = f"block table entry at {pos}: {count} instructions, {sends} sends: an old table? rebuild"
            raise ValueError(msg)
        indices = struct.unpack_from(f"<{sends}H", data, pos + HEADER_SIZE)
        if any(index >= count for index in indices):
            msg = f"block table entry at {pos}: a send past the block's {count} instructions"
            raise ValueError(msg)
        entries.append((pos, Entry(address, annotation, count, indices, bool(raw_count & WAYPOINT_BIT))))
        pos = (end + ENTRY_ALIGN - 1) & ~(ENTRY_ALIGN - 1)
    return entries


def format_version(elf: ELFFile) -> None:
    """Refuses an executable whose table is not in the format InSight reads."""
    info = elf.get_section_by_name(INFO_SECTION)
    if info is None:
        msg = f"no {INFO_SECTION}: an old table? rebuild (the link runs llvm-hbng-postlink)"
        raise ValueError(msg)
    data = info.data()
    if len(data) != 2:
        msg = f"{INFO_SECTION} of {len(data)} bytes, not a 16-bit version"
        raise ValueError(msg)
    (version,) = struct.unpack("<H", data)
    if version != FORMAT_VERSION:
        msg = f"table format version {version}, InSight reads version {FORMAT_VERSION}"
        raise ValueError(msg)


def table_issues(data: bytes, index: bytes | None) -> list[tuple[int, str]]:
    """(address, message) for each way the table is not sorted, or its index does not list each
    entry in order with its offset."""
    entries = table_entries(data)
    issues: list[tuple[int, str]] = []
    for (_, entry), (_, after) in pairwise(entries):
        if after.address < entry.end:
            issues.append((after.address, f"entry after {entry.address:#x}: not sorted, or overlapping"))
    if index is None:
        issues.append((0, f"no {INDEX_SECTION}"))
        return issues
    if len(index) != INDEX_RECORD.size * len(entries):
        msg = f"{INDEX_SECTION} of {len(index)} bytes for {len(entries)} entries"
        issues.append((0, msg))
        return issues
    for k, (offset, entry) in enumerate(entries):
        address, at = INDEX_RECORD.unpack_from(index, INDEX_RECORD.size * k)
        if (address, at) != (entry.address, offset):
            msg = f"{INDEX_SECTION} record {k} is ({address:#x}, {at}), the entry at {offset} is this block"
            issues.append((entry.address, msg))
    return issues


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
    format_version(elf)
    table = block_table(table_section.data())
    texts = block_texts(table, annotation_section.data(), annotation_section["sh_addr"])
    return {entry.address: (entry, text) for entry, text in texts}
