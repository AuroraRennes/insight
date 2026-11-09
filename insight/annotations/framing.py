"""The framing of the annotation section: each block's '@<offset>' groups, closed by END.

The block table (.hbngbbt) locates each block's text in .hbngannot: one group per instruction, in
order, empty groups included, each holding one DSL transfer. A block not starting with '@0' is in
the old format.
"""

from __future__ import annotations

import re
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

GROUP_RE = re.compile(r"@(0|[1-9][0-9]*)")


class FramingError(Exception):
    def __init__(self, message: str, address: int, offset: int | None = None) -> None:
        where = f"block {address:#x}" if offset is None else f"block {address:#x} @{offset}"
        super().__init__(f"{where}: {message}")
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


def read_block(text: str, address: int) -> Block:
    """One block's text, framed and each group parsed."""
    groups: list[Group] = []
    for offset, lines in split_groups(text, address):
        try:
            form = parse("\n".join(line for _, line in lines))
        except DslSyntaxError as error:
            raise FramingError(str(error), address, offset) from error
        groups.append(Group(offset, form))
    return Block(address, tuple(groups))


# The sections
# \_____________


def block_table(data: bytes) -> list[tuple[int, int]]:
    """(block address, annotation address) pairs: two little-endian 64-bit words each."""
    entry = 16
    if len(data) % entry:
        msg = f"block table of {len(data)} bytes, not a multiple of {entry}"
        raise ValueError(msg)
    return [
        (int.from_bytes(data[i : i + 8], "little"), int.from_bytes(data[i + 8 : i + 16], "little"))
        for i in range(0, len(data), entry)
    ]


def block_texts(table: list[tuple[int, int]], annotations: bytes, base: int) -> list[tuple[int, str]]:
    """(block address, text): each block's text runs to the next one's in the section."""
    starts = sorted({annotation for _, annotation in table})
    ends = dict(zip(starts, [*starts[1:], base + len(annotations)], strict=True))
    texts: list[tuple[int, str]] = []
    for address, annotation in table:
        if not base <= annotation < base + len(annotations):
            msg = f"annotations at {annotation:#x}, outside {ANNOTATION_SECTION}"
            raise FramingError(msg, address)
        chunk = annotations[annotation - base : ends[annotation] - base]
        texts.append((address, chunk.decode("ascii")))
    return texts


def read_blocks(elf: ELFFile) -> list[Block]:
    """Every annotated block of an executable."""
    table_section = elf.get_section_by_name(BLOCK_TABLE_SECTION)
    annotation_section = elf.get_section_by_name(ANNOTATION_SECTION)
    if table_section is None or annotation_section is None:
        msg = f"no {BLOCK_TABLE_SECTION} or {ANNOTATION_SECTION} section: not built with the HBNG compiler"
        raise ValueError(msg)
    table = block_table(table_section.data())
    texts = block_texts(table, annotation_section.data(), annotation_section["sh_addr"])
    return [read_block(text, address) for address, text in texts]
