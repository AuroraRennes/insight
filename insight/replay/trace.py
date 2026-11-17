"""Reading flowsight-qemu's trace: the input stream (what the coprocessor would receive) and the
audit stream (what QEMU actually did), in program order. The file is zstd-compressed; it is read
through the zstd command.
"""

from __future__ import annotations

import struct
import subprocess
from collections import deque
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

# Header: the magic, a u32 version, a u32 0, then the address and size of the channel page (u64
# each): the stores there are the sends.
MAGIC = b"FSTRACE\0"
VERSION = 1
HEADER = struct.Struct("<8sIIQQ")
CHUNK = 1 << 20

# Records: a type byte, then the fields, little-endian with no padding.
#   Input stream, what the coprocessor would receive:
#     B  u64 pc, u32 n                a block entered: the n instructions from pc
#     S  u64 value                    a send, in channel order
#     Y  i64 num                      a syscall entered: KSight's events for it follow
#     L  u64 addr, u64 len, u8 tag    label a range with tag (0: fresh or overwritten memory)
#     C  u64 addr, u64 len, u64 fd    check a range before an output syscall to fd
#     M  u64 dst, u64 src, u64 len    move the tags of a range (mremap)
#     G  u64 handler, restorer, sp, fp  a signal delivered: the handler's block follows, entered
#                                       with this SP and FP
#   Audit stream, what QEMU actually did:
#     R  u64 sp, u64 fp               SP and FP at each B, before its first instruction
#     A  u64 pc, u64 addr, u8 size, u8 store  a memory access other than a send
# Keyed by the type byte's value, as the parser reads it.
FORMATS: dict[int, struct.Struct] = {
    ord("B"): struct.Struct("<QI"),
    ord("S"): struct.Struct("<Q"),
    ord("Y"): struct.Struct("<q"),
    ord("L"): struct.Struct("<QQB"),
    ord("C"): struct.Struct("<QQQ"),
    ord("M"): struct.Struct("<QQQ"),
    ord("G"): struct.Struct("<QQQQ"),
    ord("R"): struct.Struct("<QQ"),
    ord("A"): struct.Struct("<QQBB"),
}


class TraceError(Exception):
    pass


@dataclass(frozen=True)
class Header:
    chan: int
    chan_size: int


Record = tuple  # (type letter, field...), e.g. ("B", pc, n)


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER.size:
        msg = "truncated header"
        raise TraceError(msg)
    magic, version, _, chan, size = HEADER.unpack_from(data)
    if magic != MAGIC:
        msg = "not a FlowSight trace"
        raise TraceError(msg)
    if version != VERSION:
        msg = f"trace version {version}, expected {VERSION}"
        raise TraceError(msg)
    return Header(chan, size)


def parse_records(chunks: Iterable[bytes]) -> Iterator[Record]:
    """The records of a stream of bytes cut anywhere. A record cut by the end is dropped (a
    killed process leaves a prefix)."""
    # By type byte: the letter, the unpacker and the record's size with its type byte
    kinds = {code: (chr(code), fmt.unpack_from, 1 + fmt.size) for code, fmt in FORMATS.items()}
    rest = b""
    for chunk in chunks:
        data = rest + chunk
        pos, end = 0, len(data)
        while pos < end:
            kind = kinds.get(data[pos])
            if kind is None:
                msg = f"unknown record type {data[pos]:#x}"
                raise TraceError(msg)
            letter, unpack, size = kind
            if pos + size > end:
                break
            yield (letter, *unpack(data, pos + 1))
            pos += size
        rest = data[pos:]


def _chunks(stream: IO[bytes], first: bytes) -> Iterator[bytes]:
    if first:
        yield first
    while chunk := stream.read(CHUNK):
        yield chunk


class TraceFile:
    """A trace on disk: its header and its records, decompressed on the fly."""

    def __init__(self, path: Path) -> None:
        self.process = subprocess.Popen(["zstd", "-dcq", "--", str(path)], stdout=subprocess.PIPE)  # noqa: S603, S607
        if self.process.stdout is None:
            msg = "no pipe from zstd"
            raise TraceError(msg)
        self.stdout = self.process.stdout
        data = self.stdout.read(CHUNK)
        self.header = parse_header(data)
        self.records = parse_records(_chunks(self.stdout, data[HEADER.size :]))

    def close(self) -> None:
        self.stdout.close()
        self.process.wait()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


NOT_PEEKED = ("",)  # Stream.head when no record is held


class Stream:
    """The records in order, with look-ahead for sends: next_send() takes the next send further
    on, keeping the records it passes for next(). peek() holds the next record in head, so that
    looking and then taking costs one read."""

    def __init__(self, records: Iterable[Record]) -> None:
        self.records = iter(records)
        self.pending: deque[Record] = deque()
        self.sends: deque[int] = deque()  # sends seen in passing, not yet taken
        self.head: Record | None = NOT_PEEKED  # the record peek() returned, None at the end

    def fetch(self) -> Record | None:
        pending, sends = self.pending, self.sends
        while True:
            record = pending.popleft() if pending else next(self.records, None)
            if record is None or record[0] != "S":
                return record
            sends.append(record[1])

    def next(self) -> Record | None:
        """The next record other than a send (sends go to next_send's queue)."""
        record = self.head
        if record is NOT_PEEKED:
            return self.fetch()
        self.head = NOT_PEEKED
        return record

    def peek(self) -> Record | None:
        if self.head is NOT_PEEKED:
            self.head = self.fetch()
        return self.head

    def next_send(self) -> int | None:
        """The next send value in channel order, None at the end of the trace."""
        if self.sends:
            return self.sends.popleft()
        while True:
            record = next(self.records, None)
            if record is None:
                return None
            if record[0] == "S":
                return int(record[1])
            self.pending.append(record)
