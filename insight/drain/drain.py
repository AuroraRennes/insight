"""The drain: walks the compactor's events through the block table and takes each block's sends."""

from __future__ import annotations

import bisect
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from insight.annotations.framing import (
    BLOCK_TABLE_SECTION,
    INDEX_RECORD,
    INDEX_SECTION,
    INSTRUCTION_SIZE,
    format_version,
    table_entries,
)
from insight.drain.events import OUTSIDE, Event, Kind

if TYPE_CHECKING:
    from collections.abc import Iterable

    from elftools.elf.elffile import ELFFile

    from insight.annotations.framing import Entry

SKIP_SECTION = ".hbngskip"
SKIP_RECORD = struct.Struct("<II")
CACHE_SIZES = (16, 64, 256, 1024)


class DrainError(Exception):
    pass


class Table:
    """The block table as the drain sees it: entries in address order, the index, the untracked ranges."""

    def __init__(
        self, entries: list[Entry], index: list[tuple[int, int]], skips: list[tuple[int, int]]
    ) -> None:
        self.entries = entries
        self.index_addresses = [address for address, _ in index]  # sorted
        self.index_entries = [k for _, k in index]
        self.skips = sorted(skips)

    @staticmethod
    def from_elf(elf: ELFFile) -> Table:
        table = elf.get_section_by_name(BLOCK_TABLE_SECTION)
        index = elf.get_section_by_name(INDEX_SECTION)
        if table is None or index is None:
            msg = f"no {BLOCK_TABLE_SECTION} or {INDEX_SECTION}: not a post-linked HBNG executable"
            raise DrainError(msg)
        format_version(elf)
        entries = table_entries(table.data())
        position = {offset: k for k, (offset, _) in enumerate(entries)}
        data = index.data()
        records = [INDEX_RECORD.unpack_from(data, i) for i in range(0, len(data), INDEX_RECORD.size)]
        skip = elf.get_section_by_name(SKIP_SECTION)
        skips = skip.data() if skip is not None else b""
        return Table(
            [entry for _, entry in entries],
            [(address, position[offset]) for address, offset in records],
            [SKIP_RECORD.unpack_from(skips, i) for i in range(0, len(skips), SKIP_RECORD.size)],
        )

    def lookup(self, address: int) -> int | None:
        """The entry starting at address, found through the index."""
        i = bisect.bisect_left(self.index_addresses, address)
        if i < len(self.index_addresses) and self.index_addresses[i] == address:
            return self.index_entries[i]
        return None

    def skipped(self, address: int) -> bool:
        i = bisect.bisect_right(self.skips, (address, OUTSIDE)) - 1
        return i >= 0 and self.skips[i][0] <= address < self.skips[i][1]


@dataclass
class Position:
    """An entry and the next of its instructions to run, or untracked code (entry None) at address."""

    entry: int | None
    offset: int = 0
    address: int = 0


@dataclass
class Drain:
    table: Table
    where: Position | None = None  # None: unknown
    resume: tuple[int, Position | None] | None = None  # after an exception: its address and where that is
    interrupted: list[tuple[int, Position | None]] = field(default_factory=list)  # signal handlers running
    visits: list[int] = field(default_factory=list)  # each entry run from its start, by address
    sends: list[int] = field(default_factory=list)  # the address of each send taken, an stp's twice
    reports: list[str] = field(default_factory=list)
    stats: Counter[str] = field(default_factory=Counter)
    caches: dict[int, list[int]] = field(default_factory=lambda: {size: [-1] * size for size in CACHE_SIZES})

    # Moving through the table
    # \________________________

    def enter(self, k: int) -> Position:
        self.visits.append(self.table.entries[k].address)
        return Position(k, 0)

    def run_to(self, k: int, position: Position, end: int) -> None:
        """Runs entry k's instructions from position up to end (exclusive), taking their sends."""
        entry = self.table.entries[k]
        for index in entry.sends:
            if position.offset <= index < end:
                self.sends.append(entry.address + INSTRUCTION_SIZE * index)
        self.stats["sends"] += sum(position.offset <= index < end for index in entry.sends)
        position.offset = end

    def next_entry(self, k: int) -> Position | None:
        """The entry after k, which the post-link step guarantees follows a block that can continue."""
        if k + 1 >= len(self.table.entries):
            self.report(f"execution continues after the last entry, {self.table.entries[k].address:#x}")
            return None
        return self.enter(k + 1)

    def to_waypoint(self, position: Position) -> Position | None:
        """Runs the blocks without a waypoint, which take no atom, up to the next block that has one."""
        while (k := position.entry) is not None and not self.table.entries[k].waypoint:
            self.run_to(k, position, self.table.entries[k].count)
            moved = self.next_entry(k)
            if moved is None:
                return None
            position = moved
        return position

    def go(self, target: int) -> Position | None:
        """A taken branch or a return from the kernel to target."""
        self.stats["lookups"] += 1
        for size, cache in self.caches.items():
            line = (target >> 2) % size
            if cache[line] == target:
                self.stats[f"hits {size}"] += 1
            cache[line] = target
        if target == OUTSIDE:
            self.report("a branch leaves the traced code")
            return None
        k = self.table.lookup(target)
        if k is not None:
            return self.enter(k)
        if self.table.skipped(target):
            self.stats["untracked entries"] += 1
            return Position(None, 0, target)
        self.report(f"a branch to {target:#x}, neither the start of a block nor untracked code")
        return None

    def report(self, message: str) -> None:
        self.reports.append(message)

    # Events
    # \_______

    def atom(self, element: str, target: int | None) -> None:
        position = self.where
        if position is None or position.entry is None:
            self.stats["atoms untracked"] += 1
            if target is not None:
                self.where = self.go(target)
            return
        position = self.to_waypoint(position)
        if position is None or position.entry is None:
            self.where = position
            return
        k = position.entry
        self.run_to(k, position, self.table.entries[k].count)
        self.stats["blocks with an atom"] += 1
        if element == "N":
            self.where = self.next_entry(k)
        elif target is not None:
            self.where = self.go(target)
        else:
            self.report(f"an E atom without a target after {self.table.entries[k].address:#x}")
            self.where = None

    def exception(self, address: int) -> None:
        """Execution got to address, then left for the kernel."""
        position = self.where
        if position is not None and position.entry is None:
            position = Position(None, 0, address)
        while position is not None and (k := position.entry) is not None:
            entry = self.table.entries[k]
            # At the end of a block without a waypoint, the next one is entered when execution continues
            start = entry.address + INSTRUCTION_SIZE * position.offset
            if start <= address < entry.end or (address == entry.end and not entry.waypoint):
                self.run_to(k, position, (address - entry.address) // INSTRUCTION_SIZE)
                break
            if entry.waypoint:
                self.report(
                    f"an exception at {address:#x}, past the block at {entry.address:#x} without an atom"
                )
                position = None
                break
            self.run_to(k, position, entry.count)
            position = self.next_entry(k)
        self.resume = (address, position)
        self.where = None

    def find(self, address: int) -> Position | None:
        """Where address is, when the drain has no position to check it against."""
        k = self.table.lookup(address)
        if k is not None:
            return self.enter(k)
        return Position(None, 0, address) if self.table.skipped(address) else None

    def reenter(self, address: int) -> None:
        """Execution is at address without a traced branch: back from the kernel, or a sync."""
        if self.interrupted and self.interrupted[-1][0] == address:
            # Back from a signal handler, where the signal interrupted
            _, position = self.interrupted.pop()
            self.where = position if position is not None else self.find(address)
            self.resume = None
            return
        if self.resume is not None:
            resume, position = self.resume
            self.resume = None
            if resume == address:
                self.where = position if position is not None else self.find(address)
                return
            # The kernel went somewhere else: a signal handler, which returns to resume
            self.interrupted.append((resume, position))
            self.stats["signals"] += 1
        self.where = self.go(address)

    def feed(self, event: Event) -> None:
        self.stats["events"] += 1
        if event.kind is Kind.BRANCH and event.count == 0:
            self.reenter(event.address)
        elif event.kind in {Kind.BRANCH, Kind.ATOMS}:
            elements = event.atom_string()
            for i, element in enumerate(elements):
                last = i == len(elements) - 1
                self.atom(element, event.address if last and event.kind is Kind.BRANCH else None)
        elif event.kind is Kind.EXCEPTION:
            self.stats["exceptions"] += 1
            self.exception(event.address)
        else:
            self.stats[f"position lost ({event.kind.name})"] += 1
            self.where = None
            self.resume = None

    def run(self, events: Iterable[Event]) -> None:
        for event in events:
            self.feed(event)


def executed(table: Table, runs: Iterable[tuple[int, int]]) -> tuple[list[int], list[int]]:
    """What the drain should find, from the addresses QEMU ran: each block started, each send."""
    starts = {entry.address for entry in table.entries}
    sends: Counter[int] = Counter()
    for entry in table.entries:
        for index in entry.sends:
            sends[entry.address + INSTRUCTION_SIZE * index] += 1
    visits: list[int] = []
    send_addresses: list[int] = []
    for pc, n in runs:
        for address in range(pc, pc + INSTRUCTION_SIZE * n, INSTRUCTION_SIZE):
            if address in starts:
                visits.append(address)
            if address in sends:
                send_addresses.extend([address] * sends[address])
    return visits, send_addresses
