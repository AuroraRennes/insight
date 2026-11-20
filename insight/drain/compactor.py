"""The compactor: ETMv4 packets of one core, traced with branch broadcast, into drain events."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from insight.drain.events import OUTSIDE, Error, Event, Kind
from insight.model.packet_parser import PacketParser
from insight.model.packets import (
    ETMAddressPacket,
    ETMAtomPacket,
    ETMExceptionPacket,
    ETMSynchronizationPacket,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

    from insight.model.packets import Packet

# ETMv4 exception types, by the name OpenCSD prints.
EXCEPTION_TYPES = {
    "PE Reset": 0x0,
    "Debug Halt": 0x1,
    "Call": 0x2,
    "Trap": 0x3,
    "System Error": 0x4,
    "Inst Debug": 0x6,
    "Data Debug": 0x7,
    "Alignment": 0xA,
    "Inst Fault": 0xB,
    "Data Fault": 0xC,
    "IRQ": 0xE,
    "FIQ": 0xF,
}


class Where(Enum):
    UNKNOWN = "unknown"
    INSIDE = "inside"
    OUTSIDE = "outside"


@dataclass
class Compactor:
    """Atoms are kept while the last address is in [low, high); addresses go out minus base."""

    low: int
    high: int
    base: int = 0
    where: Where = Where.UNKNOWN
    pending: list[str] | None = None  # atoms ending in E, waiting for the target
    exception: int | None = None  # an exception type, waiting for its address
    stats: Counter[str] = field(default_factory=Counter)

    def inside(self, address: int) -> bool:
        return self.low <= address < self.high

    def target(self, address: int) -> int | Event:
        """The 32-bit address, OUTSIDE, or an error when it does not fit."""
        if not self.inside(address):
            return OUTSIDE
        offset = address - self.base
        if not 0 <= offset < OUTSIDE:
            return Event(Kind.ERROR, Error.WIDE)
        return offset

    def feed(self, packet: Packet) -> list[Event]:
        self.stats["packets"] += 1
        if isinstance(packet, ETMAtomPacket):
            return self.atoms(packet.elements)
        if isinstance(packet, ETMAddressPacket):
            return self.address(packet.address)
        if isinstance(packet, ETMExceptionPacket):
            if packet.name.endswith("Overflow"):
                return self.lose(Event(Kind.OVERFLOW))
            # A pending E keeps waiting: the exception's address is also the branch target.
            name = packet.description.strip()
            if name not in EXCEPTION_TYPES:
                msg = f"exception {name!r} has no ETMv4 type"
                raise ValueError(msg)
            self.exception = EXCEPTION_TYPES[name]
            return []
        if isinstance(packet, ETMSynchronizationPacket) and packet.name.endswith("Trace On"):
            return self.unresolved()
        return []

    def finish(self) -> list[Event]:
        return self.unresolved()

    def unresolved(self) -> list[Event]:
        """An E atom that got no address."""
        if self.pending is None:
            return []
        return self.lose(Event(Kind.ERROR, Error.NO_TARGET))

    def lose(self, event: Event) -> list[Event]:
        self.pending = None
        self.exception = None
        self.where = Where.UNKNOWN
        return [event]

    def atoms(self, elements: list[str]) -> list[Event]:
        events = self.unresolved()
        if self.where is not Where.INSIDE:
            self.stats["atoms dropped"] += len(elements)
            return events
        self.stats["atoms"] += len(elements)
        if "E" in elements[:-1]:
            return events + self.lose(Event(Kind.ERROR, Error.E_NOT_LAST))
        if elements[-1] == "E":
            self.pending = elements
            return events
        return [*events, Event.atoms(elements)]

    def address(self, address: int) -> list[Event]:
        target = self.target(address)
        if isinstance(target, Event):
            return self.lose(target)
        events: list[Event] = []
        if self.pending is not None:
            events.append(Event.atoms(self.pending, target))
            self.pending = None
        if self.exception is not None:
            # The address execution resumes at; the kernel runs next.
            if target != OUTSIDE:
                events.append(Event(Kind.EXCEPTION, self.exception, 0, target))
            self.exception = None
            self.where = Where.OUTSIDE
            return events
        now = Where.OUTSIDE if target == OUTSIDE else Where.INSIDE
        if not events and (now is Where.INSIDE or self.where is Where.INSIDE):
            # Not after a branch: entering the range, a sync, or leaving the range without a branch.
            events.append(Event(Kind.BRANCH, 0, 0, target))
        self.where = now
        return events

    def run(self, packets: Iterable[Packet]) -> Iterator[Event]:
        for packet in packets:
            for event in self.feed(packet):
                self.stats[event.kind.name] += 1
                yield event
        for event in self.finish():
            self.stats[event.kind.name] += 1
            yield event


def listing_packets(path: Path, trace_id: int) -> Iterator[Packet]:
    """The packets of one trace source in a trc_pkt_lister listing."""
    prefix = f"ID:{trace_id:x};"
    parser = PacketParser()
    with path.open(errors="replace") as listing:
        for line in listing:
            if line.startswith(prefix) or (line.startswith("Idx:") and f" {prefix}" in line):
                yield parser.parse_packet(line)


def write_events(events: Iterable[Event], output: Path, *, hex_lines: bool) -> int:
    """Little-endian 64-bit words, or one hex word per line for a testbench."""
    words = [event.encode() for event in events]
    if hex_lines:
        output.write_text("".join(f"{word:016x}\n" for word in words))
    else:
        output.write_bytes(b"".join(word.to_bytes(8, "little") for word in words))
    return len(words)
