"""The events the compactor would send for a flowsight-qemu trace, traced with branch broadcast."""

from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from insight.drain.events import MAX_ATOMS, Event, Kind

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from elftools.elf.elffile import ELFFile

    from insight.replay.trace import Record

INSTRUCTION = 4
CALL = 0x2  # the ETMv4 exception type of an svc


class SynthError(Exception):
    pass


def classify(word: int) -> str:
    """'cond' for a branch that may fall through, 'branch' for one always taken, 'isb', 'svc' or ''."""
    if (word & 0xFF000010) == 0x54000000 or (word & 0x7C000000) == 0x34000000:  # b.cond, cbz/cbnz, tbz/tbnz
        return "cond"
    if (word & 0x7C000000) == 0x14000000 or (word & 0xFE000000) == 0xD6000000:  # b, bl, br, blr, ret
        return "branch"
    if (word & 0xFFFFF0FF) == 0xD50330DF:
        return "isb"
    if (word & 0xFFE0001F) == 0xD4000001:
        return "svc"
    return ""


class Code:
    """The instruction words of an executable's code, and where its waypoints and svcs are."""

    def __init__(self, segments: list[tuple[int, bytes]]) -> None:
        self.segments = segments
        # Every address whose instruction is a branch, an isb or an svc: these end a QEMU block
        self.special = sorted(
            base + i
            for base, data in self.segments
            for i in range(0, len(data) - 3, INSTRUCTION)
            if classify(int.from_bytes(data[i : i + 4], "little"))
        )

    @staticmethod
    def from_elf(elf: ELFFile) -> Code:
        return Code(
            [
                (segment["p_vaddr"], segment.data())
                for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1
            ]
        )

    def word(self, address: int) -> int:
        for base, data in self.segments:
            if base <= address < base + len(data):
                return int.from_bytes(data[address - base : address - base + 4], "little")
        msg = f"{address:#x} is not in the code"
        raise SynthError(msg)

    def special_inside(self, start: int, end: int) -> bool:
        i = bisect.bisect_left(self.special, start)
        return i < len(self.special) and self.special[i] < end


@dataclass
class Synth:
    code: Code
    events: list[Event] = field(default_factory=list)
    atoms: list[str] = field(default_factory=list)  # N atoms not sent yet
    stats: Counter[str] = field(default_factory=Counter)

    def flush(self) -> None:
        if self.atoms:
            self.events.append(Event.atoms(self.atoms))
            self.atoms = []

    def atom(self, element: str, target: int | None = None) -> None:
        self.stats["atoms"] += 1
        if element == "N":
            self.atoms.append("N")
            if len(self.atoms) == MAX_ATOMS:
                self.flush()
            return
        self.events.append(Event.atoms([*self.atoms, "E"], target))
        self.atoms = []

    def run_ended(self, last: int, following: int | None, *, signal: bool) -> None:
        """The run whose last instruction is at last, followed by a run at following (None at the end)."""
        end = last + INSTRUCTION
        kind = classify(self.code.word(last))
        if kind == "svc":
            self.flush()
            self.events.append(Event(Kind.EXCEPTION, CALL, 0, end))
            self.stats["syscalls"] += 1
            if following is not None:
                self.events.append(Event(Kind.BRANCH, 0, 0, following))
            return
        if following is None:
            return
        if kind == "cond" and following == end and not signal:
            self.atom("N")
        elif kind in {"cond", "branch", "isb"}:
            if signal:
                msg = f"a signal after the branch at {last:#x}: its target is unknown"
                raise SynthError(msg)
            self.stats["isb"] += kind == "isb"
            self.atom("E", following)
        elif signal:
            # Taken between two instructions: an asynchronous exception, then the handler
            self.flush()
            self.events.append(Event(Kind.EXCEPTION, 0xE, 0, end))
            self.events.append(Event(Kind.BRANCH, 0, 0, following))
        elif following != end:
            msg = f"execution went from {last:#x} to {following:#x} without a branch"
            raise SynthError(msg)

    def run(self, records: Iterable[Record]) -> list[Event]:
        last: int | None = None
        signal = False
        for record in records:
            if record[0] == "G":
                signal = True
                self.stats["signals"] += 1
            if record[0] != "B":
                continue
            _, pc, n = record
            self.stats["runs"] += 1
            self.stats["instructions"] += n
            if self.code.special_inside(pc, pc + INSTRUCTION * (n - 1)):
                msg = f"the run of {n} instructions at {pc:#x} has a branch before its end"
                raise SynthError(msg)
            if last is None:
                self.events.append(Event(Kind.BRANCH, 0, 0, pc))
            else:
                self.run_ended(last, pc, signal=signal)
            signal = False
            last = pc + INSTRUCTION * (n - 1)
        if last is not None:
            self.run_ended(last, None, signal=False)
        self.flush()
        return self.events


def runs(records: Iterable[Record]) -> Iterator[tuple[int, int]]:
    for record in records:
        if record[0] == "B":
            yield record[1], record[2]
