"""The compactor's 64-bit events, one per AXI-Stream beat."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# Bits 63:61 hold the kind, 60:56 a count or a code, 55:32 atom bits or a number, 31:0 an address.
KIND_SHIFT = 61
COUNT_SHIFT = 56
BITS_SHIFT = 32
COUNT_MASK = 0x1F
BITS_MASK = 0xFF_FFFF
ADDR_MASK = 0xFFFF_FFFF
MAX_ATOMS = 24

# The target of a branch that leaves the traced range.
OUTSIDE = 0xFFFF_FFFF


class Kind(IntEnum):
    BRANCH = 0  # atoms, the last one E, and the branch target (no atoms: execution is now at the target)
    ATOMS = 1  # atoms, all N
    EXCEPTION = 2  # the exception type and the address execution would have resumed at
    OVERFLOW = 3  # the ETM lost trace; position unknown until the next address
    LOST = 4  # the compactor dropped events
    CONTEXT = 5  # a new context ID
    ERROR = 6  # the trace breaks an assumption of the compactor; position unknown


class Error(IntEnum):
    E_NOT_LAST = 1  # an E atom followed by more atoms in the same packet
    NO_TARGET = 2  # an E atom not followed by an address
    WIDE = 3  # an address in the range that does not fit in 32 bits after the load bias


@dataclass(frozen=True)
class Event:
    kind: Kind
    count: int = 0  # atoms (BRANCH, ATOMS), the exception type, or the error code
    bits: int = 0  # atom bits, bit 0 the oldest, E = 1 (BRANCH, ATOMS), or how many were lost (LOST)
    address: int = 0  # target, resume address or context ID

    @staticmethod
    def atoms(elements: list[str], target: int | None = None) -> Event:
        if len(elements) > MAX_ATOMS:
            msg = f"{len(elements)} atoms in one event"
            raise ValueError(msg)
        bits = sum(1 << i for i, element in enumerate(elements) if element == "E")
        if target is None:
            return Event(Kind.ATOMS, len(elements), bits)
        return Event(Kind.BRANCH, len(elements), bits, target)

    def encode(self) -> int:
        return (
            (self.kind << KIND_SHIFT)
            | ((self.count & COUNT_MASK) << COUNT_SHIFT)
            | ((self.bits & BITS_MASK) << BITS_SHIFT)
            | (self.address & ADDR_MASK)
        )

    @staticmethod
    def decode(word: int) -> Event:
        return Event(
            Kind(word >> KIND_SHIFT),
            (word >> COUNT_SHIFT) & COUNT_MASK,
            (word >> BITS_SHIFT) & BITS_MASK,
            word & ADDR_MASK,
        )

    def atom_string(self) -> str:
        return "".join("E" if self.bits >> i & 1 else "N" for i in range(self.count))

    def __str__(self) -> str:
        target = "outside" if self.address == OUTSIDE else f"{self.address:#x}"
        text = self.kind.name
        match self.kind:
            case Kind.BRANCH:
                text = f"BRANCH {self.atom_string() or '-'} {target}"
            case Kind.ATOMS:
                text = f"ATOMS {self.atom_string()}"
            case Kind.EXCEPTION:
                text = f"EXCEPTION {self.count:#x} {self.address:#x}"
            case Kind.LOST:
                text = f"LOST {self.bits}"
            case Kind.CONTEXT:
                text = f"CONTEXT {self.address:#x}"
            case Kind.ERROR:
                text = f"ERROR {Error(self.count).name}"
        return text
