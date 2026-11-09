"""Tag locations: one per X register (and SP), one per V-register byte, one per memory byte."""

from __future__ import annotations

from dataclasses import dataclass

from insight.dsl.terms import MOD, Term

SP_INDEX = 31
REGISTER_ALIASES = {"FP": 29, "LR": 30}


@dataclass(frozen=True)
class Reg:
    """X0-X30, and SP as register 31 (one tag each)."""

    n: int

    def __post_init__(self) -> None:
        if not 0 <= self.n <= SP_INDEX:
            msg = f"register X{self.n} out of range"
            raise ValueError(msg)

    def __str__(self) -> str:
        return "SP" if self.n == SP_INDEX else f"X{self.n}"


@dataclass(frozen=True)
class VByte:
    """Byte b (0-15) of V<n>."""

    n: int
    b: int

    def __post_init__(self) -> None:
        if not 0 <= self.n <= 31 or not 0 <= self.b <= 15:
            msg = f"V{self.n}[{self.b}] out of range"
            raise ValueError(msg)

    def __str__(self) -> str:
        return f"V{self.n}[{self.b}]"


@dataclass(frozen=True)
class Mem:
    """The one memory byte at addr."""

    addr: Term

    def __str__(self) -> str:
        return f"M[{self.addr}]"


Loc = Reg | VByte | Mem


def loc_key(loc: Loc) -> tuple[int, str, int, int]:
    """Deterministic order for dumps: registers, then V bytes, then memory by base and offset."""
    if isinstance(loc, Reg):
        return (0, "", loc.n, 0)
    if isinstance(loc, VByte):
        return (1, "", loc.n, loc.b)
    base = Term(loc.addr.coeffs, 0)
    offset = loc.addr.const - MOD if loc.addr.const >= MOD // 2 else loc.addr.const
    return (2, str(base), offset, 0)
