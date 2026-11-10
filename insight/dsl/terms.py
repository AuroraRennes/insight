"""Value terms: 64-bit addresses and the tracked SP/FP.

A term is kept in a canonical linear form, sum of coefficient * atom plus a constant, modulo 2^64,
so two terms are equal when their canonical forms are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

BITS = 64
MOD = 1 << BITS
MASK = MOD - 1

SYMBOL_RE = re.compile(r"<X([0-9]|[12][0-9]|30)>|<SP>|<FP>|S(0|[1-9][0-9]*)|GLOBAL|LO12")

ExtKind = Literal["uxtw", "sxtw"]
EXT_KINDS: tuple[str, ...] = ("uxtw", "sxtw", "uxtx", "sxtx")


def to_signed(value: int) -> int:
    value &= MASK
    return value - MOD if value >= MOD // 2 else value


@dataclass(frozen=True)
class Sym:
    name: str

    def __post_init__(self) -> None:
        if not SYMBOL_RE.fullmatch(self.name):
            msg = f"unknown symbol {self.name!r}"
            raise ValueError(msg)

    @property
    def is_register(self) -> bool:
        """A general register's value (<Xn>), as opposed to a tracked or block-level value."""
        return self.name.startswith("<X")

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Ext:
    """ext(term, uxtw|sxtw, shift): the low 32 bits of term, extended to 64, shifted left."""

    term: Term
    kind: ExtKind
    shift: int

    def __str__(self) -> str:
        return f"ext({self.term}, {self.kind}, {self.shift})"


@dataclass(frozen=True)
class And:
    """(term & mask)."""

    term: Term
    mask: int

    def __str__(self) -> str:
        return f"({self.term} & {hex_text(self.mask)})"


Atom = Sym | Ext | And


def hex_text(value: int) -> str:
    value = to_signed(value)
    return f"-{-value:#x}" if value < 0 else f"{value:#x}"


def atom_key(atom: Atom) -> tuple[int, str]:
    order = {Sym: 0, Ext: 1, And: 2}[type(atom)]
    return (order, str(atom))


@dataclass(frozen=True)
class Term:
    """Canonical linear form: the coefficients are sorted by atom, nonzero, modulo 2^64."""

    coeffs: tuple[tuple[Atom, int], ...] = ()
    const: int = 0

    # Construction
    # \_____________

    @staticmethod
    def make(coeffs: dict[Atom, int], const: int) -> Term:
        items = sorted(
            ((atom, coef & MASK) for atom, coef in coeffs.items() if coef & MASK),
            key=lambda item: atom_key(item[0]),
        )
        return Term(tuple(items), const & MASK)

    @staticmethod
    def sym(name: str) -> Term:
        return Term(((Sym(name), 1),), 0)

    @staticmethod
    def of(value: int) -> Term:
        return Term((), value & MASK)

    # Arithmetic
    # \___________

    def as_dict(self) -> dict[Atom, int]:
        return dict(self.coeffs)

    def __add__(self, other: Term | int) -> Term:
        other = lift(other)
        coeffs = self.as_dict()
        for atom, coef in other.coeffs:
            coeffs[atom] = coeffs.get(atom, 0) + coef
        return Term.make(coeffs, self.const + other.const)

    def __radd__(self, other: int) -> Term:
        return self + other

    def __neg__(self) -> Term:
        return Term.make({atom: -coef for atom, coef in self.coeffs}, -self.const)

    def __sub__(self, other: Term | int) -> Term:
        return self + (-lift(other))

    def __rsub__(self, other: int) -> Term:
        return lift(other) - self

    def __mul__(self, factor: int) -> Term:
        if not isinstance(factor, int):
            return NotImplemented
        return Term.make({atom: coef * factor for atom, coef in self.coeffs}, self.const * factor)

    def __rmul__(self, factor: int) -> Term:
        return self * factor

    def __and__(self, mask: int) -> Term:
        if not isinstance(mask, int):
            return NotImplemented
        mask &= MASK
        if self.is_const:
            return Term.of(self.const & mask)
        if mask == MASK:
            return self
        if mask == 0:
            return Term.of(0)
        return Term(((And(self, mask), 1),), 0)

    def ext(self, kind: str, shift: int) -> Term:
        """The extended-register operand: uxtw/sxtw/uxtx/sxtx, then a left shift."""
        if kind not in EXT_KINDS:
            msg = f"unknown extension {kind!r}"
            raise ValueError(msg)
        if not 0 <= shift < BITS:
            msg = f"shift {shift} out of range"
            raise ValueError(msg)
        if kind in {"uxtx", "sxtx"}:
            return self * (1 << shift)
        if self.is_const:
            low = self.const & 0xFFFFFFFF
            if kind == "sxtw" and low & 0x80000000:
                low -= 1 << 32
            return Term.of(low << shift)
        ext_kind: ExtKind = "uxtw" if kind == "uxtw" else "sxtw"
        return Term(((Ext(self, ext_kind, shift), 1),), 0)

    # Inspection
    # \___________

    @property
    def is_const(self) -> bool:
        return not self.coeffs

    def symbols(self) -> frozenset[Sym]:
        found: set[Sym] = set()
        for atom, _ in self.coeffs:
            if isinstance(atom, Sym):
                found.add(atom)
            else:
                found |= atom.term.symbols()
        return frozenset(found)

    def evaluate(self, env: dict[str, int]) -> int:
        """The term's value, every symbol given by env (by name), modulo 2^64."""
        total = self.const
        for atom, coef in self.coeffs:
            if isinstance(atom, Sym):
                value = env[atom.name]
            elif isinstance(atom, Ext):
                inner = atom.term.evaluate(env) & 0xFFFFFFFF
                if atom.kind == "sxtw" and inner & 0x80000000:
                    inner -= 1 << 32
                value = inner << atom.shift
            else:
                value = atom.term.evaluate(env) & atom.mask
            total += coef * value
        return total & MASK

    def subst(self, mapping: dict[Sym, Term]) -> Term:
        if not mapping:
            return self
        result = Term.of(self.const)
        for atom, coef in self.coeffs:
            if isinstance(atom, Sym):
                part = mapping.get(atom, Term(((atom, 1),), 0))
            elif isinstance(atom, Ext):
                part = atom.term.subst(mapping).ext(atom.kind, atom.shift)
            else:
                part = atom.term.subst(mapping) & atom.mask
            result = result + part * coef
        return result

    def __str__(self) -> str:
        parts: list[str] = []
        for atom, coef in self.coeffs:
            signed = to_signed(coef)
            magnitude = abs(signed)
            text = str(atom) if magnitude == 1 else f"{magnitude}*{atom}"
            if not parts:
                parts.append(f"-{text}" if signed < 0 else text)
            else:
                parts.append(f"- {text}" if signed < 0 else f"+ {text}")
        const = to_signed(self.const)
        if not parts:
            return str(const)
        if const:
            parts.append(f"- {-const}" if const < 0 else f"+ {const}")
        return " ".join(parts)


def lift(value: Term | int) -> Term:
    return value if isinstance(value, Term) else Term.of(value)
