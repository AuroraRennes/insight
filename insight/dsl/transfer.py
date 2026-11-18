"""Transfers, the normal form of an instruction or a block, which is its meaning.

Each written location maps to its dependency set: its new tag is the OR of its sources' tags at
the entry, and a location outside the map keeps its tag. The values part gives the tracked SP and
FP at the exit as terms, and an instruction form lists the registers it sends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from insight.dsl.errors import AliasUndecidedError, InstructionFormError, OpaqueError
from insight.dsl.locations import Mem
from insight.dsl.terms import Sym, Term, relation

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping

    from insight.dsl.locations import Loc, Reg

ValueReg = Literal["SP", "FP"]
VALUE_REGS: tuple[ValueReg, ...] = ("SP", "FP")
ENTRY_SYMS: dict[ValueReg, Sym] = {"SP": Sym("<SP>"), "FP": Sym("<FP>")}

EMPTY: frozenset[Loc] = frozenset()


@dataclass(frozen=True)
class Dep:
    srcs: frozenset[Loc]
    excl: frozenset[Loc] = EMPTY
    over: frozenset[Loc] = EMPTY

    def __post_init__(self) -> None:
        if not self.over <= self.srcs:
            extra = ", ".join(sorted(map(str, self.over - self.srcs)))
            msg = f"over-approximated sources that are not sources: {extra}"
            raise ValueError(msg)

    def is_identity_of(self, loc: Loc) -> bool:
        return self.srcs == {loc} and not self.excl and not self.over


@dataclass(frozen=True)
class Opaque:
    """A statement without a dependency meaning: svc, or an unsupported instruction."""

    kind: Literal["svc", "unsupported"]
    text: str = ""

    def __str__(self) -> str:
        return "svc" if self.kind == "svc" else f'unsupported "{self.text}"'


@dataclass(frozen=True)
class Transfer:
    tags: Mapping[Loc, Dep] = field(default_factory=dict)
    values: Mapping[ValueReg, Term] = field(default_factory=dict)
    opaque: tuple[Opaque, ...] = ()
    sends: tuple[Reg, ...] = ()

    # Access
    # \_______

    def dep(self, loc: Loc) -> Dep:
        return self.tags.get(loc) or Dep(frozenset({loc}))

    def value(self, reg: ValueReg) -> Term:
        return self.values.get(reg) or Term(((ENTRY_SYMS[reg], 1),), 0)

    def normalized(self) -> Transfer:
        """Identity entries dropped: two transfers with the same meaning normalise equal."""
        tags = {loc: dep for loc, dep in self.tags.items() if not dep.is_identity_of(loc)}
        values = {reg: term for reg, term in self.values.items() if term != self.value_entry(reg)}
        return Transfer(tags, values, self.opaque, self.sends)

    @staticmethod
    def value_entry(reg: ValueReg) -> Term:
        return Term(((ENTRY_SYMS[reg], 1),), 0)

    def same_meaning(self, other: Transfer) -> bool:
        """Equality of the normal forms. Memory locations are compared by their canonical
        linear terms."""
        a, b = self.normalized(), other.normalized()
        return (
            dict(a.tags) == dict(b.tags)
            and dict(a.values) == dict(b.values)
            and a.opaque == b.opaque
            and a.sends == b.sends
        )

    # Symbols
    # \________

    def locations(self) -> Iterator[Loc]:
        for loc, dep in self.tags.items():
            yield loc
            yield from dep.srcs
            yield from dep.excl

    def symbols(self) -> frozenset[Sym]:
        """The symbols of every address and value."""
        found: set[Sym] = set()
        for loc in self.locations():
            if isinstance(loc, Mem):
                found |= loc.addr.symbols()
        for term in self.values.values():
            found |= term.symbols()
        return frozenset(found)

    def subst(self, mapping: Mapping[Sym, Term]) -> Transfer:
        """Every address and value with the symbols of mapping replaced."""
        replace = dict(mapping)

        def move(loc: Loc) -> Loc:
            return Mem(loc.addr.subst(replace)) if isinstance(loc, Mem) else loc

        tags: dict[Loc, Dep] = {}
        for loc, dep in self.tags.items():
            target = move(loc)
            if target in tags:
                msg = f"{target} written twice once its symbols are replaced"
                raise ValueError(msg)
            tags[target] = Dep(
                frozenset(map(move, dep.srcs)), frozenset(map(move, dep.excl)), frozenset(map(move, dep.over))
            )
        values = {reg: term.subst(replace) for reg, term in self.values.items()}
        return Transfer(tags, values, self.opaque, self.sends)

    def __str__(self) -> str:
        from insight.dsl.printer import dump  # noqa: PLC0415 (printer imports this module)

        return dump(self)

    # Composition
    # \____________

    def check_composable(self) -> None:
        """Only block forms compose: no opaque statement, no send, no <Xn>."""
        if self.opaque:
            msg = f"cannot compose through {self.opaque[0]}"
            raise OpaqueError(msg)
        if self.sends:
            msg = f"send {self.sends[0]}: pair the sends first, then compose the block form"
            raise InstructionFormError(msg)
        registers = sorted(str(sym) for sym in self.symbols() if sym.is_register)
        if registers:
            msg = f"{registers[0]}: compose block forms (sends), not instruction forms"
            raise InstructionFormError(msg)

    def at_exit(self, loc: Loc) -> Dep:
        """What a location at this transfer's exit depends on at its entry."""
        if not isinstance(loc, Mem):
            return self.dep(loc)
        written = same_byte(loc, [each for each in self.tags if isinstance(each, Mem)])
        return Dep(frozenset({loc})) if written is None else self.tags[written]

    def then(self, second: Transfer) -> Transfer:
        """This transfer followed by second."""
        self.check_composable()
        second.check_composable()
        entry = {ENTRY_SYMS[reg]: self.value(reg) for reg in VALUE_REGS}

        def rebase(loc: Loc) -> Loc:
            return Mem(loc.addr.subst(entry)) if isinstance(loc, Mem) else loc

        tags: dict[Loc, Dep] = {}
        for loc, dep in second.tags.items():
            target = rebase(loc)
            if target in tags:
                msg = f"{target} written twice"
                raise ValueError(msg)
            tags[target] = self.through(dep, rebase)
        second_mem = [loc for loc in tags if isinstance(loc, Mem)]
        for loc, dep in self.tags.items():
            if loc in tags or (isinstance(loc, Mem) and same_byte(loc, second_mem) is not None):
                continue
            tags[loc] = dep
        values = {reg: second.value(reg).subst(entry) for reg in VALUE_REGS}
        return Transfer(tags, values).normalized()

    def through(self, dep: Dep, rebase: Callable[[Loc], Loc]) -> Dep:
        """A dependency of the next transfer, its sources taken back through this one. A source
        stays over-approximated only if every path to it is."""
        srcs: set[Loc] = set()
        exact: set[Loc] = set()
        excl: set[Loc] = set()
        over = {rebase(src) for src in dep.over}
        for src in map(rebase, dep.srcs):
            inner = self.at_exit(src)
            srcs |= inner.srcs
            excl |= inner.excl
            if src not in over:
                exact |= inner.srcs - inner.over
        for src in map(rebase, dep.excl):
            inner = self.at_exit(src)
            excl |= inner.srcs | inner.excl
        return Dep(frozenset(srcs), frozenset(excl), frozenset(srcs - exact))


def same_byte(loc: Mem, written: Iterable[Mem]) -> Mem | None:
    """The written location at the same address, if any; fails when that cannot be decided."""
    written = list(written)
    relations = [relation(loc.addr, other.addr) for other in written]
    if "eq" in relations:
        return written[relations.index("eq")]
    if "unknown" in relations:
        raise AliasUndecidedError(loc.addr, written[relations.index("unknown")].addr)
    return None


def compose(transfers: Iterable[Transfer]) -> Transfer:
    result = Transfer()
    for transfer in transfers:
        result = result.then(transfer)
    return result
