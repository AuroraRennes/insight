"""Composition against applying the transfers one after the other, on random transfers and states."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

import pytest

from insight.dsl.errors import AliasUndecidedError
from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.terms import MASK, Term
from insight.dsl.transfer import Dep, Transfer, compose

if TYPE_CHECKING:
    from insight.dsl.locations import Loc
    from insight.dsl.transfer import ValueReg

Concrete = tuple[object, ...]
State = dict[Concrete, frozenset[Concrete]]

BASES = [Term.sym("<SP>"), Term.sym("<FP>"), Term.sym("S0")]
REGS: list[Loc] = [*(Reg(n) for n in range(4)), *(VByte(0, b) for b in range(2))]


def concrete(loc: Loc, env: dict[str, int]) -> Concrete:
    if isinstance(loc, Mem):
        return ("M", loc.addr.evaluate(env))
    return (type(loc).__name__, str(loc))


def apply(transfer: Transfer, state: State, env: dict[str, int]) -> tuple[State, dict[str, int]]:
    """The tags after transfer, each tag the set of entry locations it comes from."""

    def tag(loc: Loc) -> frozenset[Concrete]:
        where = concrete(loc, env)
        return state.get(where, frozenset({where}))

    new = dict(state)
    for loc, dep in transfer.tags.items():
        new[concrete(loc, env)] = frozenset().union(*map(tag, dep.srcs))
    values = dict(env)
    for reg in ("SP", "FP"):
        values[f"<{reg}>"] = transfer.value(reg).evaluate(env)
    return new, values


def random_transfer(rng: random.Random) -> Transfer:
    """Registers, V bytes and memory bytes around one base for the writes (an instruction's writes
    are distinct bytes), any base for the sources."""
    mems: list[Loc] = [Mem(base + off) for base in BASES for off in range(-3, 4)]
    write_base = rng.choice(BASES)
    writable = REGS + [Mem(write_base + off) for off in range(-3, 4)]
    tags = {
        loc: Dep(frozenset(rng.sample(REGS + mems, rng.randint(0, 3))))
        for loc in rng.sample(writable, rng.randint(0, 4))
    }
    values: dict[ValueReg, Term] = {}
    if rng.random() < 0.3:
        values["SP"] = Term.sym("<SP>") + rng.randint(-2, 2)
    if rng.random() < 0.2:
        values["FP"] = rng.choice([Term.sym("<SP>") + rng.randint(-2, 2), Term.sym("S1")])
    return Transfer(tags, values)


def random_env(rng: random.Random) -> dict[str, int]:
    """Valuations that make the bases overlap often."""
    sp = rng.choice([0x1000, 2])  # 2: an address wrapping below 0
    return {name: (sp + rng.randint(-6, 6)) & MASK for name in ("S0", "S1", "<FP>")} | {"<SP>": sp}


def same_result(a: tuple[State, dict[str, int]], b: tuple[State, dict[str, int]]) -> bool:
    (sa, va), (sb, vb) = a, b
    keys = set(sa) | set(sb)
    return va == vb and all(sa.get(k, frozenset({k})) == sb.get(k, frozenset({k})) for k in keys)


@pytest.mark.parametrize("seed", range(20))
def test_composition_is_sequential_application(seed: int) -> None:
    rng = random.Random(seed)
    composed = 0
    for _ in range(200):
        transfers = [random_transfer(rng) for _ in range(rng.randint(2, 4))]
        try:
            block = compose(transfers)
        except AliasUndecidedError:
            continue
        composed += 1
        for _ in range(5):
            env = random_env(rng)
            step: tuple[State, dict[str, int]] = ({}, env)
            for transfer in transfers:
                step = apply(transfer, *step)
            assert same_result(apply(block, {}, env), step), (transfers, env)
    assert composed > 20  # enough decided cases to mean something


@pytest.mark.parametrize("seed", range(5))
def test_composition_is_associative(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(200):
        a, b, c = (random_transfer(rng) for _ in range(3))
        try:
            left = a.then(b).then(c)
            right = a.then(b.then(c))
        except AliasUndecidedError:
            continue
        assert left.same_meaning(right)
