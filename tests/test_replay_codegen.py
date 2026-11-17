"""The replay's generated group code against a direct evaluation of the same forms."""

import random

import pytest

from insight.dsl.locations import Mem
from insight.dsl.syntax import parse
from insight.dsl.terms import MASK
from insight.replay.codegen import generate, runs_of, tag_fill, tag_or
from insight.replay.state import PAGE, State

FORMS = [
    "X0 <- M[S0 + 3 .. +4]",
    "M[S0 .. +4] <- X1\nM[S0 + 4 .. +4] <- X2",
    "M[<SP> - 16 .. +8] <- FP\nM[<SP> - 8 .. +8] <- LR\n<SP> <- <SP> - 16",
    "V0[0:15] <- M[S0 .. +16] per 1",
    "M[S0 .. +16] <- V1[0:15] per 1",
    "X3 <- X3 | M[S0 .. +8]\nM[S0 .. +8] <- X4",  # every source read before any write
    "M[S0 .. +8] <- M[S1 .. +8] per 1",  # two bases, which may overlap
    "X0 <- M[S0 + ext(S1, sxtw, 3) .. +8]",
    "X0 <- X1\nX1 <- X0",
    "X5 <- 0\n<FP> <- <SP> + 32",
]

# Values for S0 and S1: inside a page, across a page boundary, near the top of the address space
VALUES = [0x10000, 0x1FFC, 0x2FF9, 0x10004, MASK - 6]


def random_state(rng: random.Random, near: list[int]) -> State:
    state = State()
    state.x = [rng.choice((0, 0, 1, 2, 4)) for _ in range(32)]
    state.v = [bytearray(rng.choice((0, 0, 1, 8)) for _ in range(16)) for _ in range(32)]
    for addr in near:
        for i in range(-24, 24):
            if rng.random() < 0.5:
                state.mem.set((addr + i) & MASK, rng.choice((0, 1, 2, 16)))
    return state


def snapshot(state: State) -> tuple:
    memory = {(page << 12) + i: b for page, data in state.mem.pages.items() for i, b in enumerate(data) if b}
    return list(state.x), [bytes(v) for v in state.v], memory, state.sp, state.fp


def reference(form, state: State, env: dict[str, int]) -> set[int]:
    """The form run from its data structures: the bytes it names, its tags and SP/FP."""
    addrs = {loc.addr: loc.addr.evaluate(env) for loc in form.locations() if isinstance(loc, Mem)}
    new = []
    for loc, dep in form.tags.items():
        tag = 0
        for src in dep.srcs:
            tag |= state.tag(src, addrs)
        new.append((loc, tag))
    for loc, tag in new:
        state.set_tag(loc, tag, addrs)
    sp = form.values["SP"].evaluate(env) if "SP" in form.values else state.sp
    fp = form.values["FP"].evaluate(env) if "FP" in form.values else state.fp
    state.sp, state.fp = sp, fp
    return set(addrs.values())


@pytest.mark.parametrize("text", FORMS)
def test_generated_code_matches_the_forms(text: str):
    form = parse(text)
    mems = list(dict.fromkeys(loc.addr for loc in form.locations() if isinstance(loc, Mem)))
    where, apply = generate(form, mems)
    rng = random.Random(text)
    for s0 in VALUES:
        for s1 in (0x10008, 0xFFFFFFF0, s0 + 4):
            sent = [s0, s1 & MASK]
            sp, fp = 0x2FFC, 0x7000
            env = {"<SP>": sp, "<FP>": fp, "S0": sent[0], "S1": sent[1]}
            expected, actual = random_state(rng, [*sent, sp]), State()
            expected.sp = actual.sp = sp
            expected.fp = actual.fp = fp
            (actual.x, actual.v, actual.mem.pages) = (
                list(expected.x),
                [bytearray(v) for v in expected.v],
                {k: bytearray(p) for k, p in expected.mem.pages.items()},
            )
            named = reference(form, expected, env)

            runs, starts = where(sp, fp, sent)
            assert {(start + i) & MASK for start, n in runs for i in range(n)} == named
            actual.sp, actual.fp = apply(
                starts, sp, fp, sent, actual.x, actual.v, actual.mem.pages, actual.mem.set
            )
            assert snapshot(actual) == snapshot(expected), (text, hex(s0), hex(s1))


def test_runs_join_consecutive_bytes_of_one_base():
    form = parse("X0 <- M[S0 .. +8] | M[S0 + 16 .. +4] | M[S1 .. +2]")
    runs = runs_of([loc.addr for loc in form.locations() if isinstance(loc, Mem)])
    assert sorted((const, n) for _, const, n in runs.runs) == [(0, 2), (0, 8), (16, 4)]  # srcs is a set


def test_tag_or_and_fill_across_a_page():
    pages: dict[int, bytearray] = {}
    tag_fill(pages, PAGE - 3, 6, 0)
    assert pages == {}  # clean bytes allocate nothing
    tag_fill(pages, PAGE - 3, 6, 4)
    assert sorted(pages) == [0, 1]
    assert tag_or(pages, PAGE - 1, 2) == 4
    assert tag_or(pages, PAGE + 3, 4) == 0
    assert tag_or(pages, 7 * PAGE, 8) == 0
