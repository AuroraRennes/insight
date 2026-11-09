import random

import pytest

from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.printer import dump
from insight.dsl.syntax import parse
from insight.dsl.terms import Term
from insight.dsl.transfer import Dep, Transfer

S0 = Term.sym("S0")
SP = Term.sym("<SP>")


def test_roundtrip():
    # Not a real instruction: one line per statement form, to check that dump then parse is the
    # identity.
    text = """
        send X0
        X1 <- M[<X0> + 8 .. +8]
        M[<SP> - 16 .. +8] <- LR
        V0[0:15] <- V1[0:7] per 1:2 over V1[0]
        V2[0:15] <- V4[0:15] | V5[0:15] per 1 excl V3[0:15] per 1
        V6[0:15] <- [V1[3:0] V1[7:4] 0 0 0 0 V2[0:3]]
        V7[0:15] <- M[<X0> .. +4 step 8 times 4] per 1
        X5 <- M[(S1 & -64) + ext(S2, uxtw, 3)]
        <SP> <- <SP> - 16
        <FP> <- <X29>
    """
    t = parse(text)
    assert parse(dump(t)) == t
    assert dump(parse(dump(t))) == dump(t)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("X1 <- M[S0 .. +8]", "X1 <- M[S0 .. +8]"),
        ("M[<SP> - 16 .. +8] <- LR", "M[<SP> - 16 .. +8] <- X30"),
        ("V0[0:15] <- [V1[3:15] V2[0:2]]", "V0[0:15] <- [V1[3:15] V2[0:2]]"),
        ("V0[0:7] <- [V1[3:0] V1[7:4]]", "V0[0:7] <- [V1[3:0] V1[7:4]]"),
        ("V0[0:15] <- [V1[8:15] 0 0 0 0 0 0 0 0]", "V0[0:15] <- [V1[8:15] 0 0 0 0 0 0 0 0]"),
        ("V0[0:15] <- 0 excl V1[0:15]", "V0[0:15] <- 0 excl V1[0:15]"),
        ("<SP> <- <SP> - 16", "<SP> <- <SP> - 16"),
        ("send FP", "send X29"),
        ("send X1\nsend X0\nsend X1", "send X1\nsend X0\nsend X1"),
        ("svc", "svc"),
    ],
)
def test_dump_regroups(text, expected):
    assert dump(parse(text)) == expected


@pytest.mark.parametrize(
    "text",
    [
        "V0[0:7] <- V1[0:7] | V2[0:7] per 4",
        "V0[0:15] <- V1[0:7] per 1:2",
        "V0[0:15] <- V1[0:15] | V2[0:15] per 1 excl V0[0:15] per 1",
        "V0[0:15] <- 0 excl V1[0:15] | V2[0:15] per 4",
        "V0[0:15] <- V1[0:15] excl V3[0:15] per 1",
        "V0[0:15] <- M[<X0> + 4 .. +4 step 8 times 4] per 1",
        "V0[0:15] <- M[<X0> .. +16] per 1",
    ],
)
def test_dump_finds_per_structure(text):
    assert dump(parse(text)) == text


def test_dump_strided_destination_is_split_but_equal():
    t = parse("M[<X0> .. +4 step 8 times 4] <- V0[0:15] per 1")
    assert len(dump(t).splitlines()) == 4
    assert parse(dump(t)) == t


def test_dump_orders_memory_by_offset():
    lines = dump(parse("M[S0 .. +4] <- X1\nM[S0 + 8 .. +4] <- X2\nM[S0 + 12] <- X2")).splitlines()
    assert lines == ["M[S0 .. +4] <- X1", "M[S0 + 8 .. +5] <- X2"]


def _random_transfer(rng) -> Transfer:
    pool = (
        [Reg(n) for n in range(4)]
        + [VByte(n, b) for n in range(3) for b in range(16)]
        + [Mem(S0 + k) for k in range(24)]
        + [Mem(SP - 8 + k) for k in range(8)]
    )
    tags = {}
    for dst in rng.sample(pool, rng.randint(1, 24)):
        srcs = frozenset(rng.sample(pool, rng.randint(0, 3)))
        excl = frozenset(rng.sample(pool, rng.randint(0, 1)))
        over = frozenset(rng.sample(sorted(srcs, key=str), rng.randint(0, min(1, len(srcs)))))
        tags[dst] = Dep(srcs, excl, over)
    return Transfer(tags, {"SP": SP - 16} if rng.random() < 0.5 else {})


def test_dump_roundtrip_random():
    rng = random.Random(20261109)  # noqa: S311 (reproducible test data)
    for _ in range(300):
        t = _random_transfer(rng)
        assert parse(dump(t)) == t, dump(t)
