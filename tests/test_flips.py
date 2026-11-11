"""Flip tests: R's rules pass, and wrong rules (missed flows, wrong overwrites, addresses) fail.

One layout of sixteen states per test, to keep the suite quick; the full runs use two.
"""

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from insight.dsl.syntax import parse
from insight.flips.check import flip_test
from insight.flips.forms import form_of
from insight.flips.machine import Exclusive, epilogue, prologue, words


def quick(encoding, text=None):
    return flip_test(bytes.fromhex(encoding), parse(text) if text is not None else None, layouts=1)


CORRECT = [
    ("2000028b", "add x0, x1, x2"),
    ("2000829a", "csel x0, x1, x2, eq"),
    ("e0179f1a", "cset w0, eq"),
    ("2000a0f2", "movk x0, #1, lsl #16"),
    ("000000ca", "eor x0, x0, x0"),
    ("000000da", "sbc x0, x0, x0"),
    ("2000014b", "sub w0, w1, w1"),
    ("200021aa", "orn x0, x1, x1"),
    ("000400ca", "eor x0, x0, x0, lsl #1"),
    ("40d03bd5", "mrs x0, tpidr_el0"),
    ("208440f8", "ldr x0, [x1], #8"),
    ("00d861b8", "ldr w0, [x0, w1, sxtw #2]"),
    ("fd7bc1a8", "ldp x29, x30, [sp], #16"),
    ("09fd0ac8", "stlxr w10, x9, [x8]"),
    ("5d0200f9", "str x29, [x18]"),
    ("00013fd6", "blr x8"),
]


@pytest.mark.parametrize(("encoding", "text"), CORRECT, ids=[text for _, text in CORRECT])
def test_rule_passes(encoding, text):
    report = quick(encoding)
    assert report.ok, (text, report.failures)
    assert report.precision == []


WRONG = [
    # a write-back base whose tag is cleared
    ("208440f8", "X0 <- M[<X1> .. +8]\nX1 <- 0", "soundness: X1 flows into X1"),
    # a load of the wrong size, and at the wrong offset
    ("200040f9", "X0 <- M[<X1> .. +4]", "soundness: M["),
    ("200440f9", "X0 <- M[<X1> + 16 .. +8]", "soundness: M["),
    # a conditional select missing one source
    ("2000829a", "X0 <- X1", "soundness: X2 flows into X0"),
    # a store-exclusive written as a plain store: the bytes it may leave unchanged
    ("09fd0ac8", "M[<X8> .. +8] <- X9\nX10 <- 0", "soundness: M["),
    # the wrong write-back amount for SP
    ("fd7bc1a8", "FP <- M[<SP> .. +8]\nLR <- M[<SP> + 8 .. +8]\n<SP> <- <SP> + 8", "value: SP"),
    # a rule that excludes one of its inputs
    ("2000028b", "X0 <- X1 excl X2", "the rule excludes inputs"),
    # movk keeps the other bits: overwriting drops a flow
    ("2000a0f2", "X0 <- 0", "soundness: X0 flows into X0"),
    # x - x - !C does not depend on x: the union of the sources keeps x's tag
    ("000000da", "X0 <- X0", "overwrite: the rule keeps X0"),
    # mov of an immediate overwrites: keeping is check 2's failure
    ("200080d2", "X0 <- X0", "overwrite: the rule keeps X0"),
    # also when the rule leaves the register out
    ("200080d2", "", "overwrite: the rule keeps X0"),
    # a store of the wrong size: the bytes it leaves keep their own value, which the rule drops
    ("080000b9", "M[<X0> .. +8] <- X8", "soundness: M["),
]


@pytest.mark.parametrize(
    ("encoding", "text", "failure"),
    WRONG,
    ids=[f"{e}:{(t.splitlines() or ['(empty)'])[0]}" for e, t, _ in WRONG],
)
def test_wrong_rule_fails(encoding, text, failure):
    report = quick(encoding, text)
    assert not report.ok
    assert any(message.startswith(failure) for message in report.failures), report.failures


def test_precision_is_reported():
    """A rule with a flow that never happens passes, and the flow is listed."""
    report = quick("2000028b", "X0 <- X1 | X2 | X3")
    assert report.ok
    assert report.precision == ["X3 -> X0: in the rule, never observed"]


def test_svc_is_skipped():
    assert quick("010000d4").skipped.startswith("system call")


def test_unsupported_is_skipped():
    assert quick("2028621e").skipped == "R: FP/SIMD form without a rule"  # fadd d0, d1, d2


def test_prologue_and_epilogue_encodings():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    text = [
        f"{insn.mnemonic} {insn.op_str}"
        for insn in decoder.disasm(words(prologue(Exclusive(8, pair=True)) + epilogue()), 0)
    ]
    assert len(text) == len(prologue(Exclusive(8, pair=True))) + len(epilogue())
    assert text[:4] == [
        "mov x30, #0",
        "movk x30, #0x4000, lsl #16",
        "ldr x0, [x30, #0x110]",
        "ldxp x1, x2, [x0]",
    ]
    assert "msr nzcv, x0" in text
    assert "msr fpcr, xzr" in text
    assert "msr tpidr_el1, x30" in text
    assert text[-1] == "stp q30, q31, [x30, #0x300]"


def test_forms():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    forms = [form_of(insn) for insn in decoder.disasm(bytes.fromhex("208440f8fd7bbea900d861b82000829a"), 0)]
    assert forms == ["ldr x, [x] post, #", "stp x, x, [sp, #]!", "ldr w, [x, w sxtw #]", "csel cc x, x, x"]
