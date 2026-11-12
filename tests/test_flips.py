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
    ("214cc49a", "crc32x w1, w1, x4"),
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


CORRECT += [
    ("228440fc", "ldr d2, [x1], #8"),
    ("e51bffad", "ldp q5, q6, [sp, #-0x20]!"),
    ("0091400d", "ld1 {v0.s}[1], [x8]"),
    ("0078c24c", "ld1 {v0.4s}, [x0], x2"),
    ("0040000c", "st3 {v0.8b, v1.8b, v2.8b}, [x0]"),
    ("6100679e", "fmov d1, x3"),
    ("2000ae9e", "fmov x0, v1.d[1]"),
    ("021ca00e", "mov v2.8b, v0.8b"),
    ("0004185e", "mov d0, v0.d[1]"),
    ("2004144e", "dup v0.4s, v1.s[2]"),
    ("201c224e", "and v0.16b, v1.16b, v2.16b"),
    ("201c216e", "eor v0.16b, v1.16b, v1.16b"),
    ("e097076f", "bic v0.8h, #0xff"),
    ("208ca26e", "cmeq v0.4s, v1.4s, v2.4s"),
    ("201c626e", "bsl v0.16b, v1.16b, v2.16b"),
    ("201ca22e", "bit v0.8b, v1.8b, v2.8b"),
    ("2038824e", "zip1 v0.4s, v1.4s, v2.4s"),
    ("2018026e", "ext v0.16b, v1.16b, v2.16b, #3"),
    ("2008600e", "rev64 v0.4h, v1.4h"),
    ("20a8316e", "uminv b0, v1.16b"),
    ("2000629e", "scvtf d0, x1"),
    ("20a4106f", "ushll2 v0.4s, v1.8h, #0"),
    ("00a4086f", "ushll2 v0.8h, v0.16b, #0"),
    ("20a4200f", "sshll v0.2d, v1.2s, #0"),
    ("2038612e", "shll v0.4s, v1.4h, #16"),
]

# Lane-wise unions: sound, and less precise than the bits (a sum's low byte does not depend on
# its high one), so they pass with precision reports.
LANES = [
    ("2084a24e", "add v0.4s, v1.4s, v2.4s"),
    ("2080a24f", "mul v0.4s, v1.4s, v2.s[1]"),
    ("20147d6f", "usra v0.2d, v1.2d, #3"),
    ("200c421f", "fmadd d0, d1, d2, d3"),
    ("20a4132f", "ushll v0.4s, v1.4h, #3"),
    ("2028214e", "xtn2 v0.16b, v1.8h"),
    ("20bca24e", "addp v0.4s, v1.4s, v2.4s"),
    ("20147b5f", "ssra d0, d1, #5"),
    ("20943b5f", "sqshrn s0, d1, #5"),
    ("2068a06e", "uadalp v0.2d, v1.4s"),
    ("2038a04e", "suqadd v0.4s, v1.4s"),
    ("2020034e", "tbl v0.16b, {v1.16b, v2.16b}, v3.16b"),
]


@pytest.mark.parametrize(("encoding", "text"), CORRECT, ids=[text for _, text in CORRECT])
def test_rule_passes(encoding, text):
    report = quick(encoding)
    assert report.ok, (text, report.failures)
    assert report.precision == []


@pytest.mark.parametrize(("encoding", "text"), LANES, ids=[text for _, text in LANES])
def test_lane_rule_passes(encoding, text):
    report = quick(encoding)
    assert report.ok, (text, report.failures)


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
    ("2000028b", "X0 <- X1 excl X2", "the rule excludes X2 from X0, which the policy does not"),
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
    # a scalar load that keeps the upper bytes: the instruction clears them
    ("228440fc", "V2[0:7] <- M[<X1> .. +8] per 1", "overwrite: the rule keeps V2[8]"),
    # a lane load that clears the other lanes: they keep their bytes
    ("0091400d", "V0[4:7] <- M[<X8> .. +4] per 1\nV0[0:3] <- 0", "soundness: V0[0] flows into V0[0]"),
    # a pair stored in the wrong order
    (
        "e51bffad",
        "V6[0:15] <- M[<SP> - 32 .. +16] per 1\nV5[0:15] <- M[<SP> - 16 .. +16] per 1\n<SP> <- <SP> - 32",
        "soundness: M[",
    ),
    # a register post-index whose register is not a source of the base
    ("0078c24c", "V0[0:15] <- M[<X0> .. +16] per 1", "soundness: X2 flows into X0"),
    # st3 written as three registers one after the other, not interleaved
    (
        "0040000c",
        (
            "M[<X0> .. +8] <- V0[0:7] per 1\n"
            "M[<X0> + 8 .. +8] <- V1[0:7] per 1\n"
            "M[<X0> + 16 .. +8] <- V2[0:7] per 1"
        ),
        "soundness: V",
    ),
    # a dup from the wrong element
    ("2004144e", "V0[0:15] <- [V1[0:3] V1[0:3] V1[0:3] V1[0:3]]", "soundness: V1[8] flows into V0[0]"),
    # zip1 with its sources swapped
    ("2038824e", "V0[0:15] <- [V2[0:3] V1[0:3] V2[4:7] V1[4:7]]", "soundness: V1[0] flows into V0[0]"),
    # ext by the wrong amount
    ("2018026e", "V0[0:15] <- [V1[2:15] V2[0:1]]", "soundness: V1[3] flows into V0[0]"),
    # addp taken lane-wise, not pairwise
    ("20bca24e", "V0[0:15] <- V1[0:15] | V2[0:15] per 4", "soundness: V1[4] flows into V0[0]"),
    # ushll2 from the lower half
    ("20a4106f", "V0[0:15] <- V1[0:7] per 2:4", "soundness: V1[8] flows into V0[0]"),
    # sxtl taken as a zero-extension: the bytes above copy the top one
    (
        "20a4200f",
        "V0[0:15] <- [V1[0:3] 0 0 0 0 V1[4:7] 0 0 0 0]",
        "soundness: V1[3] flows into V0[4]",
    ),
    # xtn2 clearing the lower half it keeps
    ("2028214e", "V0[8:15] <- V1[0:15] per 2:1\nV0[0:7] <- 0", "soundness: V0[0] flows into V0[0]"),
    # a table lookup taken byte for byte: any table byte may be picked
    ("2020034e", "V0[0:15] <- V1[0:15] per 1 excl V3[0:15] per 1", "soundness: V"),
    # bic of 0xff keeping the bytes it clears
    ("e097076f", "", "overwrite: the rule keeps V0[0]"),
    # bsl excluding its data instead of its mask
    (
        "201c626e",
        "V0[0:15] <- V0[0:15] | V2[0:15] per 1 excl V1[0:15] per 1",
        "the rule excludes V1[0] from V0[0], which the policy does not",
    ),
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
    assert quick("2048284e").skipped == "R: FP/SIMD form without a rule"  # aese v0.16b, v1.16b


def test_union_of_an_element_passes_with_precision():
    """The compiler's union for 'mov d0, v0.d[1]' is sound: the extra flows are precision reports."""
    report = quick("0004185e", "V0[0:7] <- V0[8:15]\nV0[8:15] <- 0")
    assert report.ok
    assert len(report.precision) == 56


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
