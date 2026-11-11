"""R on general-register instructions: each rule against the transfer written in the DSL."""

from pathlib import Path

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

from insight.annotations.against_r import compare_block, differences
from insight.annotations.framing import Block, Group, read_blocks
from insight.annotations.pairing import code_at, decode
from insight.dsl.syntax import parse
from insight.flips.forms import load_corpus
from insight.semantics.operands import UnsupportedFormError
from insight.semantics.rules import rule

ELFS = Path(__file__).parent.parent / "data" / "annotations" / "elf"


def insn_of(encoding):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    (insn,) = decoder.disasm(bytes.fromhex(encoding), 0x1000)
    return insn


STLXR_BYTES = "\n".join(f"M[<X8> + {i}] <- M[<X8> + {i}] | X9" for i in range(8))

RULES = [
    ("2000028b", "add x0, x1, x2", "X0 <- X1 | X2"),
    ("2000829a", "csel x0, x1, x2, eq", "X0 <- X1 | X2"),
    ("e0179f1a", "cset w0, eq", "X0 <- 0"),
    ("1f0c00f1", "cmp x0, #3", ""),
    ("000000ca", "eor x0, x0, x0", "X0 <- 0"),
    ("000000da", "sbc x0, x0, x0", "X0 <- 0"),
    ("2000014b", "sub w0, w1, w1", "X0 <- 0"),
    ("200021aa", "orn x0, x1, x1", "X0 <- 0"),
    ("000400ca", "eor x0, x0, x0, lsl #1", "X0 <- X0"),
    ("2000018b", "add x0, x1, x1", "X0 <- X1"),
    ("2000a0f2", "movk x0, #1, lsl #16", "X0 <- X0"),
    ("200080d2", "mov x0, #1", "X0 <- 0"),
    ("40d03bd5", "mrs x0, tpidr_el0", "X0 <- 0"),
    ("200040f9", "ldr x0, [x1]", "X0 <- M[<X1> .. +8]"),
    ("200440f9", "ldr x0, [x1, #8]", "X0 <- M[<X1> + 8 .. +8]"),
    ("208440f8", "ldr x0, [x1], #8", "X0 <- M[<X1> .. +8]"),
    ("00d861b8", "ldr w0, [x0, w1, sxtw #2]", "X0 <- M[<X0> + ext(<X1>, sxtw, 2) .. +4]"),
    ("2c79aab8", "ldrsw x12, [x9, x10, lsl #2]", "X12 <- M[<X9> + 4*<X10> .. +4]"),
    ("1c6b3d38", "strb w28, [x24, x29]", "M[<X24> + <FP>] <- X28"),
    ("080000b9", "str w8, [x0]", "M[<X0> .. +4] <- X8"),
    (
        "fd7bbea9",
        "stp x29, x30, [sp, #-32]!",
        "M[<SP> - 32 .. +8] <- FP\nM[<SP> - 24 .. +8] <- LR\n<SP> <- <SP> - 32",
    ),
    (
        "fd7bc1a8",
        "ldp x29, x30, [sp], #16",
        "FP <- M[<SP> .. +8]\nLR <- M[<SP> + 8 .. +8]\n<SP> <- <SP> + 16",
    ),
    ("09fd0ac8", "stlxr w10, x9, [x8]", f"{STLXR_BYTES}\nX10 <- 0"),
    ("ff430091", "add sp, sp, #16", "<SP> <- <SP> + 16"),
    ("fd030091", "mov x29, sp", "FP <- SP"),
    ("3fe57a92", "and sp, x9, #-64", "SP <- X9\n<SP> <- (<X9> & -64)"),
    ("bf4300d1", "sub sp, x29, #16", "SP <- FP\n<SP> <- <FP> - 16"),
    ("5d0200f9", "str x29, [x18]", "send X29"),
    ("410200a9", "stp x1, x0, [x18]", "send X0\nsend X1"),
    ("00013fd6", "blr x8", "LR <- 0"),
    ("c0035fd6", "ret", ""),
    ("010000d4", "svc #0", "svc"),
]


@pytest.mark.parametrize(("encoding", "text", "expected"), RULES, ids=[text for _, text, _ in RULES])
def test_rule(encoding, text, expected):
    insn = insn_of(encoding)
    assert differences(parse(expected), rule(insn)) == [], text


# FP/SIMD loads and stores (byte for byte) and moves. The texts follow the compiler's annotations
# where they agree with R.
V_RULES = [
    ("2004c03d", "ldr q0, [x1, #0x10]", "V0[0:15] <- M[<X1> + 16 .. +16] per 1"),
    ("228440fc", "ldr d2, [x1], #8", "V2[0:15] <- [M[<X1> .. +8] 0 0 0 0 0 0 0 0]"),
    ("2400403d", "ldr b4, [x1]", "V4[0] <- M[<X1>]\nV4[1:15] <- 0"),
    (
        "e51bffad",
        "ldp q5, q6, [sp, #-0x20]!",
        "V5[0:15] <- M[<SP> - 32 .. +16] per 1\nV6[0:15] <- M[<SP> - 16 .. +16] per 1\n<SP> <- <SP> - 32",
    ),
    ("27e01f7c", "stur h7, [x1, #-2]", "M[<X1> - 2 .. +2] <- V7[0:1] per 1"),
    (
        "00a0df4c",
        "ld1 {v0.16b, v1.16b}, [x0], #32",
        "V0[0:15] <- M[<X0> .. +16] per 1\nV1[0:15] <- M[<X0> + 16 .. +16] per 1",
    ),
    ("0091400d", "ld1 {v0.s}[1], [x8]", "V0[4:7] <- M[<X8> .. +4] per 1"),
    ("0078c24c", "ld1 {v0.4s}, [x0], x2", "V0[0:15] <- M[<X0> .. +16] per 1\nX0 <- X0 | X2"),
    ("00c4404d", "ld1r {v0.8h}, [x0]", "V0[0:15] <- M[<X0> .. +2 step 0 times 8] per 1"),
    (
        "0040000c",
        "st3 {v0.8b, v1.8b, v2.8b}, [x0]",
        (
            "M[<X0> .. +1 step 3 times 8] <- V0[0:7] per 1\n"
            "M[<X0> + 1 .. +1 step 3 times 8] <- V1[0:7] per 1\n"
            "M[<X0> + 2 .. +1 step 3 times 8] <- V2[0:7] per 1"
        ),
    ),
    ("2300669e", "fmov x3, d1", "X3 <- V1[0:7]"),
    ("6100679e", "fmov d1, x3", "V1[0:15] <- [X3 X3 X3 X3 X3 X3 X3 X3 0 0 0 0 0 0 0 0]"),
    ("2000ae9e", "fmov x0, v1.d[1]", "X0 <- V1[8:15]"),
    ("0100af9e", "fmov v1.d[1], x0", "V1[8:15] <- X0"),
    ("2040601e", "fmov d0, d1", "V0[0:7] <- V1[0:7] per 1\nV0[8:15] <- 0"),
    ("00106c1e", "fmov d0, #0.5", "V0[0:15] <- 0"),
    ("00e4006f", "movi v0.2d, #0", "V0[0:15] <- 0"),
    ("21e4002f", "movi d1, #0xff", "V1[0:15] <- 0"),
    ("021ca00e", "mov v2.8b, v0.8b", "V2[0:7] <- V0[0:7] per 1\nV2[8:15] <- 0"),
    ("0004185e", "mov d0, v0.d[1]", "V0[0:7] <- V0[8:15] per 1\nV0[8:15] <- 0"),
    ("203c140e", "mov w0, v1.s[2]", "X0 <- V1[8:11]"),
    ("202c0e4e", "smov x0, v1.h[3]", "X0 <- V1[6:7]"),
    ("001c0b4e", "mov v0.b[5], w0", "V0[5] <- X0"),
    ("2004186e", "mov v0.d[1], v1.d[0]", "V0[8:15] <- V1[0:7] per 1"),
    ("000c040e", "dup v0.2s, w0", "V0[0:7] <- X0\nV0[8:15] <- 0"),
    ("2004144e", "dup v0.4s, v1.s[2]", "V0[0:15] <- [V1[8:11] V1[8:11] V1[8:11] V1[8:11]]"),
]


@pytest.mark.parametrize(("encoding", "text", "expected"), V_RULES, ids=[text for _, text, _ in V_RULES])
def test_fp_simd_rule(encoding, text, expected):
    insn = insn_of(encoding)
    assert f"{insn.mnemonic} {insn.op_str}".startswith(text.split(",")[0]), text
    assert differences(parse(expected), rule(insn)) == [], text


def test_union_of_an_element_is_imprecise():
    """The compiler's 'mov d0, v0.d[1]': each byte gets the whole element (sound, not R's)."""
    found = differences(parse("V0[0:7] <- V0[8:15]\nV0[8:15] <- 0"), rule(insn_of("0004185e")))
    assert len(found) == 8
    union = " | ".join(sorted(f"V0[{b}]" for b in range(8, 16)))
    assert found[0] == f"annotation V0[0] <- {union}, R V0[0] <- V0[8]"


def test_unsupported_fails_closed():
    with pytest.raises(UnsupportedFormError, match="fadd d0, d1, d2: FP/SIMD form without a rule"):
        rule(insn_of("2028621e"))


def test_store_of_a_non_register_fails_closed():
    """SME's ZA array is not a register operand for capstone: the store has no data register."""
    with pytest.raises(UnsupportedFormError, match="0 general register operands, 1 expected"):
        rule(insn_of("006220e1"))  # str za[w15, 0], [x16]


def test_good_elf_against_r():
    """The fixture's store-exclusive pair is annotated as an overwrite; R keeps the bytes' tags
    too, since the store may fail. Everything else agrees."""
    with (ELFS / "good.elf").open("rb") as file:
        elf = ELFFile(file)
        found = []
        for block in read_blocks(elf):
            comparison = compare_block(block, decode(code_at(elf, block.address, block.size), block.address))
            found += [message for _, message in comparison.mismatches]
            assert comparison.unsupported == []
    assert len(found) == 16
    assert all(message.startswith("stlxp w9, x8, x1, [x0]: annotation M[") for message in found)
    assert "stlxp w9, x8, x1, [x0]: annotation M[<X0>] <- X8, R M[<X0>] <- M[<X0>] | X8" in found


def block_of(words, forms):
    """A block of the instructions given by their encodings, annotated with forms, and its decoding."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    code = b"".join(word.to_bytes(4, "little") for word in words)
    insns = list(decoder.disasm(code, 0x1000))
    block = Block(0x1000, tuple(Group(4 * i, parse(form)) for i, form in enumerate(forms)))
    return block, insns


ADR_X13 = 0x100000AD  # adr x13, .+20
ADD_X13_X14 = 0x8B0E09AD  # add x13, x13, x14, lsl #2
DISPATCHES = [
    ("ldrh", [ADR_X13, 0x7868798E, ADD_X13_X14], "X14"),  # ldrh w14, [x12, x8, lsl #1]
    ("ldrb", [ADR_X13, 0x386B6949, 0x8B0909AD], "X9"),  # ldrb w9, [x10, x11]; add x13, x13, x9, lsl #2
    ("ldrsw", [ADR_X13, 0xB8AB7949, 0x8B0901AD], "X9"),  # ldrsw x9, [x10, x11, lsl #2]; add x13, x13, x9
]


@pytest.mark.parametrize(("words", "entry"), [d[1:] for d in DISPATCHES], ids=[d[0] for d in DISPATCHES])
def test_jump_table_load_is_a_constant(words, entry):
    """The compiler's dispatch: its entry load is compared with 'Ws <- 0', not with R's load."""
    block, insns = block_of(words, ["X13 <- 0", f"{entry} <- 0", f"X13 <- X13 | {entry}"])
    comparison = compare_block(block, insns)
    assert comparison.mismatches == []
    assert comparison.jump_table_loads == 1


@pytest.mark.parametrize(
    "words",
    [
        [ADR_X13, 0x7868798E, 0x8B0E09AF],  # the add writes x15, not the adr's x13
        [ADR_X13, 0x7868698E, ADD_X13_X14],  # ldrh w14, [x12, x8]: the index is not scaled
        [0x8B0E09AF, 0x7868798E, ADD_X13_X14],  # no adr before the load
    ],
    ids=["other-destination", "unscaled-index", "no-adr"],
)
def test_near_dispatch_is_an_ordinary_load(words):
    """Anything but the exact dispatch keeps R's rule: a 'Ws <- 0' on the load is a mismatch."""
    block, insns = block_of(words, ["X13 <- 0", "X14 <- 0", "X13 <- X13 | X14"])
    comparison = compare_block(block, insns)
    assert comparison.jump_table_loads == 0
    assert any(offset == 4 and message.startswith("ldrh w14") for offset, message in comparison.mismatches)


CORPUS = Path(__file__).parent.parent / "data" / "flips" / "corpus.json"


def test_r_fails_closed_on_the_corpus():
    """Every encoding of the corpus has a rule, or R names why it has none: nothing else is raised.
    The forms of a given HBNG binary R must have rules for are checked by 'insight check --against-r'."""
    ruled = 0
    for encodings in load_corpus(CORPUS).forms.values():
        for encoding in encodings:
            try:
                rule(insn_of(encoding))
                ruled += 1
            except UnsupportedFormError:
                pass
    assert ruled > 2000
