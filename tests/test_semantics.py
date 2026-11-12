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
    ("0841ca1a", "crc32b w8, w8, w10", "X8 <- X8 | X10"),
    ("2058c21a", "crc32cw w0, w1, w2", "X0 <- X1 | X2"),
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


# FP/SIMD loads and stores (byte for byte), moves and data processing. The texts follow the
# compiler's annotations where they agree with R.
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
    # lane-wise: lane i from lane i of every source (an element: the same one for every lane)
    ("2084a24e", "add v0.4s, v1.4s, v2.4s", "V0[0:15] <- V1[0:15] | V2[0:15] per 4"),
    ("2084a20e", "add v0.2s, v1.2s, v2.2s", "V0[0:7] <- V1[0:7] | V2[0:7] per 4\nV0[8:15] <- 0"),
    ("200c421f", "fmadd d0, d1, d2, d3", "V0[0:7] <- V1[0:7] | V2[0:7] | V3[0:7]\nV0[8:15] <- 0"),
    ("2094a24e", "mla v0.4s, v1.4s, v2.4s", "V0[0:15] <- V0[0:15] | V1[0:15] | V2[0:15] per 4"),
    ("20147d6f", "usra v0.2d, v1.2d, #3", "V0[0:15] <- V0[0:15] | V1[0:15] per 8"),
    (
        "2080a24f",
        "mul v0.4s, v1.4s, v2.s[1]",
        "\n".join(f"V0[{4 * i}:{4 * i + 3}] <- V1[{4 * i}:{4 * i + 3}] | V2[4:7]" for i in range(4)),
    ),
    ("200c621e", "fcsel d0, d1, d2, eq", "V0[0:7] <- V1[0:7] | V2[0:7]\nV0[8:15] <- 0"),
    ("2058200e", "cnt v0.8b, v1.8b", "V0[0:7] <- V1[0:7] per 1\nV0[8:15] <- 0"),
    # bitwise: byte for byte; x ^ x, x - x clear; orr and bic of an immediate set or clear the
    # bytes where it is all ones
    ("201c224e", "and v0.16b, v1.16b, v2.16b", "V0[0:15] <- V1[0:15] | V2[0:15] per 1"),
    ("2058202e", "mvn v0.8b, v1.8b", "V0[0:7] <- V1[0:7] per 1\nV0[8:15] <- 0"),
    ("201c216e", "eor v0.16b, v1.16b, v1.16b", "V0[0:15] <- 0"),
    ("2084a16e", "sub v0.4s, v1.4s, v1.4s", "V0[0:15] <- 0"),
    ("2034004f", "orr v0.4s, #1, lsl #8", ""),
    ("2014000f", "orr v0.2s, #1", "V0[8:15] <- 0"),
    ("e097076f", "bic v0.8h, #0xff", "\n".join(f"V0[{2 * i}] <- 0" for i in range(8))),
    # comparisons: clean, the sources 'excl'
    ("208ca26e", "cmeq v0.4s, v1.4s, v2.4s", "V0[0:15] <- 0 excl V1[0:15] | V2[0:15] per 4"),
    ("2098200e", "cmeq v0.8b, v1.8b, #0", "V0[0:7] <- 0 excl V1[0:7] per 1\nV0[8:15] <- 0"),
    ("0820601e", "fcmp d0, #0.0", ""),
    # selects and table lookups: the mask or the index 'excl'
    ("201c626e", "bsl v0.16b, v1.16b, v2.16b", "V0[0:15] <- V1[0:15] | V2[0:15] per 1 excl V0[0:15] per 1"),
    (
        "201ca22e",
        "bit v0.8b, v1.8b, v2.8b",
        "V0[0:7] <- V0[0:7] | V1[0:7] per 1 excl V2[0:7] per 1\nV0[8:15] <- 0",
    ),
    (
        "2020034e",
        "tbl v0.16b, {v1.16b, v2.16b}, v3.16b",
        "V0[0:15] <- V1[0:15] | V2[0:15] excl V3[0:15] per 1",
    ),
    ("0000030e", "tbl v0.8b, {v0.16b}, v3.8b", "V0[0:7] <- V0[0:15] excl V3[0:7] per 1\nV0[8:15] <- 0"),
    (
        "2010034e",
        "tbx v0.16b, {v1.16b}, v3.16b",
        "\n".join(f"V0[{k}] <- V0[{k}] | V1[0:15] excl V3[{k}]" for k in range(16)),
    ),
    # widening ('2': the upper half of the source), narrowing ('2': into the upper half); an
    # extension by whole bytes moves bytes, zeros or copies of the element's top byte above
    ("20a4132f", "ushll v0.4s, v1.4h, #3", "V0[0:15] <- V1[0:7] per 2:4"),
    ("20a4102f", "ushll v0.4s, v1.4h, #0", "V0[0:15] <- [V1[0:1] 0 0 V1[2:3] 0 0 V1[4:5] 0 0 V1[6:7] 0 0]"),
    (
        "20a4106f",
        "ushll2 v0.4s, v1.8h, #0",
        "V0[0:15] <- [V1[8:9] 0 0 V1[10:11] 0 0 V1[12:13] 0 0 V1[14:15] 0 0]",
    ),
    (
        "00a4086f",
        "ushll2 v0.8h, v0.16b, #0",
        "V0[0:15] <- [V0[8] 0 V0[9] 0 V0[10] 0 V0[11] 0 V0[12] 0 V0[13] 0 V0[14] 0 V0[15] 0]",
    ),
    (
        "20a4200f",
        "sshll v0.2d, v1.2s, #0",
        "V0[0:15] <- [V1[0:3] V1[3] V1[3] V1[3] V1[3:7] V1[7] V1[7] V1[7] V1[7]]",
    ),
    ("2038612e", "shll v0.4s, v1.4h, #16", "V0[0:15] <- [0 0 V1[0:1] 0 0 V1[2:3] 0 0 V1[4:5] 0 0 V1[6:7]]"),
    ("20c0a22e", "umull v0.2d, v1.2s, v2.2s", "V0[0:15] <- V1[0:7] | V2[0:7] per 4:8"),
    ("20e0220e", "pmull v0.8h, v1.8b, v2.8b", "V0[0:15] <- V1[0:7] | V2[0:7] per 1:2"),
    ("20e0e24e", "pmull2 v0.1q, v1.2d, v2.2d", "V0[0:15] <- V1[8:15] | V2[8:15] per 8:16"),
    (
        "2010222e",
        "uaddw v0.8h, v1.8h, v2.8b",
        "\n".join(f"V0[{2 * i}:{2 * i + 1}] <- V1[{2 * i}:{2 * i + 1}] | V2[{i}]" for i in range(8)),
    ),
    ("2028210e", "xtn v0.8b, v1.8h", "V0[0:7] <- V1[0:15] per 2:1\nV0[8:15] <- 0"),
    ("20943b5f", "sqshrn s0, d1, #5", "V0[0:3] <- V1[0:7] per 8:4\nV0[4:15] <- 0"),
    ("2028214e", "xtn2 v0.16b, v1.8h", "V0[8:15] <- V1[0:15] per 2:1"),
    # pairwise and reductions
    ("20bca24e", "addp v0.4s, v1.4s, v2.4s", "V0[0:7] <- V1[0:15] per 8:4\nV0[8:15] <- V2[0:15] per 8:4"),
    ("00bca10e", "addp v0.2s, v0.2s, v1.2s", "V0[0:3] <- V0[0:7]\nV0[4:7] <- V1[0:7]\nV0[8:15] <- 0"),
    ("20b8f15e", "addp d0, v1.2d", "V0[0:7] <- V1[0:15]\nV0[8:15] <- 0"),
    ("0028206e", "uaddlp v0.8h, v0.16b", "V0[0:15] <- V0[0:15] per 2"),
    ("0028600e", "saddlp v0.2s, v0.4h", "V0[0:7] <- V0[0:7] per 4\nV0[8:15] <- 0"),
    ("2068606e", "uadalp v0.4s, v1.8h", "V0[0:15] <- V0[0:15] | V1[0:15] per 4"),
    ("2038306e", "uaddlv h0, v1.16b", "V0[0:1] <- V1[0:15]\nV0[2:15] <- 0"),
    # scalar forms with an immediate (shifts, fixed-point conversions): one lane of 8 bytes
    ("2054435f", "shl d0, d1, #3", "V0[0:7] <- V1[0:7] per 8\nV0[8:15] <- 0"),
    ("20147b5f", "ssra d0, d1, #5", "V0[0:7] <- V0[0:7] | V1[0:7] per 8\nV0[8:15] <- 0"),
    ("2054477f", "sli d0, d1, #7", "V0[0:7] <- V0[0:7] | V1[0:7] per 8\nV0[8:15] <- 0"),
    ("2064437f", "sqshlu d0, d1, #3", "V0[0:7] <- V1[0:7] per 8\nV0[8:15] <- 0"),
    ("20e47d5f", "scvtf d0, d1, #3", "V0[0:7] <- V1[0:7] per 8\nV0[8:15] <- 0"),
    ("20fc7d5f", "fcvtzs d0, d1, #3", "V0[0:7] <- V1[0:7] per 8\nV0[8:15] <- 0"),
    # permutes: byte maps
    ("2038824e", "zip1 v0.4s, v1.4s, v2.4s", "V0[0:15] <- [V1[0:3] V2[0:3] V1[4:7] V2[4:7]]"),
    (
        "2018424e",
        "uzp1 v0.8h, v1.8h, v2.8h",
        "V0[0:15] <- [V1[0:1] V1[4:5] V1[8:9] V1[12:13] V2[0:1] V2[4:5] V2[8:9] V2[12:13]]",
    ),
    ("2068824e", "trn2 v0.4s, v1.4s, v2.4s", "V0[0:15] <- [V1[4:7] V2[4:7] V1[12:15] V2[12:15]]"),
    ("2018026e", "ext v0.16b, v1.16b, v2.16b, #3", "V0[0:15] <- [V1[3:15] V2[0:2]]"),
    ("2008206e", "rev32 v0.16b, v1.16b", "V0[0:15] <- [V1[3:0] V1[7:4] V1[11:8] V1[15:12]]"),
    ("2008600e", "rev64 v0.4h, v1.4h", "V0[0:7] <- [V1[6:7] V1[4:5] V1[2:3] V1[0:1]]\nV0[8:15] <- 0"),
    # conversions
    ("2000781e", "fcvtzs w0, d1", "X0 <- V1[0:7]"),
    ("2000629e", "scvtf d0, x1", "V0[0:7] <- X1\nV0[8:15] <- 0"),
    ("20c0221e", "fcvt d0, s1", "V0[0:7] <- V1[0:3]\nV0[8:15] <- 0"),
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
    with pytest.raises(UnsupportedFormError, match=r"aese v0\.16b, v1\.16b: FP/SIMD form without a rule"):
        rule(insn_of("2048284e"))


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
