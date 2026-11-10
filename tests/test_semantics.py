"""R on general-register instructions: each rule against the transfer written in the DSL."""

from pathlib import Path

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

from insight.annotations.against_r import compare_block, differences
from insight.annotations.framing import read_blocks
from insight.annotations.pairing import code_at, decode
from insight.dsl.syntax import parse
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


def test_unsupported_fails_closed():
    with pytest.raises(UnsupportedFormError, match="fmov d0, x1"):
        rule(insn_of("2000679e"))


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
