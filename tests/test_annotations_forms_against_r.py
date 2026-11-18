from insight.annotations.against_r import compare_block
from insight.annotations.framing import Entry, read_block
from insight.annotations.pairing import decode
from insight.annotations.sendcheck import check_sends

PAGE = 0x400000

ENCODINGS = {
    "adrp x16, 0x400000": "f01f00f0",  # at 0x1000: the channel page
    "str x0, [x16]": "000200f9",
    "str x3, [x16]": "030200f9",
    "stp x1, x0, [x16]": "010200a9",
    "ldr x0, [x0]": "000040f9",
    "str x1, [x0]": "010000f9",
    "ldr x2, [x3]": "620040f9",
    "add x29, sp, #16": "fd430091",
    "ldr x29, [sp]": "fd0340f9",
    "str x29, [x16]": "1d0200f9",
    "ldr x0, [x29, #8]": "a00740f9",
}


def code(*instructions: str):
    return decode(bytes.fromhex("".join(ENCODINGS[each] for each in instructions)), 0x1000)


def check(text: str, *instructions: str, sends: tuple[int, ...] = ()) -> list[tuple[int, str]]:
    """The send check's issues, then the comparison with R's; sends are the table's indices."""
    insns = code(*instructions)
    block = read_block(text, 0x1000, Entry(0x1000, 0, len(insns), sends))
    found = check_sends(block, insns, PAGE)
    return found.issues + compare_block(block, insns, found.sends).mismatches


SENDS = ("adrp x16, 0x400000", "stp x1, x0, [x16]", "str x0, [x16]", "ldr x0, [x0]")
SENT = "@0\nsend X0\nsend X1\nsend X0\nX16 <- 0\nX0 <- M[S2 .. +8]\nEND\n"


def test_block_form_against_r():
    assert check(SENT, *SENDS, sends=(1, 1, 2)) == []


def test_block_form_differs_from_r():
    (issue,) = check(SENT.replace("S2", "S0"), *SENDS, sends=(1, 1, 2))
    assert issue[0] == 0
    assert "4 instructions: annotation X0 <- M[S0" in issue[1]


ALIASING = ("adrp x16, 0x400000", "str x0, [x16]", "str x3, [x16]", "str x1, [x0]", "ldr x2, [x3]")


def test_undecided_aliasing_must_be_split():
    text = "@0\nsend X0\nsend X3\nX16 <- 0\nM[S0 .. +8] <- X1\nX2 <- M[S1 .. +8]\nEND\n"
    ((offset, message),) = check(text, *ALIASING, sends=(1, 2))
    assert offset == 0
    assert message.startswith("R over 5 instructions: cannot decide whether M[S1")


def test_fp_follows_the_compiler_convention():
    # add x29, sp, #16 computes FP; ldr x0, [x29, #8] reads through it.
    assert (
        check(
            "@0\nX29 <- SP\nX0 <- M[<SP> + 24 .. +8]\n<FP> <- <SP> + 16\nEND\n",
            "add x29, sp, #16",
            "ldr x0, [x29, #8]",
        )
        == []
    )
    # Without the FP update, the load's address differs.
    issues = check("@0\nX29 <- SP\nX0 <- M[<FP> + 8 .. +8]\nEND\n", "add x29, sp, #16", "ldr x0, [x29, #8]")
    assert any("<FP> <- <SP> + 16" in message for _, message in issues)


RELOAD = ("adrp x16, 0x400000", "ldr x29, [sp]", "str x29, [x16]")


def test_fp_given_by_its_send():
    # A reload of x29 leaves FP until its send gives it.
    text = "@0\nsend X29\nX16 <- 0\nX29 <- M[<SP> .. +8]\n<FP> <- S0\nEND\n"
    assert check(text, *RELOAD, sends=(2,)) == []
    issues = check("@0\nsend X29\nX16 <- 0\nX29 <- M[<SP> .. +8]\nEND\n", *RELOAD, sends=(2,))
    assert any("R <FP> <- S0" in message for _, message in issues)
