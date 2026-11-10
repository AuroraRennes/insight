import pytest

from insight.annotations.framing import read_block
from insight.annotations.pairing import decode
from insight.annotations.sendcheck import check_sends, instruction_sends

ENCODINGS = {
    "str x0, [x18]": "400200f9",
    "stp x1, x0, [x18]": "410200a9",
    "str w0, [x18]": "400200b9",
    "str x0, [x18, #8]": "400600f9",
    "str x0, [x18], #8": "408600f8",
    "ldr x0, [x18]": "400240f9",
    "mov x18, x0": "f20300aa",
    "str x0, [x1]": "200000f9",
    "stp x29, x30, [sp, #-16]!": "fd7bbfa9",
    "ldr x0, [x0]": "000040f9",
    "stp xzr, x0, [x18]": "5f0200a9",
}


def code(*instructions: str):
    return decode(bytes.fromhex("".join(ENCODINGS[each] for each in instructions)), 0x1000)


@pytest.mark.parametrize(
    ("instruction", "sends"),
    [
        ("str x0, [x18]", (0,)),
        ("stp x1, x0, [x18]", (0, 1)),  # the second register is emitted first
        ("stp xzr, x0, [x18]", (0, 31)),  # the zero register as an offset
        ("str x0, [x1]", ()),
        ("stp x29, x30, [sp, #-16]!", ()),
        ("ldr x0, [x0]", ()),
        ("str w0, [x18]", None),
        ("str x0, [x18, #8]", None),
        ("str x0, [x18], #8", None),
        ("ldr x0, [x18]", None),
        ("mov x18, x0", None),
    ],
)
def test_instruction_sends(instruction, sends):
    (insn,) = code(instruction)
    assert instruction_sends(insn) == sends


def test_matching_sends():
    block = read_block("@0\nsend X0\nsend X1\n@4\nsend X0\n@8\nX0 <- M[<X0> .. +8]\nEND\n", 0x1000)
    assert check_sends(block, code("stp x1, x0, [x18]", "str x0, [x18]", "ldr x0, [x0]")) == []


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("@0\nEND\n", "str x0, [x18] makes send X0, the group lists no send"),
        ("@0\nsend X1\nEND\n", "str x0, [x18] makes send X0, the group lists send X1"),
        ("@0\nsend X0\nsend X0\nEND\n", "str x0, [x18] makes send X0, the group lists send X0, send X0"),
    ],
)
def test_send_lines_must_match_the_store(text, message):
    issues = check_sends(read_block(text, 0x1000), code("str x0, [x18]"))
    assert issues == [(0, message)]


def test_zero_register_send():
    block = read_block("@0\nsend X0\nsend XZR\nEND\n", 0x1000)
    assert check_sends(block, code("stp xzr, x0, [x18]")) == []
    block = read_block("@0\nsend X0\nEND\n", 0x1000)
    assert check_sends(block, code("stp xzr, x0, [x18]")) == [
        (0, "stp xzr, x0, [x18] makes send X0, send XZR, the group lists send X0")
    ]


def test_pair_order_matters():
    block = read_block("@0\nsend X1\nsend X0\nEND\n", 0x1000)
    assert check_sends(block, code("stp x1, x0, [x18]")) == [
        (0, "stp x1, x0, [x18] makes send X0, send X1, the group lists send X1, send X0")
    ]


def test_no_send_line_without_a_send():
    block = read_block("@0\nsend X0\nX0 <- M[<X0> .. +8]\nEND\n", 0x1000)
    assert check_sends(block, code("ldr x0, [x0]")) == [
        (0, "ldr x0, [x0] makes no send, the group lists send X0")
    ]


def test_other_uses_of_x18():
    block = read_block("@0\n@4\nEND\n", 0x1000)
    issues = check_sends(block, code("str w0, [x18]", "mov x18, x0"))
    assert [offset for offset, _ in issues] == [0, 4]
    assert all("accesses or writes x18" in message for _, message in issues)


def test_instruction_count_must_match():
    with pytest.raises(ValueError, match="1 instructions for 2 groups"):
        check_sends(read_block("@0\n@4\nEND\n", 0x1000), code("ldr x0, [x0]"))
