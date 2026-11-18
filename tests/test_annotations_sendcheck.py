import pytest

from insight.annotations.framing import Entry, read_block
from insight.annotations.pairing import decode
from insight.annotations.sendcheck import check_sends, send_shape

PAGE = 0x400000

ENCODINGS = {
    "adrp x16, 0x400000": "f01f00f0",  # at 0x1000: the channel page
    "adrp x16, 0x401000": "30200090",  # at 0x1000: another page
    "str x0, [x16]": "000200f9",
    "stp x1, x0, [x16]": "010200a9",
    "stp xzr, x0, [x16]": "1f0200a9",
    "str w0, [x16]": "000200b9",
    "str x0, [x16, #8]": "000600f9",
    "str x0, [x16], #8": "008600f8",
    "ldr x0, [x16]": "000240f9",
    "ldr x16, [sp, #8]": "f00740f9",
    "mov x16, x1": "f00301aa",
    "add x16, x1, #8": "30200091",
    "ldr x0, [x0]": "000040f9",
    "stp x29, x30, [sp, #-16]!": "fd7bbfa9",
}


def code(*instructions: str):
    return decode(bytes.fromhex("".join(ENCODINGS[each] for each in instructions)), 0x1000)


@pytest.mark.parametrize(
    ("instruction", "shape"),
    [
        ("str x0, [x16]", (16, (0,))),
        ("stp x1, x0, [x16]", (16, (0, 1))),  # the second register reaches the channel first
        ("stp xzr, x0, [x16]", None),  # the zero register is never sent
        ("str w0, [x16]", None),
        ("str x0, [x16, #8]", None),
        ("str x0, [x16], #8", None),
        ("ldr x0, [x16]", None),
        ("stp x29, x30, [sp, #-16]!", None),
    ],
)
def test_send_shape(instruction, shape):
    (insn,) = code(instruction)
    assert send_shape(insn) == shape


def test_sends_through_the_page():
    block = read_block(
        "@0\nX16 <- 0\n@4\nsend X0\nsend X1\n@8\nsend X0\n@12\nX0 <- M[<X0> .. +8]\nEND\n", 0x1000
    )
    result = check_sends(
        block, code("adrp x16, 0x400000", "stp x1, x0, [x16]", "str x0, [x16]", "ldr x0, [x0]"), PAGE
    )
    assert (result.issues, result.sends, dict(result.origins)) == ([], {1, 2}, {})


def test_a_store_without_send_lines_is_memory():
    block = read_block("@0\nM[<X16> .. +8] <- X0\nEND\n", 0x1000)
    result = check_sends(block, code("str x0, [x16]"), PAGE)
    assert (result.issues, result.sends) == ([], set())


@pytest.mark.parametrize(
    ("before", "origin"),
    [
        ((), "from entry"),
        (("ldr x16, [sp, #8]",), "reloaded from the stack"),
        (("mov x16, x1",), "copied by a mov"),
    ],
)
def test_page_not_followed_is_counted(before, origin):
    text = "".join(f"@{4 * i}\n" for i in range(len(before))) + f"@{4 * len(before)}\nsend X0\nEND\n"
    result = check_sends(read_block(text, 0x1000), code(*before, "str x0, [x16]"), PAGE)
    assert (result.issues, dict(result.origins)) == ([], {origin: 1})


@pytest.mark.parametrize(
    "before",
    ["adrp x16, 0x401000", "add x16, x1, #8"],
)
def test_base_must_hold_the_page(before):
    block = read_block("@0\n@4\nsend X0\nEND\n", 0x1000)
    result = check_sends(block, code(before, "str x0, [x16]"), PAGE)
    assert result.issues == [(4, "str x0, [x16]: x16 does not hold the channel page")]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("@0\nsend X1\nEND\n", "str x0, [x16] makes send X0, the group lists send X1"),
        ("@0\nsend X0\nsend X0\nEND\n", "str x0, [x16] makes send X0, the group lists send X0, send X0"),
    ],
)
def test_send_lines_must_match_the_store(text, message):
    result = check_sends(read_block(text, 0x1000), code("str x0, [x16]"), PAGE)
    assert result.issues == [(0, message)]


def test_zero_register_is_not_sent():
    block = read_block("@0\nsend X0\nEND\n", 0x1000)
    assert check_sends(block, code("stp xzr, x0, [x16]"), PAGE).issues == [
        (0, "stp xzr, x0, [x16]: lists send X0 but is not a send")
    ]


def test_pair_order_matters():
    block = read_block("@0\nsend X1\nsend X0\nEND\n", 0x1000)
    assert check_sends(block, code("stp x1, x0, [x16]"), PAGE).issues == [
        (0, "stp x1, x0, [x16] makes send X0, send X1, the group lists send X1, send X0")
    ]


def test_send_lines_on_something_else():
    block = read_block("@0\nsend X0\nX0 <- M[<X0> .. +8]\nEND\n", 0x1000)
    assert check_sends(block, code("ldr x0, [x0]"), PAGE).issues == [
        (0, "ldr x0, [x0]: lists send X0 but is not a send")
    ]


def test_instruction_count_must_match():
    with pytest.raises(ValueError, match="1 instructions for a block of 2"):
        check_sends(read_block("@0\n@4\nEND\n", 0x1000), code("ldr x0, [x0]"), PAGE)


FORM = code("adrp x16, 0x400000", "stp x1, x0, [x16]", "str x0, [x16]", "ldr x0, [x0]")


def form(sends: str, at: tuple[int, ...]):
    """The block of FORM as one form, its sends at the instructions the block table gives."""
    return read_block(f"@0\n{sends}END\n", 0x1000, Entry(0x1000, 0, 4, at))


def test_form_sends():
    result = check_sends(form("send X0\nsend X1\nsend X0\n", (1, 1, 2)), FORM, PAGE)
    assert (result.issues, result.sends) == ([], {1, 2})


def test_form_sends_must_match_their_store():
    result = check_sends(form("send X1\nsend X0\nsend X0\n", (1, 1, 2)), FORM, PAGE)
    assert result.issues == [(4, "stp x1, x0, [x16]: named by send X1, send X0, sends send X0, send X1")]


def test_form_send_at_something_else():
    result = check_sends(form("send X0\nsend X1\nsend X0\n", (1, 1, 3)), FORM, PAGE)
    assert result.issues == [(12, "ldr x0, [x0]: named by send X0, sends no send")]


def test_form_sends_in_order():
    result = check_sends(form("send X0\nsend X0\nsend X1\n", (2, 1, 1)), FORM, PAGE)
    assert result.issues == [(0, "the sends are not in the order of their instructions")]
