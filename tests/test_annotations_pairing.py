import pytest

from insight.annotations.framing import read_block
from insight.annotations.pairing import PairingError, decode, pair_sends, register_writes
from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.syntax import parse
from insight.dsl.terms import Term
from tests.annotation_fixtures import FIXTURES, fixture_blocks, fixture_files

S = [Term.sym(f"S{i}") for i in range(8)]
NONE = frozenset[int]()


def pair(text, writes=None):
    block = read_block(text, 0x400)
    return pair_sends(block, writes or [NONE] * len(block.groups))


def form(text):
    return parse(text)


@pytest.mark.parametrize("path", fixture_files(), ids=lambda path: path.stem)
def test_every_fixture_value_has_a_send(path):
    for block in fixture_blocks(path).values():
        paired = pair_sends(block, [NONE] * len(block.groups))
        assert not any(sym.is_register for each in paired.forms for sym in each.symbols())


def test_preceding_send():
    paired = pair("@0\nsend X0\n@4\nX0 <- M[<X0> .. +8]\n@8\nEND\n")
    assert paired.forms[1].same_meaning(form("X0 <- M[S0 .. +8]"))
    assert [(send.index, send.group, send.reg) for send in paired.sends] == [(0, 0, Reg(0))]


def test_sends_are_numbered_over_the_block():
    paired = pair(
        "@0\nsend X1\nsend X0\n@4\nX2 <- M[<X0> + ext(<X1>, sxtw, 2)]\n@8\nsend X3\n@12\nX4 <- M[<X3>]\nEND\n"
    )
    assert paired.forms[1].same_meaning(form("X2 <- M[S1 + ext(S0, sxtw, 2)]"))
    assert paired.forms[3].same_meaning(form("X4 <- M[S2]"))


def test_repeated_sends_pair_with_the_last():
    block = fixture_blocks(FIXTURES / "hbng-neon-ldst.annot")["HBNG_ld4"]
    paired = pair_sends(block, [NONE] * len(block.groups))
    assert len(paired.sends) == 4
    assert paired.forms[2].dep(VByte(0, 1)).srcs == {Mem(S[3] + 4)}  # the last send: S3


def test_send_and_value_in_the_same_group():
    paired = pair("@0\nsend X29\n<FP> <- <X29>\n@4\nEND\n")
    assert paired.forms[0].value("FP") == S[0]


def test_a_linker_offset_needs_no_send():
    # send x8; ldr x0, [x8, :lo12:sym]
    paired = pair("@0\nsend X8\n@4\nX0 <- M[<X8> + LO12 .. +8]\nEND\n")
    assert paired.forms[1].same_meaning(form("X0 <- M[S0 + LO12 .. +8]"))


def test_a_write_in_between_breaks_the_pairing():
    # send x1; ldr x8, [x1], #8 (writes x1 back); a use of <X1>
    text = "@0\nsend X1\n@4\nX8 <- M[<X1> .. +8]\n@8\nX0 <- M[<X1>]\nEND\n"
    with pytest.raises(PairingError, match=r"@8: <X1>"):
        pair(text, [NONE, frozenset({1, 8}), NONE])
    assert pair(text, [NONE, frozenset({8}), NONE]).forms[2].same_meaning(form("X0 <- M[S0]"))


def test_the_using_instruction_may_write_its_register_after_a_preceding_send():
    paired = pair("@0\nsend X0\n@4\nX0 <- M[<X0> .. +8]\nEND\n", [NONE, frozenset({0})])
    assert paired.forms[1].same_meaning(form("X0 <- M[S0 .. +8]"))


def test_store_exclusive_pairs_with_the_following_send():
    block = fixture_blocks(FIXTURES / "hbng-exclusive.annot")["HBNG_cas128_n_2"]
    paired = pair_sends(block, [frozenset({9}), NONE, NONE])  # stlxp w9, x8, x1, [x0]
    assert paired.forms[0].dep(Mem(S[0])).srcs == {Reg(8)}
    assert paired.forms[0].dep(Mem(S[0] + 8)).srcs == {Reg(1)}


def test_preceding_send_wins_over_a_following_one():
    block = fixture_blocks(FIXTURES / "hbng-loads-stores.annot")["HBNG_excl_add_n_1"]
    writes = [NONE, frozenset({0}), frozenset({9}), frozenset({10}), NONE, NONE]
    paired = pair_sends(block, writes)
    assert [send.group for send in paired.sends] == [0, 4]
    assert paired.forms[3].dep(Mem(S[0])).srcs == {Reg(9)}


def test_following_send_after_a_write_of_the_register():
    with pytest.raises(PairingError, match=r"@0: <X0>"):
        pair("@0\nX0 <- M[<X0> .. +8]\n@4\nsend X0\nEND\n", [frozenset({0}), NONE])


def test_no_send():
    with pytest.raises(PairingError, match="no send of X5"):
        pair("@0\nX0 <- M[<X5>]\nEND\n")


def test_sp_values_from_a_sent_register():
    block = fixture_blocks(FIXTURES / "hbng-sp-fp.annot")["HBNG_realign"]
    paired = pair_sends(block, [NONE] * len(block.groups))
    assert paired.forms[4].value("SP") == S[0] & -64


def test_writes_count_must_match():
    with pytest.raises(ValueError, match="1 instructions for 2 groups"):
        pair_sends(read_block("@0\n@4\nEND\n", 0x400), [NONE])


@pytest.mark.parametrize(
    ("encoding", "written"),
    [
        ("000040f9", {0}),  # ldr x0, [x0]
        ("288440f8", {8, 1}),  # ldr x8, [x1], #8
        ("288c40f8", {8, 1}),  # ldr x8, [x1, #8]!
        ("09fd0ac8", {10}),  # stlxr w10, x9, [x8]
        ("088429c8", {9}),  # stlxp w9, x8, x1, [x0]
        ("fd7bc1a8", {29, 30}),  # ldp x29, x30, [sp], #16
        ("608ac14c", {19}),  # ld2 {v0.4s, v1.4s}, [x19], x1
        ("e803002a", {8}),  # mov w8, w0
        ("400200f9", set()),  # str x0, [x18]
        ("410200a9", set()),  # stp x1, x0, [x18]
        ("e9079f1a", {9}),  # cset w9, ne
        ("010000d4", {0}),  # svc #0
        ("00000094", {*range(18), 30}),  # bl
    ],
)
def test_register_writes(encoding, written):
    (insn,) = decode(bytes.fromhex(encoding), 0x1000)
    assert register_writes(insn) == written


def test_decode_rejects_partial_code():
    with pytest.raises(ValueError, match="cannot decode"):
        decode(bytes.fromhex("000040f9ffffffff"), 0x1000)
