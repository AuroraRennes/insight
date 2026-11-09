import pytest

from insight.dsl.errors import DslSyntaxError
from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.syntax import parse
from insight.dsl.terms import Term
from insight.dsl.transfer import Opaque

S0 = Term.sym("S0")
SP = Term.sym("<SP>")
X0 = Term.sym("<X0>")
X1 = Term.sym("<X1>")


def v(n, lo, hi=None):
    hi = lo if hi is None else hi
    step = 1 if lo <= hi else -1
    return [VByte(n, b) for b in range(lo, hi + step, step)]


def srcs(t, loc):
    return t.tags[loc].srcs


def excl(t, loc):
    return t.tags[loc].excl


# Statements, one form at a time
# \_______________________________


def test_load():
    t = parse("X0 <- M[<X1> + 8 .. +8]")
    assert srcs(t, Reg(0)) == {Mem(X1 + 8 + k) for k in range(8)}


def test_prologue():
    t = parse("M[<SP> - 16 .. +8] <- FP\nM[<SP> - 8 .. +8] <- LR\n<SP> <- <SP> - 16")
    assert set(t.tags) == {Mem(SP - 16 + k) for k in range(16)}
    assert srcs(t, Mem(SP - 16)) == {Reg(29)}
    assert srcs(t, Mem(SP - 1)) == {Reg(30)}
    assert t.values == {"SP": SP - 16}


def test_lanewise_and_top_clear():
    t = parse("V0[0:7] <- V1[0:7] | V2[0:7] per 4\nV0[8:15] <- 0")
    assert srcs(t, VByte(0, 5)) == set(v(1, 4, 7) + v(2, 4, 7))
    assert srcs(t, VByte(0, 12)) == frozenset()


def test_widening():
    t = parse("V0[0:15] <- V1[0:7] per 1:2")
    assert srcs(t, VByte(0, 0)) == srcs(t, VByte(0, 1)) == {VByte(1, 0)}
    assert srcs(t, VByte(0, 15)) == {VByte(1, 7)}


def test_ext_byte_map():
    t = parse("V0[0:15] <- [V1[3:15] V2[0:2]]")
    assert srcs(t, VByte(0, 0)) == {VByte(1, 3)}
    assert srcs(t, VByte(0, 12)) == {VByte(1, 15)}
    assert srcs(t, VByte(0, 13)) == {VByte(2, 0)}


def test_rev32_descending_ranges():
    t = parse("V0[0:15] <- [V1[3:0] V1[7:4] V1[11:8] V1[15:12]]")
    assert [next(iter(srcs(t, VByte(0, b)))) for b in range(4)] == v(1, 3, 0)
    assert srcs(t, VByte(0, 15)) == {VByte(1, 12)}


def test_byte_map_zeros():
    t = parse("V0[0:15] <- [V1[8:15] 0 0 0 0 0 0 0 0]")
    assert srcs(t, VByte(0, 7)) == {VByte(1, 15)}
    assert srcs(t, VByte(0, 8)) == frozenset()


def test_bsl_excludes_its_own_mask_byte():
    t = parse("V0[0:15] <- V1[0:15] | V2[0:15] per 1 excl V0[0:15] per 1")
    assert srcs(t, VByte(0, 3)) == {VByte(1, 3), VByte(2, 3)}
    assert excl(t, VByte(0, 3)) == {VByte(0, 3)}


def test_compare_excludes_its_own_element():
    t = parse("V0[0:15] <- 0 excl V1[0:15] | V2[0:15] per 4")
    assert srcs(t, VByte(0, 5)) == frozenset()
    assert excl(t, VByte(0, 5)) == set(v(1, 4, 7) + v(2, 4, 7))


def test_tbl_whole_table_own_index_byte():
    t = parse("V0[0:15] <- V1[0:15] excl V3[0:15] per 1")
    assert srcs(t, VByte(0, 9)) == set(v(1, 0, 15))
    assert excl(t, VByte(0, 9)) == {VByte(3, 9)}


def test_zero_with_per():
    t = parse("V0[0:15] <- 0 per 4")
    assert all(srcs(t, loc) == frozenset() for loc in v(0, 0, 15))


def test_ld2_strided():
    t = parse(
        "V0[0:15] <- M[<X0> .. +4 step 8 times 4] per 1\nV1[0:15] <- M[<X0> + 4 .. +4 step 8 times 4] per 1"
    )
    assert srcs(t, VByte(0, 0)) == {Mem(X0)}
    assert srcs(t, VByte(0, 4)) == {Mem(X0 + 8)}
    assert srcs(t, VByte(0, 15)) == {Mem(X0 + 27)}
    assert srcs(t, VByte(1, 0)) == {Mem(X0 + 4)}


def test_ld1r_step_zero():
    t = parse("V0[0:15] <- M[<X0> .. +4 step 0 times 4] per 1")
    assert srcs(t, VByte(0, 1)) == srcs(t, VByte(0, 5)) == srcs(t, VByte(0, 13)) == {Mem(X0 + 1)}


def test_st2_strided_destination():
    t = parse("M[<X0> .. +4 step 8 times 4] <- V0[0:15] per 1")
    assert srcs(t, Mem(X0 + 8)) == {VByte(0, 4)}
    assert Mem(X0 + 4) not in t.tags


def test_over():
    t = parse("V0[0:1] <- V1[0:1] per 1 over V1[1]")
    assert t.tags[VByte(0, 0)].over == frozenset()
    assert t.tags[VByte(0, 1)].over == {VByte(1, 1)}


# Values, sends, opaque statements
# \_________________________________


def test_values():
    t = parse("<SP> <- (<X9> & -64)\n<FP> <- <X29>")
    assert t.values == {"SP": Term.sym("<X9>") & -64, "FP": Term.sym("<X29>")}


def test_fp_reload_send_group():
    t = parse("send X29\n<FP> <- <X29>")
    assert t.sends == (Reg(29),)
    assert t.values == {"FP": Term.sym("<X29>")}


def test_send_aliases():
    assert parse("send FP\nsend X0").sends == (Reg(29), Reg(0))


def test_repeated_sends_keep_fifo_order():
    # ld4 {v0-v3}, [x0] today: stp x0, x0, [x18] twice, four FIFO entries.
    assert parse("send X0\nsend X0\nsend X0\nsend X0").sends == (Reg(0),) * 4
    # stp x29, x16, [x18]: x16 is emitted first.
    assert parse("send X16\nsend X29").sends == (Reg(16), Reg(29))


def test_tags_and_values_are_told_apart():
    t = parse("FP <- X29\n<FP> <- <SP> + 16")
    assert srcs(t, Reg(29)) == {Reg(29)}
    assert t.values == {"FP": SP + 16}


def test_opaque():
    assert parse("svc").opaque == (Opaque("svc"),)
    assert parse('unsupported "UMLALv8i16_v4i32"').opaque == (Opaque("unsupported", "UMLALv8i16_v4i32"),)


def test_sp_tag_and_aliases():
    t = parse("SP <- X9  # realignment\nFP <- SP\nLR <- 0")
    assert srcs(t, Reg(31)) == {Reg(9)}
    assert srcs(t, Reg(29)) == {Reg(31)}
    assert srcs(t, Reg(30)) == frozenset()


def test_terms_in_addresses():
    t = parse("X0 <- M[<X1> + ext(<X2>, sxtw, 2)]\nX3 <- M[(S0 & -64) + 2*S1 - 8]")
    assert Mem(X1 + Term.sym("<X2>").ext("sxtw", 2)) in srcs(t, Reg(0))
    assert Mem((S0 & -64) + 2 * Term.sym("S1") - 8) in srcs(t, Reg(3))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("X1 <- X2\nX1 <- X3", "written twice"),
        ("V0[0:15] <- V1[0:7] per 4", "elements"),
        ("V0[0:3] <- [V1[0] V1[1]]", "byte map of 2 for 4"),
        ("X1 <- X2 over X3", "not sources"),
        ("X31 <- X0", "expected a location"),
        ("V0[3:1] <- 0", "bad byte range"),
        ("V0[0:3] <- V1[3:0] per 1", "bad byte range"),
        ("X0 <- M[S0 * S1]", "two non-constant"),
        ("X0 <- M[X1]", "unexpected 'X1' in a term"),
        ("X0 <- M[SP0]", "unexpected 'SP0' in a term"),
        ("<SP> <- <SP>\n<SP> <- <FP>", "written twice"),
        ("SP := <SP>", "unexpected '= <SP>'"),
        ("X0 <- X1 X2", "unexpected 'X2'"),
        ("X0 <- M[<X1> .. +4 step 8]", "expected 'times'"),
        ("X0 <- M[<X1> .. +4 step 8 times 0]", "bad stride"),
        ("send SP", "expected send X<n>"),
        ("svc\nX0 <- 0", "must stand alone"),
        ('X0 <- X1\nunsupported "TBXv16i8One"', "must stand alone"),
    ],
)
def test_errors(text, message):
    with pytest.raises(DslSyntaxError, match=message):
        parse(text)
