import pytest

from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.syntax import parse
from insight.dsl.terms import Sym, Term
from insight.dsl.transfer import Dep, Opaque, Transfer

SP = Term.sym("<SP>")


def test_identity_entries_do_not_matter():
    assert parse("X1 <- X1").same_meaning(Transfer())
    assert parse("<SP> <- <SP>").same_meaning(Transfer())
    assert not parse("X1 <- X1 | X2").same_meaning(Transfer())
    assert not parse("X1 <- 0").same_meaning(Transfer())


def test_keep_overwrite_clear():
    t = parse("X1 <- X1 | X2\nX2 <- X3\nX3 <- 0")
    assert Reg(1) in t.dep(Reg(1)).srcs  # keeps
    assert Reg(2) not in t.dep(Reg(2)).srcs  # overwritten
    assert t.dep(Reg(3)).srcs == frozenset()  # cleared
    assert t.dep(Reg(4)).srcs == {Reg(4)}  # unwritten: kept


def test_values_default_to_entry():
    t = parse("<SP> <- <SP> - 16")
    assert t.value("SP") == SP - 16
    assert t.value("FP") == Term.sym("<FP>")


def test_spelling_does_not_matter():
    lanes = parse("V0[0:3] <- V1[0:3] | V2[0:3] per 1")
    bytes_ = parse("\n".join(f"V0[{b}] <- V1[{b}] | V2[{b}]" for b in range(4)))
    assert lanes.same_meaning(bytes_)
    assert parse("M[<SP> - 8 .. +2] <- X0").same_meaning(parse("M[<SP> - 7] <- X0\nM[<SP> - 8] <- X0"))
    assert parse("FP <- LR").same_meaning(parse("X29 <- X30"))


def test_addresses_compare_by_canonical_form():
    assert parse("X0 <- M[<SP> + 8 - 16]").same_meaning(parse("X0 <- M[<SP> - 8]"))
    assert not parse("X0 <- M[<SP> - 8]").same_meaning(parse("X0 <- M[<FP> - 8]"))


def test_sends_and_opaque_are_part_of_the_meaning():
    assert not parse("send X0").same_meaning(Transfer())
    assert parse("send X0").sends == (Reg(0),)
    assert not parse("send X0").same_meaning(parse("send X0\nsend X0"))
    assert not parse("send X0\nsend X1").same_meaning(parse("send X1\nsend X0"))
    assert parse("svc").opaque == (Opaque("svc"),)
    assert not parse("svc").same_meaning(parse('unsupported "TBXv16i8One"'))


def test_excl_and_over_are_part_of_the_meaning():
    plain = parse("V0[0] <- V1[0] | V2[0]")
    assert not plain.same_meaning(parse("V0[0] <- V1[0] | V2[0] excl V3[0]"))
    assert not plain.same_meaning(parse("V0[0] <- V1[0] | V2[0] over V2[0]"))
    assert parse("V0[0] <- V1[0] | V2[0] over V2[0]").dep(VByte(0, 0)).over == {VByte(2, 0)}


def test_memory_bytes_are_separate_locations():
    t = parse("M[<SP> - 16 .. +8] <- FP")
    assert set(t.tags) == {Mem(SP - 16 + k) for k in range(8)}


def test_over_must_be_sources():
    with pytest.raises(ValueError, match="not sources"):
        Dep(frozenset({Reg(1)}), over=frozenset({Reg(2)}))


def test_symbols():
    t = parse("X0 <- M[<X1> + 8]\nM[S0] <- X2\n<SP> <- <SP> - 16\nX3 <- M[GLOBAL + 64]")
    assert {str(sym) for sym in t.symbols()} == {"<X1>", "S0", "<SP>", "GLOBAL"}


def test_subst_replaces_addresses_and_values():
    t = parse("X0 <- M[<X1> + 8] excl M[<X1>]\nM[<X1> + 16] <- X2\n<FP> <- <X1>")
    paired = t.subst({Sym("<X1>"): Term.sym("S3")})
    assert paired.same_meaning(parse("X0 <- M[S3 + 8] excl M[S3]\nM[S3 + 16] <- X2\n<FP> <- S3"))


def test_subst_refuses_to_merge_two_written_locations():
    with pytest.raises(ValueError, match="written twice"):
        parse("M[<X1>] <- X0\nM[S0] <- X2").subst({Sym("<X1>"): Term.sym("S0")})
