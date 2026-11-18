import pytest

from insight.dsl.errors import AliasUndecidedError, InstructionFormError, OpaqueError
from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.syntax import parse
from insight.dsl.terms import Sym, Term
from insight.dsl.transfer import Dep, Opaque, Transfer, compose

SP = Term.sym("<SP>")
S0 = Term.sym("S0")


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


# Composition
# \____________


def test_simultaneous_assignment():
    swap = parse("X0 <- X1\nX1 <- X0")  # both sources read at the entry
    assert swap.then(swap).same_meaning(Transfer())


def test_registers_compose():
    t = parse("X0 <- 0").then(parse("X1 <- X0 | X2"))
    assert t.dep(Reg(1)).srcs == {Reg(2)}
    assert t.dep(Reg(0)).srcs == frozenset()


def test_prologue_epilogue():
    # stp x29, x30, [sp, #-16]! ; ldp x29, x30, [sp], #16
    stp = parse("M[<SP> - 16 .. +8] <- FP\nM[<SP> - 8 .. +8] <- LR\n<SP> <- <SP> - 16")
    ldp = parse("FP <- M[<SP> .. +8]\nLR <- M[<SP> + 8 .. +8]\n<SP> <- <SP> + 16")
    t = stp.then(ldp)
    assert t.value("SP") == SP
    assert t.dep(Reg(29)).srcs == {Reg(29)}
    assert t.dep(Reg(30)).srcs == {Reg(30)}
    # The saved bytes are still written by the block.
    assert t.dep(Mem(SP - 16)).srcs == {Reg(29)}
    assert set(t.normalized().tags) == {Mem(SP - 16 + k) for k in range(16)}


def test_sp_rebases_the_second_transfer():
    t = parse("<SP> <- <SP> - 32").then(parse("X0 <- M[<SP> + 8]"))
    assert t.dep(Reg(0)).srcs == {Mem(SP - 24)}


def test_store_then_load_same_byte():
    t = parse("M[S0 + 4] <- X1").then(parse("X2 <- M[S0 + 4] | M[S0 + 5]"))
    assert t.dep(Reg(2)).srcs == {Reg(1), Mem(S0 + 5)}


def test_store_overwritten_by_later_store():
    t = parse("M[S0] <- X1").then(parse("M[S0] <- X2"))
    assert t.dep(Mem(S0)).srcs == {Reg(2)}


def test_distinct_stack_slots():
    t = parse("M[<SP> - 16] <- X1").then(parse("X2 <- M[<SP> - 32]\nM[<SP> - 8] <- X3"))
    assert t.dep(Reg(2)).srcs == {Mem(SP - 32)}
    assert t.dep(Mem(SP - 16)).srcs == {Reg(1)}


def test_undecided_alias_fails():
    with pytest.raises(AliasUndecidedError):
        parse("M[S0] <- X1").then(parse("X2 <- M[S1]"))
    with pytest.raises(AliasUndecidedError):
        parse("M[S0] <- X1").then(parse("M[S1] <- X2"))


def test_alias_decided_by_constant_difference_only():
    # The same bits, but not a constant apart: undecided.
    with pytest.raises(AliasUndecidedError):
        parse("M[ext(S0, uxtw, 0)] <- X1").then(parse("X2 <- M[(S0 & 0xffffffff)]"))
    with pytest.raises(AliasUndecidedError):
        parse("M[S0] <- X1").then(parse("X2 <- M[<SP> - 8]"))


def test_over_and_excl_propagate():
    first = parse("V0[0:1] <- V1[0:1] | V2[0:1] over V2[0:1]\nX3 <- X4")
    second = parse("X5 <- V0[0] | X6\nX7 <- 0 excl X3")
    t = first.then(second)
    dep = t.dep(Reg(5))
    assert dep.srcs == {VByte(1, 0), VByte(1, 1), VByte(2, 0), VByte(2, 1), Reg(6)}
    assert dep.over == {VByte(2, 0), VByte(2, 1)}
    assert t.dep(Reg(7)) == Dep(frozenset(), frozenset({Reg(4)}))


def test_source_both_exact_and_over_is_exact():
    first = parse("X1 <- X9 | X8 over X9\nX2 <- X9")
    t = first.then(parse("X0 <- X1 | X2"))
    assert t.dep(Reg(0)).over == frozenset()


def test_composition_is_associative():
    a = parse("M[<SP> - 8 .. +8] <- X0\n<SP> <- <SP> - 16\nX1 <- X2 | X3")
    b = parse("X3 <- M[<SP> + 8 .. +8]\nV0[0:3] <- X3")
    c = parse("M[<SP> + 8 .. +4] <- V0[0:3] per 1\n<SP> <- <SP> + 16\nX0 <- X1")
    left = a.then(b).then(c)
    right = a.then(b.then(c))
    assert left.same_meaning(right)
    assert compose([a, b, c]).same_meaning(left)


def test_instruction_form_is_not_composed():
    with pytest.raises(InstructionFormError):
        parse("X0 <- M[<X1>]").then(Transfer())


def test_opaque_is_not_composed():
    with pytest.raises(OpaqueError):
        parse("svc").then(Transfer())
    with pytest.raises(OpaqueError):
        Transfer().then(parse('unsupported "TBXv16i8One"'))


def test_sends_are_not_composed():
    with pytest.raises(InstructionFormError, match="pair the sends"):
        parse("send X0").then(Transfer())


def test_fp_reload_once_paired():
    # ldp x29, x30, [sp], #16 ; str x29, [x18] (send X29, then <FP> <- <X29>), paired as S0.
    ldp = parse("FP <- M[<SP> .. +8]\nLR <- M[<SP> + 8 .. +8]\n<SP> <- <SP> + 16")
    send = parse("<FP> <- S0")
    t = ldp.then(send)
    assert t.value("FP") == Term.sym("S0")
    assert t.value("SP") == SP + 16
    assert t.dep(Reg(29)).srcs == {Mem(SP + k) for k in range(8)}


def test_tracked_fp_is_not_the_register():
    with pytest.raises(InstructionFormError, match="<X29>"):
        parse("<FP> <- <X29>").then(Transfer())
    t = parse("<FP> <- <SP> + 16").then(parse("X0 <- M[<FP> - 8]"))
    assert t.dep(Reg(0)).srcs == {Mem(SP + 8)}
