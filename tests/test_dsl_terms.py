import pytest

from insight.dsl.terms import MASK, Sym, Term

S0 = Term.sym("S0")
S1 = Term.sym("S1")
SP = Term.sym("<SP>")


def test_canonical_linear_form():
    assert S0 + 8 - 8 == S0
    assert 2 * S0 - S0 == S0
    assert S0 + S1 == S1 + S0
    assert (S0 - S0).is_const
    assert (S0 + 3) * 4 == 4 * S0 + 12


def test_wraps_modulo_2_64():
    assert Term.of(-1).const == MASK
    assert Term.of(MASK) + 1 == Term.of(0)
    assert Term.of(0) == S0 * (1 << 64)


def test_extensions():
    assert S0.ext("uxtx", 3) == 8 * S0
    assert S0.ext("sxtx", 0) == S0
    assert Term.of(0x80000000).ext("sxtw", 0) == Term.of(-0x80000000)
    assert Term.of(0x1_8000_0000).ext("uxtw", 1) == Term.of(0x1_0000_0000)
    assert not S0.ext("uxtw", 0).is_const


def test_masks():
    assert Term.of(0x1234) & 0xFF0 == Term.of(0x230)
    assert S0 & -1 == S0
    assert Term.of(0) == S0 & 0
    assert not (S0 & -16).is_const


def test_symbols_and_subst():
    term = SP - 16 + Term.sym("<X1>").ext("sxtw", 2)
    assert {str(sym) for sym in term.symbols()} == {"<SP>", "<X1>"}
    rebased = term.subst({Sym("<SP>"): SP - 32, Sym("<X1>"): S1})
    assert rebased == SP - 48 + S1.ext("sxtw", 2)


def test_linker_offset():
    term = Term.sym("<X8>") + Term.sym("LO12") + 8
    assert str(term) == "<X8> + LO12 + 8"
    assert not Sym("LO12").is_register


def test_unknown_symbol():
    with pytest.raises(ValueError, match="unknown symbol"):
        Term.sym("X1")
    with pytest.raises(ValueError, match="unknown symbol"):
        Term.sym("<X31>")


def test_printing():
    assert str(SP - 16) == "<SP> - 16"
    assert str(-S0 + 2 * S1 + 1) == "-S0 + 2*S1 + 1"
    assert str(Term.of(-8)) == "-8"
    assert str(S0.ext("sxtw", 2) + 4) == "ext(S0, sxtw, 2) + 4"
    assert str(S0 & -64) == "(S0 & -0x40)"


def test_tracked_values_are_not_registers():
    assert Sym("<X29>").is_register
    assert not Sym("<SP>").is_register
    assert not Sym("<FP>").is_register
    assert not Sym("S0").is_register
    with pytest.raises(ValueError, match="unknown symbol"):
        Sym("SP0")
