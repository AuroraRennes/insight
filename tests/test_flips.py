"""Instruction forms, and the unicorn machine the flip tests run on."""

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from insight.flips.forms import form_of
from insight.flips.machine import Exclusive, epilogue, prologue, words


def test_prologue_and_epilogue_encodings():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    text = [
        f"{insn.mnemonic} {insn.op_str}"
        for insn in decoder.disasm(words(prologue(Exclusive(8, pair=True)) + epilogue()), 0)
    ]
    assert len(text) == len(prologue(Exclusive(8, pair=True))) + len(epilogue())
    assert text[:4] == [
        "mov x30, #0",
        "movk x30, #0x4000, lsl #16",
        "ldr x0, [x30, #0x110]",
        "ldxp x1, x2, [x0]",
    ]
    assert "msr nzcv, x0" in text
    assert "msr fpcr, xzr" in text
    assert "msr tpidr_el1, x30" in text
    assert text[-1] == "stp q30, q31, [x30, #0x300]"


def test_forms():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    forms = [form_of(insn) for insn in decoder.disasm(bytes.fromhex("208440f8fd7bbea900d861b82000829a"), 0)]
    assert forms == ["ldr x, [x] post, #", "stp x, x, [sp, #]!", "ldr w, [x, w sxtw #]", "csel cc x, x, x"]
