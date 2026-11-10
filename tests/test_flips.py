"""Instruction forms: mnemonic and operand shape."""

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from insight.flips.forms import form_of


def test_forms():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    forms = [form_of(insn) for insn in decoder.disasm(bytes.fromhex("208440f8fd7bbea900d861b82000829a"), 0)]
    assert forms == ["ldr x, [x] post, #", "stp x, x, [sp, #]!", "ldr w, [x, w sxtw #]", "csel cc x, x, x"]
