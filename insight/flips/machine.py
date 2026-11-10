"""The unicorn backend: one instruction run from a full machine state, the state read back.

The state moves through memory, loaded by a prologue and stored by an epilogue, since register
access through unicorn's binding is slow; each part and the stop address are on pages of their
own, or unicorn retranslates them on every run. The CPU model is the Cortex-A53, FPCR is 0.
"""

from __future__ import annotations

from dataclasses import dataclass

from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc, UcError
from unicorn.arm64_const import UC_CPU_ARM64_A53

CODE = 0x1000_0000  # the prologue
TEST = CODE + 0x2000  # the instruction under test, then a branch to the epilogue
LANDING = TEST + 0x800  # where every branch under test goes: a branch to the epilogue
EPILOGUE = CODE + 0x4000  # the epilogue, then a branch to STOP
STOP = CODE + 0x6000
DATA = 0x2000_0000
SENDS = 0x3000_0000
STATE = 0x4000_0000
PAGE = 0x1000

X_OFFSET = 0
SP_OFFSET = 248
NZCV_OFFSET = 256
TPIDR_OFFSET = 264
EXCLUSIVE_OFFSET = 272
V_OFFSET = 288
REGISTERS_SIZE = 800
MEMORY_OFFSET = REGISTERS_SIZE
STATE_SIZE = REGISTERS_SIZE + PAGE

STM_REGISTER = 18
SCRATCH = 30  # the register holding the state block's address in the prologue and epilogue


# Encodings
# \__________
# The few instructions the prologue and epilogue need, checked against capstone in the tests.

NZCV = (3, 3, 4, 2, 0)
TPIDR_EL0 = (3, 3, 13, 0, 2)
TPIDR_EL1 = (3, 0, 13, 0, 4)
FPCR = (3, 3, 4, 4, 0)


def movz(rd: int, imm16: int, hw: int = 0) -> int:
    return 0xD2800000 | hw << 21 | imm16 << 5 | rd


def movk(rd: int, imm16: int, hw: int) -> int:
    return 0xF2800000 | hw << 21 | imm16 << 5 | rd


def ldp_x(rt: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA9400000 | (offset // 8 & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt


def stp_x(rt: int, rt2: int, rn: int, offset: int) -> int:
    return 0xA9000000 | (offset // 8 & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt


def ldp_q(rt: int, rt2: int, rn: int, offset: int) -> int:
    return 0xAD400000 | (offset // 16 & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt


def stp_q(rt: int, rt2: int, rn: int, offset: int) -> int:
    return 0xAD000000 | (offset // 16 & 0x7F) << 15 | rt2 << 10 | rn << 5 | rt


def ldr_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9400000 | (offset // 8) << 10 | rn << 5 | rt


def str_x(rt: int, rn: int, offset: int) -> int:
    return 0xF9000000 | (offset // 8) << 10 | rn << 5 | rt


def sysreg(word: int, reg: tuple[int, int, int, int, int], rt: int) -> int:
    op0, op1, crn, crm, op2 = reg
    return word | op0 << 19 | op1 << 16 | crn << 12 | crm << 8 | op2 << 5 | rt


def mrs(rt: int, reg: tuple[int, int, int, int, int]) -> int:
    return sysreg(0xD5300000, reg, rt)


def msr(reg: tuple[int, int, int, int, int], rt: int) -> int:
    return sysreg(0xD5100000, reg, rt)


def branch(source: int, target: int) -> int:
    return 0x14000000 | ((target - source) // 4 & 0x3FFFFFF)


def add_imm0(rd: int, rn: int) -> int:
    """mov to or from SP: add rd, rn, #0."""
    return 0x91000000 | rn << 5 | rd


# Load-exclusive of each size, to arm the monitor: (load-exclusive, its pair form)
LDXR = {1: 0x085F7C00, 2: 0x485F7C00, 4: 0x885F7C00, 8: 0xC85F7C00}
LDXP = {4: 0x887F0000, 8: 0xC87F0000}


def ldxr(size: int, rt: int, rn: int) -> int:
    return LDXR[size] | rn << 5 | rt


def ldxp(size: int, rt: int, rt2: int, rn: int) -> int:
    return LDXP[size] | rt2 << 10 | rn << 5 | rt


def load_address(rd: int, address: int) -> list[int]:
    parts = [(hw, (address >> (16 * hw)) & 0xFFFF) for hw in range(1, 4)]
    return [movz(rd, address & 0xFFFF)] + [movk(rd, part, hw) for hw, part in parts if part]


@dataclass(frozen=True)
class Exclusive:
    """How the prologue arms the exclusive monitor for a store-exclusive: size and pair."""

    size: int
    pair: bool


def prologue(exclusive: Exclusive | None) -> list[int]:
    code = load_address(SCRATCH, STATE)
    if exclusive is not None:
        # A store-exclusive succeeds only if a load-exclusive armed the monitor for its address, and
        # unicorn cannot set the monitor otherwise: load-exclusive the state's exclusive address first.
        # The registers it clobbers are loaded after. The flip tests put the access address there in
        # half the states and an address elsewhere in the others, so the store succeeds and fails.
        code.append(ldr_x(0, SCRATCH, EXCLUSIVE_OFFSET))
        code.append(ldxp(exclusive.size, 1, 2, 0) if exclusive.pair else ldxr(exclusive.size, 1, 0))
    code += [ldp_q(2 * i, 2 * i + 1, SCRATCH, V_OFFSET + 32 * i) for i in range(16)]
    code += [ldr_x(0, SCRATCH, NZCV_OFFSET), msr(NZCV, 0)]
    code += [ldr_x(0, SCRATCH, TPIDR_OFFSET), msr(TPIDR_EL0, 0)]
    code += [ldr_x(0, SCRATCH, SP_OFFSET), add_imm0(31, 0)]
    code += [msr(FPCR, 31)]
    code += [ldp_x(2 * i, 2 * i + 1, SCRATCH, X_OFFSET + 16 * i) for i in range(15)]
    code.append(ldr_x(SCRATCH, SCRATCH, X_OFFSET + 8 * SCRATCH))
    return code


def epilogue() -> list[int]:
    code = [msr(TPIDR_EL1, SCRATCH), *load_address(SCRATCH, STATE)]
    code += [stp_x(2 * i, 2 * i + 1, SCRATCH, X_OFFSET + 16 * i) for i in range(15)]
    code += [mrs(0, NZCV), str_x(0, SCRATCH, NZCV_OFFSET)]
    code += [mrs(0, TPIDR_EL1), str_x(0, SCRATCH, X_OFFSET + 8 * SCRATCH)]
    code += [add_imm0(0, 31), str_x(0, SCRATCH, SP_OFFSET)]
    code += [mrs(0, TPIDR_EL0), str_x(0, SCRATCH, TPIDR_OFFSET)]
    code += [stp_q(2 * i, 2 * i + 1, SCRATCH, V_OFFSET + 32 * i) for i in range(16)]
    return code


def words(code: list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in code)


# The machine
# \____________


class RunError(Exception):
    """The instruction faulted (an unmapped or misaligned access, an undefined instruction)."""


# Direct branches: (mask, value, low bit, width) of their offset field, in words.
DIRECT_BRANCHES = (
    (0x7C000000, 0x14000000, 0, 26),  # b, bl
    (0xFF000010, 0x54000000, 5, 19),  # b.cond
    (0x7E000000, 0x34000000, 5, 19),  # cbz, cbnz
    (0x7E000000, 0x36000000, 5, 14),  # tbz, tbnz
)


def retarget(encoding: bytes) -> bytes:
    """A direct branch with its offset changed to reach LANDING from TEST; other instructions as
    they are. The offset is not part of the form, so this tests the same semantics."""
    word = int.from_bytes(encoding, "little")
    for mask, value, low, width in DIRECT_BRANCHES:
        if word & mask == value:
            field = ((1 << width) - 1) << low
            word = word & ~field | ((LANDING - TEST) // 4) << low
            return word.to_bytes(4, "little")
    return encoding


class Machine:
    """One instruction, at TEST, run from states. A branch goes to LANDING: a direct one is
    retargeted there, an indirect one must have its target register set to LANDING by the state
    (the vectors hold it fixed, as an address input)."""

    address = TEST
    landing = LANDING

    def __init__(self, encoding: bytes, exclusive: Exclusive | None = None) -> None:
        pro = prologue(exclusive)
        pro.append(branch(CODE + 4 * len(pro), TEST))
        epi = epilogue()
        epi.append(branch(EPILOGUE + 4 * len(epi), STOP))
        encoding = retarget(encoding)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM64_A53)
        for base in (CODE, TEST, EPILOGUE, STOP, DATA, SENDS, STATE):
            self.uc.mem_map(base, PAGE)
        self.uc.mem_write(CODE, words(pro))
        self.uc.mem_write(TEST, encoding + words([branch(TEST + 4, EPILOGUE)]))
        self.uc.mem_write(LANDING, words([branch(LANDING, EPILOGUE)]))
        self.uc.mem_write(EPILOGUE, words(epi))

    def run(self, state: bytes) -> bytes:
        """The state after the instruction."""
        self.uc.mem_write(STATE, state[:REGISTERS_SIZE])
        self.uc.mem_write(DATA, state[MEMORY_OFFSET:])
        try:
            self.uc.emu_start(CODE, STOP)
        except UcError as error:
            raise RunError(str(error)) from error
        return bytes(self.uc.mem_read(STATE, REGISTERS_SIZE) + self.uc.mem_read(DATA, PAGE))
