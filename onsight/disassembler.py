from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

CALLS: list[str] = ["bl", "bx", "blx"]

RET: list[str] = [
    "ret",
]

CONDITIONAL_BRANCHES: list[str] = [
    "b.eq",
    "b.ne",
    "b.cs",
    "b.cc",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
    "b.hi",
    "b.ls",
    "b.ge",
    "b.lt",
    "b.gt",
    "b.le",
    "b.al",
]

DIRECT_BRANCHES: list[str] = [
    "b",
    "br",
]

TEST_AND_BRANCHES: list[str] = [
    "cbz",
    "cbnz",
]

TABLE_BASED_BRANCHES: list[str] = [
    "tbb",
    "tbh",
]

BRANCHES: list[str] = (
    CALLS + RET + DIRECT_BRANCHES + CONDITIONAL_BRANCHES + TEST_AND_BRANCHES + TABLE_BASED_BRANCHES
)


class Disassembler:
    @staticmethod
    def is_str_branch(instr: str) -> bool:
        return instr in BRANCHES

    @staticmethod
    def disassemble_instruction(instr_bytes: bytes) -> str:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instr = next(disassembler.disasm(instr_bytes, 0))
        return f"{instr.mnemonic} {instr.op_str}"

    @staticmethod
    def is_call(instr_bytes: bytes) -> bool:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instr = next(disassembler.disasm(instr_bytes, 0))
        return instr.mnemonic in CALLS

    @staticmethod
    def is_ret(instr_bytes: bytes) -> bool:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instr = next(disassembler.disasm(instr_bytes, 0))
        return instr.mnemonic in RET

    @staticmethod
    def is_direct_branch(instr_bytes: bytes) -> bool:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instr = next(disassembler.disasm(instr_bytes, 0))
        return instr.mnemonic in DIRECT_BRANCHES + CONDITIONAL_BRANCHES
