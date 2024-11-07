from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

BRANCHES: list[str] = [
    "bl",
    "bx",
    "blx",
    "cbz",
    "cbnz",
    "tbb",
    "tbh",
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
    "b",
    "ret",
]


class Disassembler:
    @staticmethod
    def is_branch(instr: str) -> bool:
        return instr in BRANCHES

    @staticmethod
    def disassemble_instruction(instr_bytes: bytes) -> str:
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        instr = next(disassembler.disasm(instr_bytes, 0))
        return f"{instr.mnemonic} {instr.op_str}"
