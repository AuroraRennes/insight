import logging
from typing import ClassVar

from insight.exceptions import NegativeAddressError, UndefinedRegisterError
from insight.helpers import COLOG

logger = logging.getLogger("insight")


class ARM64State:
    FP_SIZES: ClassVar[dict[str, int]] = {
        "B": (1 << 8) - 1,
        "H": (1 << 16) - 1,
        "S": (1 << 32) - 1,
        "D": (1 << 64) - 1,
        "Q": (1 << 128) - 1,
    }
    INT_SIZES: ClassVar[dict[str, int]] = {
        "W": (1 << 32) - 1,
        "X": (1 << 64) - 1,
    }

    def __init__(self) -> None:
        self.registers: dict[str, int] = dict.fromkeys(
            [f"X{i}" for i in range(31)]
            + [f"Q{i}" for i in range(31)]
            + ["XZR", "SP", "PC"]
            + ["N", "Z", "C", "V"]
            + ["TPIDR"],
            0,
        )

        self.register_aliases: dict[str, str] = {"LR": "X30", "FP": "X29"}
        self.memory: dict[int, int] = {}
        # The stack value is passed through the STM ONE TIME at the start of the program
        # and its value should be maintained by the interpreter
        self.stack_value = 0

    # Register Access
    # \________________

    def write_register(self, register_name: str, tag: int) -> None:
        # Check flag registers first
        if register_name == "NZCV":
            self.registers["N"] = tag
            self.registers["Z"] = tag
            self.registers["C"] = tag
            self.registers["V"] = tag
            return

        # Resolve any alias
        if register_name in self.register_aliases:
            register_name = self.register_aliases[register_name]
        # Early bailout if the name is the one defined in the register list
        if register_name in self.registers:
            self.registers[register_name] = tag
            return

        # Extract the register name from its number, X10 -> X | 10
        reg_size: str = register_name[0]
        reg_num: str = register_name[1:]
        # Check for integer registers, always write to the largest size
        if reg_size in ARM64State.INT_SIZES:
            register_name = "X" + reg_num
            tag = tag & ARM64State.INT_SIZES[reg_size]
        # Check for floating point registers, always write to the largest size
        if reg_size in ARM64State.FP_SIZES:
            register_name = "Q" + reg_num
            tag = tag & ARM64State.FP_SIZES[reg_size]

        if register_name not in self.registers:
            raise UndefinedRegisterError(register_name)
        self.registers[register_name] = tag

    def read_register(self, register_name: str) -> int:
        # Check for aliases
        if register_name in self.register_aliases:
            register_name = self.register_aliases[register_name]
        # Early bailout if the name is the one defined in the register list
        if register_name in self.registers:
            return self.registers[register_name]

        # Extract the register name from its number, X10 -> X | 10
        reg_size: str = register_name[0]
        reg_num: str = register_name[1:]
        # Check for integer registers, always write to the largest size
        if reg_size in ARM64State.INT_SIZES:
            register_name = "X" + reg_num
            tag = self.registers[register_name] & ARM64State.INT_SIZES[reg_size]
        # Check for floating point registers, always write to the largest size
        if reg_size in ARM64State.FP_SIZES:
            register_name = "Q" + reg_num
            tag = self.registers[register_name] & ARM64State.FP_SIZES[reg_size]
        return tag

    # Memory Access
    # \________________

    def memory_write(self, address: int, size: int, tag: int) -> None:
        for i in range(address, address + size, 4):
            self.memory[i] = tag

    def memory_read(self, address: int, size: int) -> int:
        result: int = 0
        for aligned_addr in range(address, address + size, 4):
            if aligned_addr <= 0:
                raise NegativeAddressError(aligned_addr)
            if aligned_addr not in self.memory:
                logger.warning(
                    f"{COLOG['warning']} \t├ ✍️  Reading from unwritten memory at "
                    f"{hex(aligned_addr)}, setting tag 0"
                )
                self.memory_write(aligned_addr, size, 0)
            result = result << aligned_addr | self.memory[aligned_addr]
        return result

    # Rules configuration and checking
    # \___________________________________

    def check_tag_rules(self) -> None: ...
