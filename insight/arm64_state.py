from insight.exceptions import ReadingFromUnwrittenMemoryError, UndefinedRegisterError


class ARM64State:
    def __init__(self) -> None:
        self.registers: dict[str, int] = dict.fromkeys(
            [f"X{i}" for i in range(31)] + ["XZR", "SP", "PC", "N", "Z", "C", "V"], 0
        )
        self.memory: dict[int, int] = {}
        # The stack value is passed through the STM ONE TIME at the start of the program
        # and its value should be maintained by the interpreter
        self.stack_value = 0

    def write_register(self, register_name: str, tag: int) -> None:
        if register_name.startswith("W"):
            register_name = "X" + register_name[1:]
        if register_name == "NZCV":
            self.registers["N"] = tag
            self.registers["Z"] = tag
            self.registers["C"] = tag
            self.registers["V"] = tag
            return
        if register_name not in self.registers:
            raise UndefinedRegisterError(register_name)
        self.registers[register_name] = tag

    def read_register(self, register_name: str) -> int:
        if register_name.startswith("W"):
            register_name = "X" + register_name[1:]
        return self.registers[register_name]

    def memory_write(self, address: int, size: int, tag: int) -> None:
        for i in range(address, address + size, 4):
            self.memory[i] = tag

    def memory_read(self, address: int, size: int) -> int:
        result: int = 0
        for aligned_addr in range(address, address + size, 4):
            if aligned_addr not in self.memory:
                raise ReadingFromUnwrittenMemoryError(aligned_addr)
            result = result << aligned_addr | self.memory[aligned_addr]
        return result
