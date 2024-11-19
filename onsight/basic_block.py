class BasicBlock:
    def __init__(
        self, address: int, function_address: int, function_name: str, instructions: list[bytes]
    ) -> None:
        self.address: int = address
        self.instructions: list[bytes] = instructions
        self.function_name: str = function_name
        self.function_address: int = function_address

        self.ending_instruction: bytes = instructions[-1]
        self.size: int = len(self.instructions) * 4  # 4-bytes instructions

    def __repr__(self) -> str:
        return f"BB({hex(self.address)} - size {hex(self.size)})"
