class BasicBlock:
    def __init__(self, address: int, instructions: list[bytes]) -> None:
        self.address: int = address
        self.instructions: list[bytes] = instructions
        self.ending_instruction: bytes = instructions[-1]
