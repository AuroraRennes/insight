from __future__ import annotations

from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "function_address": self.function_address,
            "function_name": self.function_name,
            "instructions": [inst.hex() for inst in self.instructions],
            "ending_instruction": self.ending_instruction.hex(),
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BasicBlock:
        # Decode instructions from hex strings to bytes
        instructions = [bytes.fromhex(instr) for instr in data["instructions"]]
        return cls(
            address=data["address"],
            function_address=data["function_address"],
            function_name=data["function_name"],
            instructions=instructions,
        )
