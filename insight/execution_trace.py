from __future__ import annotations

from typing import Any, NamedTuple

from insight.basic_block import BasicBlock
from insight.disassembler import Disassembler


class AddressTrace(NamedTuple):
    address: int
    taken: bool

    def __repr__(self) -> str:
        return f"AddressTrace({hex(self.address)}, {'E' if self.taken else 'N'})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "taken": self.taken,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AddressTrace:
        return cls(address=data["address"], taken=data["taken"])


class ExecutionTrace:
    def __init__(self, address_trace: list[int], basic_blocks: dict[int, BasicBlock]) -> None:
        self.basic_blocks: dict[int, BasicBlock] = basic_blocks
        # The trace is a list of tuples:
        #   (address of the basic block, last branch taken?)
        self.trace: list[AddressTrace] = self.check_taken_not_taken(address_trace)

    def check_taken_not_taken(self, address_trace: list[int]) -> list[AddressTrace]:
        trace: list[AddressTrace] = []
        for i, address in enumerate(address_trace):
            # Last in the trace, branch is taken!
            if i == len(address_trace) - 1:
                trace.append(AddressTrace(address=address, taken=True))
                break
            bb: BasicBlock = self.basic_blocks[address]
            # Check if the address_bb[n] + size_bb[n] == address_bb[n+1]
            # meaning the branch has NOT been taken
            trace.append(AddressTrace(address=address, taken=address + bb.size != address_trace[i + 1]))
        return trace

    def to_tessla_trace(self) -> str:
        # From the base trace, output:
        # 1: addr = 0x100
        # 1: size = 0x8
        # 1: ret = false
        # 1: call = false
        # 2: addr = 0x100
        # 2: size = 0x8
        # 2: ret = false
        # 2: call = true
        file_content: list[str] = []
        file_content.append("0: addr = 0xdeadbeef\n0: size = 0x0\n0: ret = false\n0: call = true\n")
        for i, address_trace in enumerate(self.trace):
            addr: int = address_trace.address
            bb: BasicBlock = self.basic_blocks[addr]
            file_content.append(
                f"{i + 1}: addr = {hex(addr)}\n"
                f"{i + 1}: size = {hex(bb.size)}\n"
                f"{i + 1}: ret = {str(Disassembler.is_ret(bb.ending_instruction)).lower()}\n"
                f"{i + 1}: call = {str(Disassembler.is_call(bb.ending_instruction)).lower()}\n"
            )
        contents: str = "".join(file_content)
        return contents

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace": [t.to_dict() for t in self.trace],
            "basic_blocks": {k: v.to_dict() for k, v in self.basic_blocks.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> ExecutionTrace:
        trace = [AddressTrace.from_dict(item) for item in data["trace"]]
        basic_blocks = {
            int(addr): BasicBlock.from_dict(bb_data) for addr, bb_data in data["basic_blocks"].items()
        }
        instance = cls(address_trace=[], basic_blocks=basic_blocks)
        instance.trace = trace  # Set trace explicitly
        return instance
