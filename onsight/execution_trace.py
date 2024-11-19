from typing import NamedTuple

from onsight.basic_block import BasicBlock


class AddressTrace(NamedTuple):
    address: int
    taken: bool

    def __repr__(self) -> str:
        return f"AddressTrace({hex(self.address)}, {'E' if self.taken else 'N'})"


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
