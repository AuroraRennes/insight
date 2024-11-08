from typing import TYPE_CHECKING

from onsight.disassembler import Disassembler
from onsight.execution_trace import ExecutionTrace

if TYPE_CHECKING:
    from onsight.basic_block import BasicBlock


class ShadowStackVerifier:
    def __init__(self) -> None:
        self.shadow_stack: list[int] = []

    def verify_trace(self, exec_trace: ExecutionTrace) -> bool:
        # As the tracing starts when a function is already called,
        # a dummy address is added to the stack
        self.shadow_stack.append(0xDEADBEEF)
        for i, address_info in enumerate(exec_trace.trace):
            # Check if the basic block ends in a call and is taken
            # TODO: is "taken" info needed?
            validated: bool = True
            basic_block: BasicBlock = exec_trace.basic_blocks[address_info.address]
            ends_in_call: bool = Disassembler.is_call(basic_block.ending_instruction)
            ends_in_ret: bool = Disassembler.is_ret(basic_block.ending_instruction)
            if ends_in_call and address_info.taken:
                # Push the return address to the stack -> right after call
                self.shadow_stack.append(basic_block.address + 4)
            elif ends_in_ret and address_info.taken:
                # Pop the address from the stack and checks it against the next one
                shadow_address: int = self.shadow_stack.pop()
                # Last ret
                if i == len(exec_trace.trace) - 1:
                    continue
                if shadow_address != exec_trace.trace[i + 1]:
                    validated = False
                    break
        return validated
