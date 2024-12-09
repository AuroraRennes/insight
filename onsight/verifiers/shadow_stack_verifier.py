from typing import TYPE_CHECKING

from onsight.disassembler import Disassembler
from onsight.exceptions import ShadowStackError
from onsight.execution_trace import ExecutionTrace
from onsight.verifiers.verifier import Verifier

if TYPE_CHECKING:
    from onsight.basic_block import BasicBlock

import logging

logger = logging.getLogger("onsight")


class ShadowStackVerifier(Verifier):
    INITIAL_VALUE: int = 0xDEADBEEF

    def __init__(self) -> None:
        self.shadow_stack: list[int] = []

    def verify_trace(self, exec_trace: ExecutionTrace) -> bool:
        logger.info("[+] Verifying backward edges using a shadow stack.")
        # As the tracing starts when a function is already called,
        # a dummy address is added to the stack
        self.shadow_stack.append(ShadowStackVerifier.INITIAL_VALUE)
        validated: bool = True
        for i, address_info in enumerate(exec_trace.trace):
            basic_block: BasicBlock = exec_trace.basic_blocks[address_info.address]
            ends_in_call: bool = Disassembler.is_call(basic_block.ending_instruction)
            ends_in_ret: bool = Disassembler.is_ret(basic_block.ending_instruction)
            # Check if the basic block ends in a call and is taken
            # TODO: is "taken" info needed?
            if ends_in_call and address_info.taken:
                # Push the return address to the stack -> right after call
                self.shadow_stack.append(basic_block.address + basic_block.size)
            elif ends_in_ret and address_info.taken:
                # Pop the address from the stack and checks it against the next one
                shadow_address: int = self.shadow_stack.pop()
                # Last ret
                if i == len(exec_trace.trace) - 1:
                    return shadow_address == ShadowStackVerifier.INITIAL_VALUE
                # Get the next address and compare it
                next_address: int = exec_trace.trace[i + 1].address
                if shadow_address != next_address:
                    validated = False
                    raise ShadowStackError(expected_address=shadow_address, address=next_address)

        # validated should always be true or an excpetion is raised
        # FIXME: this behavior is not very useful (remove exception? remove return value?)
        return validated

    def message(self) -> str:
        return "Shadow stack intact!"
