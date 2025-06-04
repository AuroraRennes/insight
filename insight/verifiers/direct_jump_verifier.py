import logging
from typing import TYPE_CHECKING

from insight.disassembler import Disassembler
from insight.exceptions import DirectJumpError
from insight.execution_trace import ExecutionTrace
from insight.verifiers.verifier import Verifier

if TYPE_CHECKING:
    from insight.basic_block import BasicBlock


logger = logging.getLogger("insight")


class DirectJumpVerifier(Verifier):
    def verify_trace(self, exec_trace: ExecutionTrace) -> bool:
        logger.info("[+] Verifying direct jumps.")
        validated = True
        for i, address_info in enumerate(exec_trace.trace):
            basic_block: BasicBlock = exec_trace.basic_blocks[address_info.address]
            ends_in_direct_branch: bool = Disassembler.is_direct_branch(basic_block.ending_instruction)
            # Check if the direct branch ends in the same function
            if ends_in_direct_branch and address_info.taken:
                # Last block
                if i == len(exec_trace.trace) - 1:
                    continue
                # Get next block info
                next_address: int = exec_trace.trace[i + 1].address
                next_basic_block: BasicBlock = exec_trace.basic_blocks[next_address]
                next_function: str = next_basic_block.function_name
                if next_function != basic_block.function_name:
                    validated = False
                    raise DirectJumpError(expected_function=basic_block.function_name, function=next_function)
        return validated

    def message(self) -> str:
        return "Direct jumps verified!"
