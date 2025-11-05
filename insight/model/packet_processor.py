from __future__ import annotations

import logging
from dataclasses import dataclass

from insight.constants import AVOIDED_FUNC_NAMES
from insight.elf.disassembler import Disassembler
from insight.elf.objdump_parser import FunctionDict, FunctionInfo
from insight.model.basic_block import BasicBlock
from insight.model.execution_trace import ExecutionTrace
from insight.model.packets import ETMAddressPacket, ETMAtomPacket, Packet

logger = logging.getLogger("insight")


@dataclass
class ProcessingInfo:
    pie_address: int
    current_offset: int
    func_info: FunctionInfo

    @classmethod
    def default(cls) -> ProcessingInfo:
        return ProcessingInfo(pie_address=0, current_offset=0, func_info=FunctionInfo.default())

    def get_current_instruction(self) -> bytes:
        return self.func_info.instructions[self.current_offset // 4]


class PacketProcessor:
    # The packet processor is responsible for taking a a packet trace and function
    # dictionary and extracting the execution trace (basic block dictionary and
    # address trace)
    def __init__(self, func_dict: FunctionDict) -> None:
        self.func_dict: FunctionDict = func_dict
        self.basic_blocks: list[BasicBlock] = []

    def process_packets(
        self, packet_trace: list[Packet], func_dict: FunctionDict, start_address: int
    ) -> ExecutionTrace:
        logger.info("{COLOG['success']} Processing parsed packets.")
        # PIE address is in reference of Position Independent Executable
        # It is the address relative to the start of the object file
        process_info: ProcessingInfo = ProcessingInfo.default()

        for packet in packet_trace:
            # Extracting address from address packet
            if isinstance(packet, ETMAddressPacket):
                address_packet: ETMAddressPacket = packet
                process_info.pie_address = address_packet.address - start_address

            # Extracting basic block(s) from atom packet
            if isinstance(packet, ETMAtomPacket):
                # Check if pie address is 0, meaning an atom packet is arriving
                # before an address packet (TODO)
                atom_packet: ETMAtomPacket = packet
                # Search the function the address in the function dict
                # If None, this means the  obtained address is outside the traced binary
                optional_func_info: FunctionInfo | None = func_dict.find_function_by_address(
                    process_info.pie_address
                )
                if optional_func_info is None:
                    continue
                # Check if it is one of the libc setup/teardown functions
                func_info: FunctionInfo = optional_func_info
                if func_info.name in AVOIDED_FUNC_NAMES:
                    continue
                # Register in the process info
                process_info.func_info = func_info
                # Offset in the function
                process_info.current_offset = process_info.pie_address - process_info.func_info.address
                # Process the atom packet elements
                process_info = self.process_atom_packet(atom_packet=atom_packet, process_info=process_info)

        return ExecutionTrace(
            address_trace=[bb.address for bb in self.basic_blocks],
            basic_blocks={bb.address: bb for bb in self.basic_blocks},
        )

    def process_atom_packet(self, atom_packet: ETMAtomPacket, process_info: ProcessingInfo) -> ProcessingInfo:
        # Pass through all elements: ["E", "E", "N", ...]
        for atom_element in atom_packet.elements:
            # Extract instructions
            basic_block: BasicBlock = self.process_basic_block(process_info=process_info)
            # Publish the basic block and address info
            self.basic_blocks.append(basic_block)
            # Update the process info (current address, func info, etc.)
            process_info = self.update_info(atom_element=atom_element, process_info=process_info)
        return process_info

    def update_info(self, atom_element: str, process_info: ProcessingInfo) -> ProcessingInfo:
        # Setup previous process info
        pie_address: int = process_info.pie_address
        current_offset: int = process_info.current_offset
        func_info: FunctionInfo = process_info.func_info
        # Process the address of the next basic block
        current_instruction: bytes = process_info.get_current_instruction()
        # - Branch taken
        if atom_element == "E" and (
            Disassembler.is_direct_branch(current_instruction) or Disassembler.is_call(current_instruction)
        ):
            pie_address = (
                func_info.address + current_offset + Disassembler.extract_branch_target(current_instruction)
            )
            # If changing functions
            optional_func_info = self.func_dict.find_function_by_address(pie_address)
            if optional_func_info:
                func_info = optional_func_info
                current_offset = pie_address - func_info.address

        # - Branch not taken
        elif atom_element == "N":
            current_offset = current_offset + 4
            pie_address = process_info.func_info.address + current_offset

        return ProcessingInfo(pie_address=pie_address, current_offset=current_offset, func_info=func_info)

    def process_basic_block(self, process_info: ProcessingInfo) -> BasicBlock:
        current_instruction: bytes = process_info.get_current_instruction()
        instructions: list[bytes] = []
        while not Disassembler.is_branch(current_instruction):
            instructions.append(current_instruction)
            process_info.current_offset += 4
            current_instruction = process_info.get_current_instruction()
        # Add the branch!
        instructions.append(current_instruction)
        return BasicBlock(
            function_address=process_info.func_info.address,
            function_name=process_info.func_info.name,
            address=process_info.pie_address,
            instructions=instructions,
        )
