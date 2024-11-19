import logging
import re
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from onsight.basic_block import BasicBlock
from onsight.disassembler import Disassembler
from onsight.exceptions import (
    NoMatchingAddressContextError,
    NoMatchingAddressError,
    NoMatchingElementsError,
    NoMatchingInfoError,
    ParserError,
    TraceSizeError,
    WrongSizeAtomPacketError,
)
from onsight.execution_trace import ExecutionTrace
from onsight.helpers import string_to_int
from onsight.packets import (
    AddressContextPacket,
    AddressPacket,
    AtomPacket,
    Context,
    InfoFields,
    InfoPacket,
    Packet,
    PacketInfo,
    SynchronizationPacket,
)
from onsight.parsers.objdump_parser import FunctionDict, FunctionInfo, ObjdumpParser
from onsight.parsers.parser import Parser

if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger("onsight")


@dataclass
class ParseInfo:
    parse_method: str
    regex: str


class PerfReportParser(Parser):
    # The PerfReportParser extract packets from the execution and derives
    # the corresponding basic blocks from it.
    #
    # As an example, a part of the execution script might looklike:
    # . ... CoreSight ETMV4I Trace data: size 0xf0 bytes
    # Idx:211; ID:16;	I_TRACE_ON : Trace On.
    # Idx:212; ID:16;	I_ADDR_CTXT_L_64IS0 : Address & Context, Long, 64 bit, IS0.;
    #    Addr=0x0000AAAAAAAA07D8; Ctxt: AArch64,EL0, NS;
    # Idx:222; ID:16;	I_ATOM_F6 : Atom format 6.; EEEEEEN
    # Idx:224; ID:16;	I_ATOM_F3 : Atom format 3.; EEN
    # ...
    #
    # In this case, four packets should be extracted:
    # P1: I_TRACE_ON
    # P2: I_ADDR_CTXT_L_64ISO
    # P3: I_ATOM_F6
    # P4: I_ATOM_F3
    #
    # And basic blocks can be found under the Atom packets as either
    # Taken (E for Executed initially) or Not taken (N)
    # In this case, 10 basic blocks (7 in ATOM_F6 + 4 in ATOM_F3) should
    # be extracted

    # Starting address
    PROGRAM_START_ADDRESS: int = 0x0000AAAAAAAA0000
    PROGRAM_MEM_SIZE: int = 0x10000

    # REGEXES
    TRACE_START_LINE_REGEX: str = r"\. \.\.\. CoreSight ETMV4I Trace data: size (0x\w+) bytes"
    ADDR_REGEX: str = r"Addr=(0x\w+)"  # Address, in address    ...; Addr=0xFFFF800008AA4BE0;
    CTXT_REGEX: str = r"Ctxt: ([,\s\w]*)"  # Context, in address    ...; Ctxt: AArch64,EL0, NS;
    ELTS_REGEX: str = r"([EN]+)"  # Basic blocks, in atoms ...;  Atom format 3.; ENE
    INFO_REGEX: str = r"INFO=(0x\w+) \{[\s\w.]*\}"  # Info, in trace info    ...; INFO=0x0 { CC.0 };

    # This dictionary takes the name as key and outputs the corresponding regexes needed
    # to extract the rest of the information. The syntax **dict.fromkeys(keys_list, value) maps multiple
    # keys to the same value in a more concise way.
    PACKETS_INFO: ClassVar[dict[str, ParseInfo]] = {
        **dict.fromkeys(["I_ADDR_L_64IS0", "I_ADDR_S_64IS0"], ParseInfo("parse_addr", ADDR_REGEX)),
        "I_ADDR_CTXT_L_64IS0": ParseInfo("parse_addr_ctxt", ADDR_REGEX + "; " + CTXT_REGEX),
        "I_TRACE_INFO": ParseInfo("parse_trace_info", INFO_REGEX),
        **dict.fromkeys([f"I_ATOM_F{i}" for i in range(7)], ParseInfo("parse_atom", ELTS_REGEX)),
        # These don't need additional parameters
        "I_TRACE_ON": ParseInfo("parse_trace_on", ""),
        "I_ASYNC": ParseInfo("parse_async", ""),
    }

    # Base regex, then composed:
    # Holds                        index      id      name     description
    #                                v         v        v          v
    PACKET_BASE_REGEX: str = r"Idx:(\d+); ID:(\d+);\s(\w*)\s: ([\s\w,&]*)."

    # libc set up and teardown
    AVOIDED_FUNC_NAMES: tuple[str, ...] = (
        "_start",
        "__libc_start_main",
        ".plt",
        "call_weak_fn",
        "_init",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__cxa_finalize",
        "__do_global_dtors_aux",
        "_fini",
    )

    def __init__(self) -> None:
        super().__init__(extension=".perf.dump")

    def parse(self, file_name: str, *args: str, **kwargs: str) -> ExecutionTrace:
        dump_file_name: str = kwargs["dump_file_name"]

        # Check extension
        self.check_extension(file_name)

        # Main parsing function
        try:
            with Path(file_name).open() as perf_dump_file:
                cpu_nb: int = 0
                cpu_packets: list[list[Packet]] = []
                for line in perf_dump_file:
                    match_start: re.Match[str] | None = re.search(
                        PerfReportParser.TRACE_START_LINE_REGEX, line
                    )
                    if match_start:
                        trace_size: int = string_to_int(match_start.group(1))
                        packets: list[Packet] = self.parse_cpu_trace(
                            perf_dump_file=perf_dump_file, cpu_nb=cpu_nb, trace_size=trace_size
                        )
                        cpu_packets.append(packets)
                        cpu_nb += 1
        except (OSError, ParserError):
            logger.exception("[-] Parsing Failed.")
            raise

        return self.process_packets(cpu_packets, dump_file_name)

    def parse_cpu_trace(self, perf_dump_file: TextIOWrapper, cpu_nb: int, trace_size: int) -> list[Packet]:
        packets: list[Packet] = []

        # Matching the base info of a packet
        line: str = next(perf_dump_file)
        match_line: re.Match[str] | None = re.search(PerfReportParser.PACKET_BASE_REGEX, line)
        while match_line:
            packet_info: PacketInfo = PacketInfo(
                index=int(match_line.group(1)),
                vmid=int(match_line.group(2)),
                header=0x0,  # No header as it is already disassembled by perf
                cpu_nb=cpu_nb,
            )

            packet_name: str = match_line.group(3)
            parse_info: ParseInfo = PerfReportParser.PACKETS_INFO[packet_name]

            parse_method: Callable[..., Packet] = getattr(self, parse_info.parse_method)
            packet: Packet = parse_method(
                packet_info=packet_info, packet_name=packet_name, line=line, regex=parse_info.regex
            )

            packets.append(packet)

            # Next one!
            line = next(perf_dump_file)
            match_line = re.search(PerfReportParser.PACKET_BASE_REGEX, line)

        # FIXME: Once packets are parsed
        # parsed_size: int = len(packets) * 8
        parsed_size: int = trace_size
        if parsed_size != trace_size:
            raise TraceSizeError(expected_size=trace_size, size=parsed_size, cpu_nb=cpu_nb)
        return packets

    # Packet parsing
    # \_______________

    def parse_addr(self, packet_name: str, packet_info: PacketInfo, line: str, regex: str) -> AddressPacket:
        match_address: re.Match[str] | None = re.search(regex, line)
        if match_address:
            address: int = string_to_int(match_address.group(1))
        else:
            raise NoMatchingAddressError

        constr_method: Callable[..., AddressPacket] = getattr(AddressPacket, packet_name[2:].lower())
        return constr_method(packet_info=packet_info, address=address)

    def parse_addr_ctxt(
        self, packet_name: str, packet_info: PacketInfo, line: str, regex: str
    ) -> AddressContextPacket:
        match_addr_ctxt: re.Match[str] | None = re.search(regex, line)
        if match_addr_ctxt:
            address: int = string_to_int(match_addr_ctxt.group(1))
            context_str: list[str] = match_addr_ctxt.group(2).split(",")
            context: Context = Context(
                architecture=context_str[0].strip(),
                exception_level=context_str[1].strip(),
                security_state=context_str[2].strip(),
            )
        else:
            raise NoMatchingAddressContextError

        constr_method: Callable[..., AddressContextPacket] = getattr(
            AddressContextPacket, packet_name[2:].lower()
        )
        return constr_method(packet_info=packet_info, address=address, context=context)

    def parse_trace_info(
        self, packet_info: PacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> InfoPacket:
        match_info: re.Match[str] | None = re.search(regex, line)
        if match_info:
            info_bits: int = string_to_int(match_info.group(1))
            info_fields: InfoFields = InfoFields(info_bits=info_bits)
        else:
            raise NoMatchingInfoError

        return InfoPacket.trace_info(packet_info=packet_info, info_fields=info_fields)

    def parse_atom(self, packet_info: PacketInfo, packet_name: str, line: str, regex: str) -> AtomPacket:
        match_elements: re.Match[str] | None = re.search(regex, line)
        if match_elements:
            elements: list[str] = list(match_elements.group(1))
        else:
            raise NoMatchingElementsError

        # I_ATOM_F1 > [I, ATOM, F1] > 1, but atom format 6 can have more elements!
        format_extracted: str = packet_name.split("_")[-1][-1]
        if int(format_extracted) != min(6, len(elements)):
            raise WrongSizeAtomPacketError(expected_size=int(format_extracted), size=len(elements))
        return AtomPacket.atom_format(packet_info=packet_info, elements=elements)

    def parse_trace_on(self, packet_info: PacketInfo, **kwargs: dict[str, Any]) -> SynchronizationPacket:
        return SynchronizationPacket.trace_on(packet_info=packet_info)

    def parse_async(self, packet_info: PacketInfo, **kwargs: dict[str, Any]) -> SynchronizationPacket:
        return SynchronizationPacket.asynch(packet_info=packet_info)

    # Packet processing
    # \_________________

    def process_packets(self, packets: list[list[Packet]], dump_file_name: str) -> ExecutionTrace:
        # Extract function info from the dump file
        func_dict: FunctionDict = ObjdumpParser.parse_dump(dump_file_name)

        # Only pick the cpu with the largest trace
        # TODO: should be a cli argument?
        packet_trace: list[Packet] = max(packets, key=len)

        # PIE address is in reference of Position Independent Executable
        # It is the address relative to the start of the object file
        pie_address: int = 0
        current_offset: int = 0
        basic_blocks: list[BasicBlock] = []

        for packet in packet_trace:
            # Extracting address from address packet
            if isinstance(packet, AddressPacket):
                address_packet: AddressPacket = packet
                pie_address = address_packet.address - PerfReportParser.PROGRAM_START_ADDRESS

            # Extracting basic block(s) from atom packet
            if isinstance(packet, AtomPacket):
                atom_packet: AtomPacket = packet

                # Search the function the address in the function dict
                optional_func_info: FunctionInfo | None = func_dict.find_function_by_address(pie_address)

                # If None, this means the  obtained address is outside the traced binary
                if optional_func_info is None:
                    continue

                # Check if it is one of the libc setup/teardown functions
                func_info: FunctionInfo = optional_func_info
                if func_info.name in PerfReportParser.AVOIDED_FUNC_NAMES:
                    continue

                # Offset in the function
                current_offset = pie_address - func_info.address

                for atom_element in atom_packet.elements:
                    # Extract instructions
                    basic_block: BasicBlock
                    basic_block = self.process_basic_block(
                        func_info=func_info, current_offset=current_offset, pie_address=pie_address
                    )
                    # Publish the basic block and address info
                    basic_blocks.append(basic_block)

                    # Update offset
                    current_offset += basic_block.size - 4
                    current_instruction: bytes = func_info.instructions[current_offset // 4]

                    # Process the address of the next basic block
                    # - Branch taken
                    if atom_element == "E" and Disassembler.is_direct_branch(current_instruction):
                        pie_address = (
                            func_info.address
                            + current_offset
                            + Disassembler.extract_branch_target(current_instruction)
                        )
                        optional_func_info = func_dict.find_function_by_address(pie_address)
                        if optional_func_info:
                            func_info = optional_func_info
                            current_offset = pie_address - func_info.address
                        # TODO: add else exception
                    # - Branch not taken
                    elif atom_element == "N":
                        current_offset += 4
                        pie_address = func_info.address + current_offset

        return ExecutionTrace(
            address_trace=[bb.address for bb in basic_blocks],
            basic_blocks={bb.address: bb for bb in basic_blocks},
        )

    def process_basic_block(
        self, func_info: FunctionInfo, current_offset: int, pie_address: int
    ) -> BasicBlock:
        current_instruction: bytes = func_info.instructions[current_offset // 4]
        instructions: list[bytes] = []
        while not Disassembler.is_branch(current_instruction):
            instructions.append(current_instruction)
            current_offset += 4
            current_instruction = func_info.instructions[current_offset // 4]
        # Add the branch!
        instructions.append(current_instruction)
        return BasicBlock(
            function_address=func_info.address,
            function_name=func_info.name,
            address=pie_address,
            instructions=instructions,
        )
