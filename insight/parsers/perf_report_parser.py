import logging
import re
from dataclasses import dataclass
from io import TextIOWrapper
from pathlib import Path

from insight.exceptions import (
    PacketParserError,
    PerfParserError,
    TraceSizeError,
)
from insight.execution_trace import ExecutionTrace
from insight.helpers import string_to_int
from insight.packet_processor import PacketProcessor
from insight.packets import (
    Packet,
)
from insight.parsers.objdump_parser import FunctionDict, ObjdumpParser
from insight.parsers.packet_parser import PacketParser
from insight.parsers.parser import Parser

logger = logging.getLogger("insight")


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
    TRACE_START_LINE_REGEX: str = r"\. \.\.\. CoreSight ETMV4I Trace data: size (?P<trace_size>0x\w+) bytes"

    def __init__(self) -> None:
        super().__init__(extension=".perf.report")

    def parse(self, file_name: str, *args: str, **kwargs: str) -> ExecutionTrace:
        try:
            dump_file_name: str = kwargs["dump_file_name"]
        except KeyError:
            logger.exception("[-] Missing file dump.")
            raise

        # Check extension
        self.check_extension(file_name)

        # Main parsing function
        try:
            with Path(file_name).open() as perf_report_file:
                cpu_nb: int = 0
                cpu_packets: list[list[Packet]] = []
                for line in perf_report_file:
                    match_start: re.Match[str] | None = re.search(
                        PerfReportParser.TRACE_START_LINE_REGEX, line
                    )
                    if match_start:
                        group: dict[str, str] = match_start.groupdict()
                        trace_size: int = string_to_int(group["trace_size"])
                        packets: list[Packet] = self.parse_cpu_trace(
                            perf_report_file=perf_report_file, cpu_nb=cpu_nb, trace_size=trace_size
                        )
                        cpu_packets.append(packets)
                        cpu_nb += 1
        except (OSError, PerfParserError):
            logger.exception("[-] Perf report parsing Failed.")
            raise

        # Extract the function dict from the dump
        func_dict: FunctionDict = ObjdumpParser.parse_dump(dump_file_name)

        # Choose the packet trace to use (TODO: cli argument?)
        # then process it
        packet_trace: list[Packet] = max(cpu_packets, key=len)
        packet_processor: PacketProcessor = PacketProcessor(func_dict=func_dict)

        return packet_processor.process_packets(
            packet_trace=packet_trace,
            func_dict=func_dict,
            start_address=PerfReportParser.PROGRAM_START_ADDRESS,
        )

    def parse_cpu_trace(self, perf_report_file: TextIOWrapper, cpu_nb: int, trace_size: int) -> list[Packet]:
        packets: list[Packet] = []
        packet_parser: PacketParser = PacketParser()

        # Matching the base info of a packet
        line: str = next(perf_report_file)
        match_line: re.Match[str] | None = re.search(PacketParser.PACKET_BASE_REGEX, line)
        while match_line:
            try:
                packets.append(packet_parser.parse_packet(line, cpu_nb))
            except PacketParserError:
                logging.exception("[-] Packet parsing failed.")
                raise

            line = next(perf_report_file)
            match_line = re.search(PacketParser.PACKET_BASE_REGEX, line)

        parsed_size: int = trace_size
        if parsed_size != trace_size:
            raise TraceSizeError(expected_size=trace_size, size=parsed_size, cpu_nb=cpu_nb)
        return packets
