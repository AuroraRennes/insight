import logging
import re
from io import TextIOWrapper
from pathlib import Path

from onsight.exceptions import TraceSizeError
from onsight.execution_trace import ExecutionTrace
from onsight.helpers import string_to_int
from onsight.packets import Packet
from onsight.parsers.parser import Parser

logger = logging.getLogger("onsight")


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

    # REGEXES
    TRACE_START_LINE_REGEX: str = r"\. \.\.\. CoreSight ETMV4I Trace data: size (0x\w+) bytes"
    PACKET_ELEMENTS_REGEX: tuple[str, ...] = (
        r"(; Addr=0x\w+)?",  # Address, in address    ...; Addr=0xFFFF800008AA4BE0;
        r"(; Ctxt: [,\s\w]*)?",  # Context, in address    ...; Ctxt: AArch64,EL0, NS;
        r"(; [EN]+)?",  # Basic blocks, in atoms ...;  Atom format 3.; ENE
        r"(; INFO=0x\w+ \{[\s\w.]*\})?",  # Info, in trace info    ...; INFO=0x0 { CC.0 };
    )
    # Base regex, then composed:
    # Holds                   index      id      name     description
    #                           v         v        v          v
    PACKET_BASE_REGEX: str = r"Idx:(\d+); ID:(\d+);\s(\w*)\s: ([\s\w,&]*)."
    PACKET_COMPLETE_REGEX: str = PACKET_BASE_REGEX + "".join(PACKET_ELEMENTS_REGEX)

    def __init__(self) -> None:
        super().__init__(extension=".perf.dump")

    def parse(self, file_name: str) -> ExecutionTrace:
        # Check extension
        self.check_extension(file_name)

        # Execution trace initialization
        exec_trace: ExecutionTrace = ExecutionTrace(address_trace=[], basic_blocks={})

        # Main parsing function
        try:
            with Path(file_name).open() as perf_dump_file:
                cpu_nb: int = 0
                for line in perf_dump_file:
                    match_start: re.Match[str] | None = re.search(
                        PerfReportParser.TRACE_START_LINE_REGEX, line
                    )
                    if match_start:
                        trace_size: int = string_to_int(match_start.group(1))
                        packets: list[Packet] = self.parse_cpu_trace(
                            perf_dump_file=perf_dump_file, cpu_nb=cpu_nb, trace_size=trace_size
                        )
                        cpu_nb += 1
        except OSError:
            logger.exception("[-] Parsing Failed.")
            raise
        else:
            self.process_packets(packets)

        return exec_trace

    def parse_cpu_trace(self, perf_dump_file: TextIOWrapper, cpu_nb: int, trace_size: int) -> list[Packet]:
        packets: list[Packet] = []

        line: str = next(perf_dump_file)
        match_line: re.Match[str] | None = re.search(PerfReportParser.PACKET_COMPLETE_REGEX, line)
        while match_line:
            pass

        parsed_size: int = len(packets) * 8
        if parsed_size != trace_size:
            raise TraceSizeError(expected_size=trace_size, size=parsed_size, cpu_nb=cpu_nb)
        return packets

    def process_packets(self, packets: list[Packet]) -> None:
        pass
