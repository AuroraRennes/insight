import logging
import re
from io import TextIOWrapper
from pathlib import Path

from onsight.basic_block import BasicBlock
from onsight.disassembler import Disassembler
from onsight.exceptions import NoEndLineError, WrongStartLineError
from onsight.execution_trace import ExecutionTrace
from onsight.helpers import reverse_endianness, string_to_bytes, string_to_int

logger = logging.getLogger("onsight")


class PerfScriptParser:
    # The PerfScriptParser extract basic blocks from the execution.
    #
    # As an example, a part of the execution script might looklike:
    # 00000000000007d8 <callee>:
    #  7d8:	d503245f 	bti	c
    #  7dc:	d10043ff 	sub	sp, sp, #0x10
    #  7e0:	b9000fe0 	str	w0, [sp, #12]
    #  7e4:	b9400fe0 	ldr	w0, [sp, #12]
    #  7e8:	7100041f 	cmp	w0, #0x1
    #  7ec:	54000061 	b.ne	7f8 <callee+0x20>    // b.any
    #  7f0:	52800000 	mov	w0, #0x0                 // #0
    #  7f4:	14000002 	b	7fc <callee+0x24>
    #  simple_call  1592/1592  [0002]   0.000000000   callee+0x1c
    # 00000000000007fc <callee+0x24>:
    # ...
    #
    # In this case, two basic blocks should be extracted:
    # BB1: 7d8 - 7ec (last branch NOT TAKEN)
    # BB2: 7f0 - 7f4 (last branch TAKEN)

    # REGEXES
    TRACE_START_LINE: str = "ARM CoreSight Trace Data Assembler Dump"
    TRACE_END_LINE: str = "End"
    # Regex line   00000000000007f8 <main+0x20>:
    #  matches     00000000000007f8  main

    # Alternative with offset from function symbol
    START_FUNCTION_REGEX: str = r"([\w\._]*) <([\w\._]+)(\+0x\w+)?>:"
    # Regex line   828:  b9801fe0  ldrsw  x0, [sp, #28]
    #  matches     828   b9801fe0  ldrsw
    DISASM_LINE_REGEX: str = r"(\w+):\s+(\w+)\s+(\w+[\.\w*]*)"

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

    def parse_disasm_log(self, disasm_log_file: str) -> ExecutionTrace:
        # Execution trace initialization
        exec_trace = ExecutionTrace(address_trace=[], basic_blocks={})

        # Main parsing function
        try:
            with Path(disasm_log_file).open() as disasm_file:
                # Check first line
                if PerfScriptParser.TRACE_START_LINE not in next(disasm_file).strip():
                    raise WrongStartLineError

                # Extracted list of basic blocks
                basic_blocks: list[BasicBlock] = []

                # Iterate over the file to extract basic blocks
                for line in disasm_file:
                    trace_end: bool = line.strip() == PerfScriptParser.TRACE_END_LINE
                    match_start: re.Match[str] | None = re.search(PerfScriptParser.START_FUNCTION_REGEX, line)

                    if match_start:
                        function_address: int = string_to_int(match_start.group(1))
                        function_name: str = match_start.group(2)
                        if match_start.group(3):
                            function_address = function_address - string_to_int(match_start.group(3))

                        if function_name in PerfScriptParser.AVOIDED_FUNC_NAMES:
                            continue
                        basic_blocks += self.parse_function(
                            disasm_file=disasm_file,
                            function_address=function_address,
                            function_name=function_name,
                        )

                if not trace_end:
                    raise NoEndLineError

        # Parsing failed
        except (OSError, WrongStartLineError, NoEndLineError):
            logger.exception("Parsing Failed.")
            raise
        else:
            # Note: not extracting basic blocks already present might be faster?
            exec_trace = ExecutionTrace(
                address_trace=[bb.address for bb in basic_blocks],
                basic_blocks={bb.address: bb for bb in basic_blocks},
            )

        return exec_trace

    def parse_function(
        self, disasm_file: TextIOWrapper, function_address: int, function_name: str
    ) -> list[BasicBlock]:
        basic_blocks: list[BasicBlock] = []

        line: str = next(disasm_file)
        match_line: re.Match[str] | None = re.search(PerfScriptParser.DISASM_LINE_REGEX, line)
        bb_address: int = string_to_int(match_line.group(1)) if match_line else 0
        instructions: list[bytes] = []
        while match_line:
            # Instruction information
            instr_address: int = string_to_int(match_line.group(1))
            bb_address = instr_address if (bb_address == -1) else bb_address
            instr_bytes: bytes = reverse_endianness(string_to_bytes(match_line.group(2)))
            instr_mnemonic: str = match_line.group(3)
            # Add bytes to the instruction
            instructions.append(instr_bytes)

            # End of basic block, should
            if Disassembler.is_str_branch(instr_mnemonic):
                basic_blocks.append(
                    BasicBlock(
                        function_address=function_address,
                        function_name=function_name,
                        address=bb_address,
                        instructions=instructions,
                    )
                )
                # FIXME: Dirty way of passing the address
                bb_address = -1
                instructions = []

            # Next one!
            line = next(disasm_file)
            match_line = re.search(PerfScriptParser.DISASM_LINE_REGEX, line)

        return basic_blocks
