from typing import TYPE_CHECKING

import pytest

from insight.disassembler import Disassembler
from insight.exceptions import NoEndLineError, WrongStartLineError
from insight.parsers.perf_script_parser import PerfScriptParser
from tests.conftest import PERF_BASE_SCRIPT_FILES, PERF_BB_SCRIPT_FILES

if TYPE_CHECKING:
    from insight.basic_block import BasicBlock
    from insight.execution_trace import AddressTrace, ExecutionTrace

# Note: The mock_file function is in conftest.py and parametrized for each fake file
#       using pytest parametrization along with the 'indirect' argument


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "\t0000000000000100 <main>:\n",
                "\t 104:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "End\n",
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_missing_start_line(mock_file):
    parser = PerfScriptParser()
    with pytest.raises(WrongStartLineError):
        parser.parse("dummy_path.perf.script")


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "ARM CoreSight Trace Data Assembler Dump\n",
                "\t0000000000000100 <main>:\n",
                "\t 104:\td65f03c0 \tret\n",
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_missing_end_line_in_function(mock_file):
    parser = PerfScriptParser()
    with pytest.raises(NoEndLineError):
        parser.parse("dummy_path.perf.script")


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "ARM CoreSight Trace Data Assembler Dump\n",
                "\t0000000000000100 <main>:\n",
                "\t 104:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_missing_end_line_in_file(mock_file):
    parser = PerfScriptParser()
    with pytest.raises(NoEndLineError):
        parser.parse("dummy_path.perf.script")


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "ARM CoreSight Trace Data Assembler Dump\n",
                "\t0000000000000100 <main>:\n",
                "\t 100:\td503245f \tbti\tc\n",
                "\t 104:\td10083ff \tsub\tsp, sp, #0x20\n",
                "\t 108:\t910083ff \tadd\tsp, sp, #0x20\n",
                "\t 10c:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "End\n",
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_parsing_one_function(mock_file):
    # Values
    main_address: int = 0x100
    main_size: int = 0x10
    parser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse("dummy_path.perf.script")
    # Check address trace
    trace: list[AddressTrace] = exec_trace.trace
    assert len(trace) == 1
    assert trace[0].address == main_address
    assert trace[0].taken
    # Check corresponding basic block
    bbs: dict[int, BasicBlock] = exec_trace.basic_blocks
    assert len(bbs.items()) == 1
    bb: BasicBlock = bbs[main_address]
    assert bb.address == main_address
    assert bb.size == main_size
    assert Disassembler.is_ret(bb.ending_instruction)


# Smoke test
@pytest.mark.parametrize("file", PERF_BASE_SCRIPT_FILES)
def test_complying_base_data_files(file):
    parser: PerfScriptParser = PerfScriptParser()
    parser.parse(file)


# Smoke test
@pytest.mark.parametrize("file", PERF_BB_SCRIPT_FILES)
def test_complying_bb_data_files(file):
    parser: PerfScriptParser = PerfScriptParser()
    parser.parse(file)
