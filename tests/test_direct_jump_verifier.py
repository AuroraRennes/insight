from typing import TYPE_CHECKING

import pytest

from insight.parsers.perf_script_parser import PerfScriptParser
from insight.verifiers.direct_jump_verifier import DirectJumpVerifier
from tests.conftest import PERF_BASE_SCRIPT_FILES, PERF_BB_SCRIPT_FILES

if TYPE_CHECKING:
    from insight.execution_trace import ExecutionTrace


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "ARM CoreSight Trace Data Assembler Dump\n",
                "\t0000000000000100 <main>:\n",
                "\t 100:\t1400000c \tb 140\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "\t0000000000000140 <main+0x40>:\n",
                "\t 140:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "End\n",
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_direct_jump_verification_passed(mock_file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse("dummy_path.perf.script")
    verifier: DirectJumpVerifier = DirectJumpVerifier()

    assert verifier.verify_trace(exec_trace=exec_trace)


@pytest.mark.parametrize("file", PERF_BASE_SCRIPT_FILES + PERF_BB_SCRIPT_FILES)
def test_data_files(file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse(file)
    verifier: DirectJumpVerifier = DirectJumpVerifier()
    assert verifier.verify_trace(exec_trace=exec_trace)
