from typing import TYPE_CHECKING

import pytest

from onsight.exceptions import ShadowStackError
from onsight.parsers.perf_script_parser import PerfScriptParser
from onsight.verifiers.shadow_stack_verifier import ShadowStackVerifier
from tests.conftest import PERF_BREAKING_DISASM_FILE, PERF_COMPLYING_DISASM_FILES

if TYPE_CHECKING:
    from onsight.execution_trace import ExecutionTrace


@pytest.mark.parametrize(
    "mock_file",
    [
        (
            [
                "ARM CoreSight Trace Data Assembler Dump\n",
                "\t0000000000000100 <main>:\n",
                "\t 100:\t9400000b \tbl 130\n",  # bl #0x2c
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "\t0000000000000130 <callee1>:\n",
                "\t 130:\t9400000b \tbl 150\n"  # bl #0x2c
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "\t0000000000000150 <callee2>:\n",
                "\t 150:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "\t0000000000000130 <callee1+0x4>:\n",
                "\t 134:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "\t0000000000000100 <main>:\n",
                "\t 104:\td65f03c0 \tret\n",
                "\t dummy_func  123/123  [0001]\n",  # break disasm regex
                "End\n",
            ]
        )
    ],
    indirect=["mock_file"],
)
def test_shadow_stack_verification_passed(mock_file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse("dummy_path.perf.disasm.log")
    verifier: ShadowStackVerifier = ShadowStackVerifier()

    assert verifier.verify_trace(exec_trace=exec_trace)


# Tests using data files
# \_______________________


@pytest.mark.parametrize("file", PERF_COMPLYING_DISASM_FILES)
def test_complying_data_files(file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse(file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    assert verifier.verify_trace(exec_trace=exec_trace)


@pytest.mark.parametrize("file", PERF_BREAKING_DISASM_FILE)
def test_breaking_files(file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse(file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    with pytest.raises(ShadowStackError):
        verifier.verify_trace(exec_trace=exec_trace)
