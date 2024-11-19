from typing import TYPE_CHECKING

import pytest

from onsight.exceptions import ShadowStackError
from onsight.parsers.perf_report_parser import PerfReportParser
from onsight.parsers.perf_script_parser import PerfScriptParser
from onsight.verifiers.shadow_stack_verifier import ShadowStackVerifier
from tests.conftest import (
    DUMP_FILES,
    PERF_REPORT_FILES,
    PERF_SCRIPT_FILES,
    filter_files,
)

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
    exec_trace: ExecutionTrace = parser.parse("dummy_path.perf.script")
    verifier: ShadowStackVerifier = ShadowStackVerifier()

    assert verifier.verify_trace(exec_trace=exec_trace)


# Tests using data files
# \_______________________


@pytest.mark.parametrize("file", filter_files(path_list=PERF_SCRIPT_FILES, comply=True))
def test_complying_data_files_script_parser(file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse(file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    assert verifier.verify_trace(exec_trace=exec_trace)


@pytest.mark.parametrize("file", filter_files(path_list=PERF_SCRIPT_FILES, comply=False))
def test_breaking_files_script_parser(file):
    parser: PerfScriptParser = PerfScriptParser()
    exec_trace: ExecutionTrace = parser.parse(file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    with pytest.raises(ShadowStackError):
        verifier.verify_trace(exec_trace=exec_trace)


@pytest.mark.parametrize(
    ("report_file", "dump_file"),
    list(
        zip(
            filter_files(path_list=PERF_REPORT_FILES, comply=True),
            filter_files(path_list=DUMP_FILES, comply=True),
            strict=False,
        )
    ),
)
def test_complying_data_files_report_parser(report_file, dump_file):
    parser: PerfReportParser = PerfReportParser()
    exec_trace: ExecutionTrace = parser.parse(file_name=report_file, dump_file_name=dump_file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    assert verifier.verify_trace(exec_trace=exec_trace)


@pytest.mark.parametrize(
    ("report_file", "dump_file"),
    list(
        zip(
            filter_files(path_list=PERF_REPORT_FILES, comply=False),
            filter_files(path_list=DUMP_FILES, comply=False),
            strict=False,
        )
    ),
)
def test_breaking_files_report_parser(report_file, dump_file):
    parser: PerfReportParser = PerfReportParser()
    exec_trace: ExecutionTrace = parser.parse(file_name=report_file, dump_file_name=dump_file)
    verifier: ShadowStackVerifier = ShadowStackVerifier()
    with pytest.raises(ShadowStackError):
        verifier.verify_trace(exec_trace=exec_trace)
