import pytest

from insight.perf.perf_report_parser import PerfReportParser
from tests.conftest import DUMP_FILES, PERF_BASE_REPORT_FILES, PERF_BB_REPORT_FILES


# Smoke test
@pytest.mark.parametrize(
    ("report_file", "dump_file"), list(zip(PERF_BASE_REPORT_FILES, DUMP_FILES, strict=False))
)
def test_complying_base_data_files(report_file, dump_file):
    parser: PerfReportParser = PerfReportParser()
    parser.parse(file_name=report_file, dump_file_name=dump_file)


# Smoke test
@pytest.mark.parametrize(
    ("report_file", "dump_file"), list(zip(PERF_BB_REPORT_FILES, DUMP_FILES, strict=False))
)
def test_complying_bb_data_files(report_file, dump_file):
    parser: PerfReportParser = PerfReportParser()
    parser.parse(file_name=report_file, dump_file_name=dump_file)
