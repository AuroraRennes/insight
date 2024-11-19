import pytest

from onsight.parsers.perf_report_parser import PerfReportParser
from tests.conftest import DUMP_FILES, PERF_REPORT_FILES

test_data = list(zip(PERF_REPORT_FILES, DUMP_FILES, strict=False))


# Smoke test
@pytest.mark.parametrize(("report_file", "dump_file"), list(zip(PERF_REPORT_FILES, DUMP_FILES, strict=False)))
def test_complying_data_files(report_file, dump_file):
    parser: PerfReportParser = PerfReportParser()
    parser.parse(file_name=report_file, dump_file_name=dump_file)
