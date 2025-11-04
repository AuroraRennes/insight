import datetime
import io
import logging
import os
import random
import shutil
from pathlib import Path
from typing import Any

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from insight.helpers import bytes_to_int

# Logging setup
# \______________


TEST_LOG_DIR = "log/tests/"

if not Path(TEST_LOG_DIR).exists():
    Path(TEST_LOG_DIR).mkdir()

SEED = bytes_to_int(os.urandom(16))
random.seed(SEED)

logger = logging.getLogger("insight")


@pytest.fixture(scope="session", autouse=True)
def log_seed() -> None:
    logger.info(f"🌱 Seed for this test run: {SEED}")


@pytest.fixture(scope="session", autouse=True)
def move_log_file(request: pytest.FixtureRequest) -> None:
    def fin() -> None:
        logger.info("Test run complete 🏁")
        # Set up name format  for test logfiles
        timestamp = datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d_%H-%M-%S")
        test_log = f"{TEST_LOG_DIR}test_run_{timestamp}.log"
        shutil.copy("log/insight.log", test_log)
        # Keep only 10 newest files
        log_files = [file for file in Path(TEST_LOG_DIR).iterdir() if "test_run" in file.name]
        log_files.sort(key=os.path.getmtime, reverse=True)
        for file in log_files[9:]:
            Path.unlink(file)

    request.addfinalizer(fin)


# Base logging disabled
@pytest.fixture(autouse=True)
def disable_logger(caplog):
    caplog.set_level(logging.CRITICAL, logger="insight")


# Can be reactivated on a given test by passing the 'log_test' argument
@pytest.fixture
def log_test(request, caplog):
    caplog.set_level(logging.DEBUG, logger="insight")
    logger.info(f"Tracing test '{request.node.name}'  🚀")

    def fin() -> None:
        logger.info(f"Trace complete for test '{request.node.name}' 🏁")
        caplog.set_level(logging.CRITICAL, logger="insight")

    request.addfinalizer(fin)


# Capstone Disassembler
# \______________________


@pytest.fixture
def cap_disasm_setup():
    return Cs(CS_ARCH_ARM64, CS_MODE_ARM)


# Reusable fixtures
# \__________________


# Parametrizable fixture, use @pytest.mark.parametrize with 'indirect'
# set up to pass a corresponding file (list[str]). For example:
# @pytest.mark.parametrize(
#   "mock_file", [ (["line1\n", "line2\n"]) ], indirect=["mock_file"]
# )
@pytest.fixture
def mock_file(monkeypatch, request):
    # Retrive the file content from the test parameter
    file_content = request.param

    # Custom open function to use StringIO instead of an actual file
    def mock_open(*args: tuple, **kwargs: dict[str, Any]) -> io.StringIO:
        return io.StringIO("".join(file_content))

    monkeypatch.setattr(Path, "open", mock_open)


# Perf related data files
# \_________________________

DATA_DIR = "data/perf"
BREAKING_FILES: list[str] = ["stack_overflow"]


def find_files_with_extension(subdir: str, extension: str) -> list[Path]:
    return sorted(Path.glob(Path(DATA_DIR) / subdir, extension))


def filter_files(path_list: list[Path], comply: bool) -> list[Path]:
    return [
        path
        for path in path_list
        if all((breaking_file_name in path.as_posix()) != comply for breaking_file_name in BREAKING_FILES)
    ]


# Dumps
DUMP_FILES: list[Path] = find_files_with_extension("bin/", "*.dump")
# Base
PERF_BASE_REPORT_FILES: list[Path] = find_files_with_extension("base/", "*.perf.report")
PERF_BASE_SCRIPT_FILES: list[Path] = find_files_with_extension("base/", "*.perf.script")
# Branch broadcast
PERF_BB_REPORT_FILES: list[Path] = find_files_with_extension("branch_broadcast/", "*.perf.report")
PERF_BB_SCRIPT_FILES: list[Path] = find_files_with_extension("branch_broadcast/", "*.perf.script")
