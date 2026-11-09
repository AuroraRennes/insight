import datetime as dt
import logging
import os
import random
import shutil
from pathlib import Path

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
        timestamp = dt.datetime.now(tz=dt.UTC).strftime("%Y-%m-%d_%H-%M-%S")
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
