import datetime
import logging
import os
import random
import shutil
from pathlib import Path

import pytest
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

from onsight.helpers import bytes_to_int

# =================================================
#                  Logging setup
# =================================================


TEST_LOG_DIR = "log/tests/"

if not Path(TEST_LOG_DIR).exists():
    Path(TEST_LOG_DIR).mkdir()

SEED = bytes_to_int(os.urandom(16))
random.seed(SEED)

logger = logging.getLogger("onsight")


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
        shutil.copy("log/onsight.log", test_log)
        # Keep only 10 newest files
        log_files = [file for file in os.listdir(TEST_LOG_DIR) if "test_run" in file]
        full_paths = [Path(TEST_LOG_DIR) / file for file in log_files]
        full_paths.sort(key=os.path.getmtime, reverse=True)
        for file in full_paths[9:]:
            Path.unlink(file)

    request.addfinalizer(fin)


# =================================================
#                    Capstone
# =================================================


@pytest.fixture
def cap_disasm_setup():
    return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
