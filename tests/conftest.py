import logging
import os
import random
import pytest
import shutil
from datetime import datetime

from onsight.helpers import bytes_to_int

# =================================================
#                  Logging setup
# =================================================


TEST_LOG_DIR = "log/tests/"

if not os.path.exists(TEST_LOG_DIR):
    os.mkdir(TEST_LOG_DIR)

SEED = bytes_to_int(os.urandom(16))
random.seed(SEED)

logger = logging.getLogger("onsight")


@pytest.fixture(scope="session", autouse=True)
def log_seed():
    logger.info(f"🌱 Seed for this test run: {SEED}")


@pytest.fixture(scope="session", autouse=True)
def move_log_file(request):
    def fin():
        logger.info("Test run complete 🏁")
        # Set up name format  for test logfiles
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        test_log = f"{TEST_LOG_DIR}test_run_{timestamp}.log"
        shutil.copy("log/onsight.log", test_log)
        # Keep only 10 newest files
        log_files = [file for file in os.listdir(TEST_LOG_DIR) if "test_run" in file]
        full_paths = [os.path.join(TEST_LOG_DIR, file) for file in log_files]
        full_paths.sort(key=os.path.getmtime, reverse=True)
        for file in full_paths[9:]:
            os.remove(file)

    request.addfinalizer(fin)
