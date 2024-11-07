from logging.config import fileConfig
from pathlib import Path

if not Path("log/").exists():
    Path("log/").mkdir()

fileConfig("logging.ini", disable_existing_loggers=False)
