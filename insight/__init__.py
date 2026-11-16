from logging.config import fileConfig
from pathlib import Path

# The logging configuration and the log directory are the checkout's, wherever insight runs from
ROOT = Path(__file__).resolve().parent.parent
(ROOT / "log").mkdir(exist_ok=True)

fileConfig(ROOT / "logging.ini", defaults={"logdir": str(ROOT / "log")}, disable_existing_loggers=False)
