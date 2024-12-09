import json
import logging
from pathlib import Path
from typing import Any

from onsight.constants import DATA_JSON
from onsight.execution_trace import ExecutionTrace

logger = logging.getLogger("onsight")


class Serializer:
    @staticmethod
    def store_execution_trace(exec_trace: ExecutionTrace, json_file_name: str) -> None:
        try:
            with (Path(DATA_JSON) / json_file_name).open(mode="w") as json_file:
                json.dump(exec_trace.to_dict(), json_file, indent=2, separators=(",", ": "))
        except OSError:
            logger.exception("[-] Failed to serialize execution trace")
            raise

    @staticmethod
    def load_execution_trace(json_file_name: str) -> ExecutionTrace:
        try:
            with Path(json_file_name).open(mode="r") as json_file:
                json_data: dict[Any, Any] = json.load(json_file)
                execution_trace: ExecutionTrace = ExecutionTrace.from_dict(json_data)
        except OSError:
            logger.exception("[-] Failed to deserialize execution trace")
        return execution_trace
