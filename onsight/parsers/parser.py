from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from onsight.exceptions import WrongExtensionError

if TYPE_CHECKING:
    from onsight.execution_trace import ExecutionTrace

logger = logging.getLogger("onsight")


class Parser(ABC):
    def __init__(self, extension: str) -> None:
        self.extension = extension

    @abstractmethod
    def parse(self, file: str) -> ExecutionTrace:
        pass

    def check_extension(self, file_name: str) -> None:
        extension: str = "".join(Path(file_name).suffixes)
        if extension != self.extension:
            raise WrongExtensionError(expected_extension=self.extension, extension=extension)

    @staticmethod
    def for_perf_disasm_log() -> Parser:
        from onsight.parsers.perf_script_parser import PerfScriptParser

        return PerfScriptParser()
