from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from insight.model.execution_trace import ExecutionTrace

logger = logging.getLogger("insight")


class Parser(ABC):
    @abstractmethod
    def parse(self, file_name: str, *args: str, **kwargs: str) -> ExecutionTrace:
        pass
