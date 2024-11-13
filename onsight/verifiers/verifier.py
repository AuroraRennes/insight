from abc import ABC, abstractmethod

from onsight.execution_trace import ExecutionTrace


class Verifier(ABC):
    @abstractmethod
    def verify_trace(self, execution_trace: ExecutionTrace) -> bool:
        pass

    @abstractmethod
    def message(self) -> str:
        pass
