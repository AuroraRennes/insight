class DslError(Exception):
    pass


class DslSyntaxError(DslError):
    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message if line is None else f"line {line}: {message}")
