class DslError(Exception):
    pass


class DslSyntaxError(DslError):
    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message if line is None else f"line {line}: {message}")


class AliasUndecidedError(DslError):
    """Two memory addresses may or may not be equal: composition cannot go on."""

    def __init__(self, a: object, b: object) -> None:
        super().__init__(f"cannot decide whether M[{a}] and M[{b}] are the same byte")
        self.a = a
        self.b = b


class OpaqueError(DslError):
    """An opaque statement (svc, unsupported) where the transfer's meaning is needed."""


class InstructionFormError(DslError):
    """A send or an <Xn> where only block-form terms are allowed."""
