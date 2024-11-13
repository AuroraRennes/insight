# Parsing exceptions
# \___________________


class ParserError(Exception):
    pass


# Perf report
# ---


class TraceSizeError(ParserError):
    def __init__(self, expected_size: int, size: int, cpu_nb: int) -> None:
        super().__init__(
            f"Trace of CPU n{cpu_nb} is expected to be {hex(expected_size)} long, was {hex(size)} long."
        )


# Perf script
# ---


class WrongExtensionError(ParserError):
    def __init__(self, expected_extension: str, extension: str) -> None:
        super().__init__(f"This parser expects files with '{expected_extension}', got '{extension}'")


class WrongStartLineError(ParserError):
    def __init__(self) -> None:
        super().__init__("perf script trace should start with 'ARM CoreSight Trace Data Assembler Dump'.")


class NoEndLineError(ParserError):
    def __init__(self) -> None:
        super().__init__("perf script trace should end with 'End'.")


# Verifier exceptions
# \___________________


class VerifierError(Exception):
    pass


class ShadowStackError(VerifierError):
    def __init__(self, expected_address: int, address: int) -> None:
        super().__init__(
            f"Return address do not match. Got {hex(address)}, expected {hex(expected_address)}."
        )


class DirectJumpError(VerifierError):
    def __init__(self, expected_function: str, function: str) -> None:
        super().__init__(
            f"Direct jumps should stay in the same function. Got '{function}', expected '{expected_function}'"
        )
