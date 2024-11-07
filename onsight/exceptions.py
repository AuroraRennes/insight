# Parsing exceptions
# \___________________


class ParseError(Exception):
    pass


class WrongStartLineError(ParseError):
    def __init__(self) -> None:
        super().__init__("perf script trace should start with 'ARM CoreSight Trace Data Assembler Dump'.")


class NoEndLineError(ParseError):
    def __init__(self) -> None:
        super().__init__("perf script trace should end with 'End'.")
