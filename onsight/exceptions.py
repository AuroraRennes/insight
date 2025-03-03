# Parsing exceptions
# \___________________


class ParserError(Exception):
    pass


# Perf report
# ---


class NoDumpFileError(ParserError):
    def __init__(self) -> None:
        super().__init__("The dump file of the traced binary is required to extract execution information.")


class TraceSizeError(ParserError):
    def __init__(self, expected_size: int, size: int, cpu_nb: int) -> None:
        super().__init__(
            f"Trace of CPU n{cpu_nb} is expected to be {hex(expected_size)} long, was {hex(size)} long."
        )


class WrongSizeAtomPacketError(ParserError):
    def __init__(self, expected_size: int, size: int) -> None:
        super().__init__(f"Expected {expected_size} elements, got {size} for atom packet.")


class NoMatchingAddressError(ParserError):
    def __init__(self) -> None:
        super().__init__(
            "Address packets are expected to have an address:"
            "'I_ADDR_L_64IS0 : Address, Long, 64 bit, IS0.;"
            "Addr=0x0000AAAAAAAA085C;' (address '0x0000AAAAAAAA085C' here)"
        )


class NoMatchingAddressContextError(ParserError):
    def __init__(self) -> None:
        super().__init__(
            "Address context packets are expected to have an address and a context:"
            "'I_ADDR_CTXT_L_64IS0 : Address & Context, Long, 64 bit, IS0.;"
            "Addr=0x0000AAAAAAAA085C; Ctxt: AArch64,EL0, NS;'"
            "(address '0x0000AAAAAAAA085C', context 'AArch64,EL0,NS' here)"
        )


class NoMatchingInfoError(ParserError):
    def __init__(self) -> None:
        super().__init__(
            "Trace info packets are expected to have information:"
            "'I_TRACE_INFO : Trace Info.; INFO=0x0 { CC.0 }' (0x0 here)"
        )


class NoMatchingElementsError(ParserError):
    def __init__(self) -> None:
        super().__init__(
            "Atom packets are expected to have elements:'I_ATOM_F3 : Atom format 3.; NNE' (NNE here)"
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
