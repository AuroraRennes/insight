# Packet parsing errors


class PacketParserError(Exception):
    pass


class NoPacketMatchError(PacketParserError):
    def __init__(self, line: str) -> None:
        super().__init__(
            f"No packet matched the one in line: {line}. Is this packet supported by the parser?"
        )


class WrongSizeAtomPacketError(PacketParserError):
    def __init__(self, expected_size: int, size: int) -> None:
        super().__init__(f"Expected {expected_size} elements, got {size} for atom packet.")


class NoMatchingAddressError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Address packets are expected to have an address:"
            "'I_ADDR_L_64IS0 : Address, Long, 64 bit, IS0.;"
            "Addr=0x0000AAAAAAAA085C;' (address '0x0000AAAAAAAA085C' here)"
        )


class NoMatchingAddressContextError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Address context packets are expected to have an address and a context:"
            "'I_ADDR_CTXT_L_64IS0 : Address & Context, Long, 64 bit, IS0.;"
            "Addr=0x0000AAAAAAAA085C; Ctxt: AArch64,EL0, NS;'"
            "(address '0x0000AAAAAAAA085C', context 'AArch64,EL0,NS' here)"
        )


class NoMatchingInfoError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Trace info packets are expected to have information:"
            "'I_TRACE_INFO : Trace Info.; INFO=0x0 { CC.0 }' (0x0 here)"
        )


class NoMatchingElementsError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Atom packets are expected to have elements:'I_ATOM_F3 : Atom format 3.; NNE' (NNE here)"
        )


# Parsing exceptions
# \___________________


class PerfParserError(Exception):
    pass


# Perf report
# ---


class NoDumpFileError(PerfParserError):
    def __init__(self) -> None:
        super().__init__("The dump file of the traced binary is required to extract execution information.")


class TraceSizeError(PerfParserError):
    def __init__(self, expected_size: int, size: int, cpu_nb: int) -> None:
        super().__init__(
            f"Trace of CPU n{cpu_nb} is expected to be {hex(expected_size)} long, was {hex(size)} long."
        )


# Perf script
# ---


class WrongExtensionError(PerfParserError):
    def __init__(self, expected_extension: str, extension: str) -> None:
        super().__init__(f"This parser expects files with '{expected_extension}', got '{extension}'")


class WrongStartLineError(PerfParserError):
    def __init__(self) -> None:
        super().__init__("perf script trace should start with 'ARM CoreSight Trace Data Assembler Dump'.")


class NoEndLineError(PerfParserError):
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


# Annotation exceptions
# \___________________

# ELF /


class ELFError(Exception):
    pass


class MissingSectionError(ELFError):
    def __init__(self) -> None:
        super().__init__("Missing ELF section.")


class EmptySectionError(ELFError):
    def __init__(self) -> None:
        super().__init__("Empty ELF section.")


# Parsing /


class AnnotationParsingError(Exception):
    pass


class MissingENDBlockError(AnnotationParsingError):
    def __init__(self) -> None:
        super().__init__("Missing END block.")


class MissingOperatorError(AnnotationParsingError):
    def __init__(self, rhs: str) -> None:
        super().__init__(f"No operator found in RHS with multiple operands: {rhs}")


class NoMatchDestinationError(AnnotationParsingError):
    def __init__(self, lhs: str) -> None:
        super().__init__(f"No match for destination in LHS: {lhs}")


class NoMatchOperandError(AnnotationParsingError):
    def __init__(self, operand: str) -> None:
        super().__init__(f"No match for operand {operand}")


class WrongOffsetValueError(AnnotationParsingError):
    def __init__(self) -> None:
        super().__init__("Incorrect offset value, should be register or immediate")


# Interpretation /


class AnnotationInterpretationError(Exception):
    pass


class OperatorNotDefinedError(AnnotationInterpretationError):
    def __init__(self, operator: str) -> None:
        super().__init__(f"Unknown operator {operator}")


class STMFIFOEmptyError(AnnotationInterpretationError):
    def __init__(self) -> None:
        super().__init__("STM FIFO empty while trying to pop.")


class StateError(AnnotationInterpretationError):
    pass


class UndefinedRegisterError(StateError):
    def __init__(self, reg: str) -> None:
        super().__init__(f"Register unknown {reg}")
