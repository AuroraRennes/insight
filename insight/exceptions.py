# Packet parsing errors


class PacketParserError(Exception):
    pass


class NoPacketMatchError(PacketParserError):
    def __init__(self, line: str) -> None:
        super().__init__(
            f"No packet matched the one in line: {line}. Is this packet supported by the parser?"
        )


class MatchNoParseError(PacketParserError):
    def __init__(self, name: str) -> None:
        super().__init__(f"Packet {name} matched but no corresponding parsing method was found.")


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


class NoMatchingDescriptionError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Exception packets are expected to have a description: 'I_EXCEPT : Exception.; Data Fault;"
            " ...' (Data fault here)"
        )


class NoMatchingVersionError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Version packets are expected to have a version number: 'VERSION:Version packet; Ver=3' (3 here)"
        )


class NoMatchingChannelError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "M8 Master packets are expected to have a channel: 'M8:Set current master; Master=0x48'"
            " (0x48 here)"
        )


class NoMatchingDataError(PacketParserError):
    def __init__(self) -> None:
        super().__init__(
            "Data packets are expected to have a size and hold data: 'D64M:64 bit data + marker; "
            "Data=0x0000fffffa3617b0' (64 size and  =0x0000fffffa3617b0 value here)"
        )


# Trace decoder exceptions
# \___________________________


# Deformatter /


class DeformatterError(Exception):
    pass


class IncompleteFrameError(DeformatterError):
    def __init__(self, size: int) -> None:
        super().__init__(f"Cannot deformat frame, expecting 128 bits, got {size}.")


# Decoder /


class DecoderError(Exception):
    pass


class HeaderNotRecognizedError(DecoderError):
    def __init__(self, header: int) -> None:
        super().__init__(f"Header {bin(header)} not recognized.")


class UnimplementedSectionError(DecoderError):
    def __init__(self, section: str) -> None:
        super().__init__(f"Trace info packet section {section} decoding is not implemented.")


class UnimplementedAddressRegError(DecoderError):
    def __init__(self, address_reg: int) -> None:
        super().__init__(f"Address register {address_reg} unimplemented, expecting only one register.")


class UnknownSTMOpcodeError(DecoderError):
    def __init__(self, trace_offset: int, nibble_selector: int) -> None:
        super().__init__(
            f"Invalid STM opcode sequence at offset {trace_offset}, "
            f"nibble {'low' if nibble_selector == 0 else 'high'}"
        )
