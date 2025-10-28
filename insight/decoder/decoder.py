from typing import ClassVar

from insight.exceptions import HeaderNotRecognizedError, UnimplementedSectionError
from insight.model.packets import (
    AddressContextPacket,
    AddressPacket,
    AtomPacket,
    Context,
    ContextPacket,
    ExceptionPacket,
    IncompletePacket,
    InfoFields,
    InfoPacket,
    Packet,
    PacketInfo,
    SynchronizationPacket,
    TimestampPacket,
    UnknownPacket,
)


class Decoder:
    # From ETM Specification, v4.0 to v4.6, table 6-12
    EXCEPTION_CODES: ClassVar[dict[int, str]] = {
        0b00000: "PE Reset",
        0b00001: "Debug halt",
        0b00010: "Call",
        0b00011: "Trap",
        0b00100: "System Error",
        0b00110: "Inst Debug",
        0b00111: "Data Debug",
        0b01010: "Alignment",
        0b01011: "Inst Fault",
        0b01100: "Data Fault",
        0b01110: "IRQ",
        0b01111: "FIQ",
    }

    def __init__(self, trace_data: bytearray) -> None:
        self.trace_data: bytearray = trace_data
        self.trace_size: int = len(trace_data)
        self.trace_offset: int = 0
        self.remaining_trace: int = self.trace_size - self.trace_offset
        self.vmid: int
        self.cid: int
        self.context: Context
        self.address_reg: int

    def decode_packet(self) -> Packet:  # noqa: C901, PLR0911, PLR0912
        # ruff disabled for this one, it is just a switch case......
        header: int = self.trace_data[self.trace_offset]

        # From ARM ETM Specification (v4.0 to 4.6)

        # Extension packet header: 0b00000000
        if header == 0b00000000:
            return self.decode_extension_packet()

        # Trace Info packet header: 0b00000001
        if header == 0b00000001:
            return self.decode_trace_info_packet()

        # Timestamp packet header: 0b0000001X
        if header == 0b00000010 | 0b00000011:
            return self.decode_timestamp_packet()

        # Trace On packet header: 0b00000100
        if header == 0b00000100:
            return self.decode_trace_on_packet()

        # Exception packet header: 0b00000110
        if header == 0b00000110:
            return self.decode_exception_packet()

        # Exception return packet header: 0b00000111
        if header == 0b00000111:
            return self.decode_exception_return_packet()

        # Resynchronization packet header: 0b00001000
        if header == 0b00001000:
            return self.decode_resynchronization_packet()

        # Context packet header: 0b1000000X
        if header >> 1 == 0b1000000:
            return self.decode_context_packet()

        # 64-bit IS0 long address and context packet header: 0b10000101
        if header == 0b10000101:
            return self.decode_address_long_64_is0_with_context_packet()

        # IS0 short address packet header: 0b10010101
        if header == 0b10010101:
            return self.decode_address_short_is0_packet()

        # 64-bit IS0 long address packet header: 0b10011101
        if header == 0b10011101:
            return self.decode_address_long_64_is0_packet()

        # Atom F6 packet: from 0b11000000 to 0b11010100
        if ((header >= 0b11000000) and (header <= 0b11010100)) or (
            (header >= 0b11100000) and (header <= 0b11110100)
        ):
            return self.decode_atom_f6_packet()

        # Atom F5 packet header: from 0b11010101 to 0b11010111
        if ((header >= 0b11010101) and (header <= 0b11010111)) or (header == 0b11110101):
            return self.decode_atom_f5_packet()

        # Atom F4 packet header: 0b110111XX
        if header >> 2 == 0b110111:
            return self.decode_atom_f4_packet()

        # Atom F3 packet header: 0b11111XXX
        if header >> 3 == 0b11111:
            return self.decode_atom_f3_packet()

        # Atom F2 packet header: 0b110110XX
        if header >> 2 == 0b110110:
            return self.decode_atom_f2_packet()

        # Atom F1 packet header: 0b1111011X
        if header >> 1 == 0b1111011:
            return self.decode_atom_f1_packet()

        raise HeaderNotRecognizedError(header)

    def decode_extension_packet(self) -> Packet:
        # Check minimal number of bytes
        if not self.check_remaining_trace(2):
            return IncompletePacket(index=self.trace_offset)

        # Overflow packet: 1 header byte + 1 payload byte containing 0x5
        if self.trace_data[self.trace_offset + 1] == 0x5:
            return ExceptionPacket.overflow(PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0))

        # Header is correct but missing rest of ASYNC
        if not self.check_remaining_trace(12):
            return IncompletePacket(index=self.trace_offset)

        # Async packet: 10 bytes of 0x00 then one 0x80
        if self.trace_data[self.trace_offset : self.trace_offset + 12] == 0x0000000000000000000080:
            return SynchronizationPacket.asynch(
                PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0)
            )

        return UnknownPacket(index=self.trace_offset)

    def decode_trace_info_packet(self) -> Packet:
        # Check minimal number of bytes, PLCTL of 1 byte
        if not self.check_remaining_trace(2):
            return IncompletePacket(index=self.trace_offset)

        packet_size: int = 2
        # Continuation bit activated for the section PLCTL
        # Note: Not sure why this section might continue? The doc only talks about bits 0-3
        while self.trace_data[packet_size - 1] & 0x80:
            packet_size += 1
            # Check remaining data size
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(index=self.trace_offset)

        plctl_bits: int = self.trace_data[self.trace_offset + 1] & 0x0F
        info_bits: int = 0

        # INFO section
        if plctl_bits & 0x1:
            # Extract information payload
            info_bits = self.trace_data[self.trace_offset + packet_size] & 0x1F

            # Note: Not sure why this section might continue? The doc only talks about bits 0-5
            while self.trace_data[packet_size - 1] & 0x80:
                packet_size += 1
                # Check remaining data size
                if not self.check_remaining_trace(packet_size):
                    return IncompletePacket(index=self.trace_offset)

        # Key section - unimplemented, should not be there
        if plctl_bits & 0x2:
            msg = "KEY"
            raise UnimplementedSectionError(msg)

        # Speculation section - unimplemented, should not be there
        if plctl_bits & 0x4:
            msg = "SPEC"
            raise UnimplementedSectionError(msg)

        # Cycle counting section - unimplemented, should not be there
        if plctl_bits & 0x8:
            msg = "CYCT"
            raise UnimplementedSectionError(msg)

        return InfoPacket.trace_info(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            info_fields=InfoFields(info_bits=info_bits),
        )

    def decode_timestamp_packet(self) -> Packet:
        # Note: These are max values, maybe checking continuation bits is better?
        packet_size: int = 11 if (self.trace_data[self.trace_offset] & 0x1) else 8

        if not self.check_remaining_trace(packet_size):
            return IncompletePacket(self.trace_offset)

        # Note: the timestamp itself is not computed

        return TimestampPacket(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0), timestamp=0
        )

    def decode_trace_on_packet(self) -> Packet:
        return SynchronizationPacket.trace_on(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0)
        )

    def decode_exception_packet(self) -> Packet:
        if not self.check_remaining_trace(2):
            return IncompletePacket(self.trace_offset)

        # Check if the continuation bit is set
        packet_size: int = 2
        if self.trace_data[self.trace_offset + 1] & 0x80:
            packet_size = 3

        if not self.check_remaining_trace(packet_size):
            return IncompletePacket(self.trace_offset)

        # Extract exception details
        # Note: TYPE[9:5] are always 0b00000 for Armv7-A/R and Armv8-A/R PEs.
        exception_code: int = (self.trace_data[self.trace_offset + 1] >> 1) & 0x1F

        return ExceptionPacket.exception(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            description=Decoder.EXCEPTION_CODES[exception_code],
        )

    def decode_exception_return_packet(self) -> Packet:
        return ExceptionPacket.return_exception(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0)
        )

    def decode_resynchronization_packet(self) -> Packet:
        return SynchronizationPacket.resynchronization(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0)
        )

    def decode_context_packet(self) -> Packet:
        packet_size: int = 1
        # Check from the header if the packet has a payload, if not reuse the previous one
        if not self.trace_data[self.trace_offset] & 0x1:
            return ContextPacket.context(
                packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
                context=self.context,
            )

        # Expecting at least one more byte then
        if not self.check_remaining_trace(2):
            return IncompletePacket(self.trace_offset)
        packet_size = 2

        # Extract context values
        byte_info: int = self.trace_data[self.trace_offset + 1]
        context: Context = self.extract_context(byte_info=byte_info)

        # Check for virtual context id
        if byte_info & 0b01000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(self.trace_offset)
            self.vmid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        # Check for context id
        if byte_info & 0b10000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(self.trace_offset)
            self.cid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        return ContextPacket.context(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0), context=context
        )

    def decode_address_long_64_is0_with_context_packet(self) -> Packet:
        if not self.check_remaining_trace(10):
            return IncompletePacket(self.trace_offset)

        # Rebuild address
        address: int = self.extract_address(
            raw_data=self.trace_data[self.trace_offset + 1 : self.trace_offset + 9]
        )
        self.address_reg = address

        packet_size: int = 9

        # Extract context values
        byte_info: int = self.trace_data[self.trace_offset + 1]
        context: Context = self.extract_context(byte_info=byte_info)

        # Check for virtual context id
        if byte_info & 0b01000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(self.trace_offset)
            self.vmid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        # Check for context id
        if byte_info & 0b10000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(self.trace_offset)
            self.cid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        return AddressContextPacket.addr_ctxt_l_64is0(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            address=address,
            context=context,
        )

    def decode_address_short_is0_packet(self) -> Packet:
        if not self.check_remaining_trace(2):
            return IncompletePacket(self.trace_offset)

        address: int = self.address_reg
        # Lower part extraction
        address = address & ~0x1FF
        address = address | ((self.trace_data[self.trace_offset + 1] & 0x7F) << 2)

        packet_size: int = 2
        if self.trace_data[self.trace_offset + 1] & 0x80:
            packet_size = 3
            if not self.check_remaining_trace(packet_size):
                return IncompletePacket(self.trace_offset)

            address = address & ~0x1FE00
            address = address | (self.trace_data[self.trace_offset + 2] << 9)

        self.address_reg = address

        return AddressPacket.addr_s_is0(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0), address=address
        )

    def decode_address_long_64_is0_packet(self) -> Packet:
        if not self.check_remaining_trace(10):
            return IncompletePacket(self.trace_offset)

        # Rebuild address
        address: int = self.extract_address(
            raw_data=self.trace_data[self.trace_offset + 1 : self.trace_offset + 9]
        )
        self.address_reg = address

        return AddressPacket.addr_l_64is0(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            address=address,
        )

    def decode_atom_f1_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b1
        elements_list: list[str] = self.create_element_list(en_bits=en_bits)

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def decode_atom_f2_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b11
        elements_list: list[str] = self.create_element_list(en_bits=en_bits)

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def decode_atom_f3_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b111
        elements_list: list[str] = self.create_element_list(en_bits=en_bits)

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def decode_atom_f4_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b11

        # Specific F4 patterns are defined ETM Specification 6-42
        f4_patterns: dict[int, list[str]] = {
            0b00: ["N", "E", "E", "E"],
            0b01: ["N", "N", "N", "N"],
            0b10: ["N", "E", "N", "E"],
            0b11: ["E", "N", "E", "N"],
        }

        elements_list: list[str] = f4_patterns[en_bits]

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def decode_atom_f5_packet(self) -> Packet:
        # The list of elements is encoded in the header
        header: int = self.trace_data[self.trace_offset]
        en_bits: int = (header & 0b10000 >> 3) | (header & 0b11)

        # Specific F4 patterns are defined ETM Specification 6-42
        f5_patterns: dict[int, list[str]] = {
            0b101: ["N", "E", "E", "E", "E"],
            0b001: ["N", "N", "N", "N", "N"],
            0b010: ["N", "E", "N", "E", "N"],
            0b011: ["E", "N", "E", "N", "E"],
        }

        elements_list: list[str] = f5_patterns[en_bits]

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def decode_atom_f6_packet(self) -> Packet:
        # Get the number of Es encoded
        header: int = self.trace_data[self.trace_offset]
        e_count: int = (header & 0b11111) + 3

        elements_list: list[str] = ["E"] * e_count + (["N"] if header & 0b10000 else ["E"])

        return AtomPacket.atom_format(
            packet_info=PacketInfo(index=self.trace_offset, vmid=0, header=0, cpu_nb=0),
            elements=elements_list,
        )

    def check_remaining_trace(self, n_bytes: int) -> bool:
        # The list of elements is encoded in the header
        self.remaining_trace = self.trace_size - self.trace_offset
        # Check for required bytes
        return self.remaining_trace >= n_bytes

    def extract_context(self, byte_info: int) -> Context:
        return Context(
            architecture="AArch64" if byte_info & 0x10 else "AArch32",
            exception_level=f"EL{byte_info & 0x3}",
            security_state="NS" if byte_info & 0x20 else "S",
        )

    def extract_address(self, raw_data: bytearray) -> int:
        return (
            raw_data[1] & 0x7F << 2
            | raw_data[2] & 0x7F << 9
            | raw_data[3] << 16
            | raw_data[4] << 24
            | raw_data[5] << 32
            | raw_data[6] << 40
            | raw_data[7] << 48
            | raw_data[8] << 56
        )

    def create_element_list(self, en_bits: int) -> list[str]:
        elements_list: list[str] = ["E" if (en_bits >> i) & 1 else "N" for i in range(en_bits.bit_length())]
        return elements_list
