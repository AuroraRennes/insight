from abc import abstractmethod
from typing import TYPE_CHECKING, ClassVar, Union

from insight.exceptions import (
    HeaderNotRecognizedError,
    UnimplementedSectionError,
    UnknownSTMOpcodeError,
)
from insight.model.packets import (
    AddressContextPacket,
    AddressPacket,
    AtomPacket,
    Context,
    ContextPacket,
    ETMPacketInfo,
    ETMSynchronizationPacket,
    ExceptionPacket,
    IncompletePacket,
    InfoFields,
    InfoPacket,
    Packet,
    PacketInfo,
    STMDataMPacket,
    STMDataMTSPacket,
    STMDataPacket,
    STMDataTSPacket,
    STMIncompletePacket,
    STMPacket,
    STMPacketInfo,
    STMSynchronizationPacket,
    STMVersionPacket,
    TimestampPacket,
    UnknownPacket,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class Decoder:
    def __init__(self, trace_data: bytearray, sid: int) -> None:
        self.trace_data: bytearray = trace_data
        self.trace_size: int = len(trace_data)
        self.trace_offset: int = 0
        self.remaining_trace: int = self.trace_size - self.trace_offset
        self.sid: int = sid

    def decode_trace(self) -> list[Packet]:
        packet_list: list[Packet] = []

        while self.trace_offset < self.trace_size:
            packet: Packet = self.decode_packet()
            packet_list.append(packet)
            self.compute_next_offset(packet)

        return packet_list

    def compute_next_offset(self, packet: Packet) -> None:
        self.trace_offset += packet.packet_info.size

    @abstractmethod
    def decode_packet(self) -> Packet: ...


class ETMDecoder(Decoder):
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

    def __init__(self, trace_data: bytearray, sid: int) -> None:
        super().__init__(trace_data=trace_data, sid=sid)
        self.vmid: int = 0
        self.cid: int = 0
        self.context: Context = Context("undef", "undef", "undef")
        self.address_regs: tuple[int, int, int] = (0, 0, 0)

        # Helpers

    # \_________

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
            raw_data[0] & 0x7F << 2
            | raw_data[1] & 0x7F << 9
            | raw_data[2] << 16
            | raw_data[3] << 24
            | raw_data[4] << 32
            | raw_data[5] << 40
            | raw_data[6] << 48
            | raw_data[7] << 56
        )

    def extract_id(self, raw_data: bytearray) -> int:
        return raw_data[0] | raw_data[1] << 8 | raw_data[2] << 16 | raw_data[3] << 24

    def create_element_list(self, en_bits: int, bit_length: int) -> list[str]:
        elements_list: list[str] = ["E" if (en_bits >> i) & 1 else "N" for i in range(bit_length)]
        return elements_list

    def create_packet_info(self, size: int) -> PacketInfo:
        return ETMPacketInfo(index=self.trace_offset, vmid=self.vmid, cid=self.cid, sid=self.sid, size=size)

    def create_incomplete_packet(self) -> IncompletePacket:
        return IncompletePacket(
            ETMPacketInfo(index=self.trace_offset, vmid=self.vmid, cid=self.cid, sid=self.sid, size=1)
        )

    def create_unknown_packet(self) -> UnknownPacket:
        return UnknownPacket(
            ETMPacketInfo(index=self.trace_offset, vmid=self.vmid, cid=self.cid, sid=self.sid, size=1)
        )

    def update_sid(self, new_sid: int) -> None:
        self.sid = new_sid

    def update_addresses(self, new_address: int) -> None:
        self.address_regs = (new_address, self.address_regs[0], self.address_regs[1])

    def reset_addresses(self) -> None:
        self.address_regs = (0, 0, 0)

    # Main decoding method
    # \______________________

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

        if header >> 2 == 0b100100:
            return self.decode_address_exact_match_packet()

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
        packet_size: int = 2
        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Overflow packet: 1 header byte + 1 payload byte containing 0x5
        if self.trace_data[self.trace_offset + 1] == 0x5:
            return ExceptionPacket.overflow(
                ETMPacketInfo(
                    index=self.trace_offset, vmid=self.vmid, cid=self.cid, sid=self.sid, size=packet_size
                )
            )

        # Header is correct but missing rest of ASYNC
        packet_size = 12
        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Async packet: 10 bytes of 0x00 then one 0x80
        if (
            self.trace_data[self.trace_offset : self.trace_offset + 12]
            == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80"
        ):
            return ETMSynchronizationPacket.asynch(
                ETMPacketInfo(
                    index=self.trace_offset, vmid=self.vmid, cid=self.cid, sid=self.sid, size=packet_size
                )
            )

        return self.create_unknown_packet()

    # Misc/Info packets
    # \__________________

    def decode_trace_info_packet(self) -> Packet:  # noqa: C901
        # FIXME: ruff finds function too complex
        # Check minimal number of bytes, PLCTL of 1 byte
        packet_size: int = 2
        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Continuation bit activated for the section PLCTL
        # Note: Not sure why this section might continue? The doc only talks about bits 0-3
        while self.trace_data[self.trace_offset + packet_size - 1] & 0x80:
            packet_size += 1
            # Check remaining data size
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()

        plctl_bits: int = self.trace_data[self.trace_offset + 1] & 0x0F
        info_bits: int = 0

        # INFO section
        if plctl_bits & 0x1:
            packet_size += 1
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()

            # Extract information payload
            info_bits = self.trace_data[self.trace_offset + packet_size] & 0x1F

            # Note: Not sure why this section might continue? The doc only talks about bits 0-5
            while self.trace_data[packet_size - 1] & 0x80:
                packet_size += 1
                # Check remaining data size
                if not self.check_remaining_trace(packet_size):
                    return self.create_incomplete_packet()

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
            packet_info=self.create_packet_info(packet_size),
            info_fields=InfoFields(info_bits=info_bits),
        )

    def decode_timestamp_packet(self) -> Packet:
        # Note: These are max values, maybe checking continuation bits is better?
        packet_size: int = 11 if (self.trace_data[self.trace_offset] & 0x1) else 8

        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Note: the timestamp itself is not computed

        return TimestampPacket(
            packet_info=self.create_packet_info(packet_size),
            timestamp=0,
        )

    def decode_trace_on_packet(self) -> Packet:
        return ETMSynchronizationPacket.trace_on(
            packet_info=self.create_packet_info(1),
        )

    def decode_exception_packet(self) -> Packet:
        if not self.check_remaining_trace(2):
            return self.create_incomplete_packet()

        # Check if the continuation bit is set
        packet_size: int = 2
        if self.trace_data[self.trace_offset + 1] & 0x80:
            packet_size = 3

        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Extract exception details
        # Note: TYPE[9:5] are always 0b00000 for Armv7-A/R and Armv8-A/R PEs.
        exception_code: int = (self.trace_data[self.trace_offset + 1] >> 1) & 0x1F

        return ExceptionPacket.exception(
            packet_info=self.create_packet_info(packet_size),
            description=ETMDecoder.EXCEPTION_CODES[exception_code],
        )

    def decode_exception_return_packet(self) -> Packet:
        return ExceptionPacket.return_exception(
            packet_info=self.create_packet_info(1),
        )

    def decode_resynchronization_packet(self) -> Packet:
        return ETMSynchronizationPacket.resynchronization(
            packet_info=self.create_packet_info(1),
        )

    # Context/Address packets
    # \_________________________

    def decode_context_packet(self) -> Packet:
        packet_size: int = 1
        # Check from the header if the packet has a payload, if not reuse the previous one
        if not self.trace_data[self.trace_offset] & 0x1:
            return ContextPacket.context(
                packet_info=self.create_packet_info(packet_size),
                context=self.context,
            )

        # Expecting at least one more byte then
        if not self.check_remaining_trace(2):
            return self.create_incomplete_packet()
        packet_size = 2

        # Extract context values
        byte_info: int = self.trace_data[self.trace_offset + 1]
        context: Context = self.extract_context(byte_info=byte_info)

        # Check for virtual context id
        if byte_info & 0b01000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()
            self.vmid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        # Check for context id
        if byte_info & 0b10000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()
            self.cid = int(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        return ContextPacket.context(
            packet_info=self.create_packet_info(packet_size),
            context=context,
        )

    def decode_address_long_64_is0_with_context_packet(self) -> Packet:
        # 1 header + 8 address + 1 context info
        packet_size: int = 10
        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Rebuild address
        address: int = self.extract_address(
            raw_data=self.trace_data[self.trace_offset + 1 : self.trace_offset + packet_size - 1]
        )

        self.update_addresses(new_address=address)

        # Extract context values
        byte_info: int = self.trace_data[self.trace_offset + packet_size - 1]
        context: Context = self.extract_context(byte_info=byte_info)

        # Check for virtual context id
        if byte_info & 0b01000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()
            self.vmid = self.extract_id(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        # Check for context id
        if byte_info & 0b10000000:
            packet_size += 4
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()
            self.cid = self.extract_id(
                self.trace_data[self.trace_offset + packet_size - 4 : self.trace_offset + packet_size]
            )

        return AddressContextPacket.addr_ctxt_l_64is0(
            packet_info=self.create_packet_info(packet_size),
            address=address,
            context=context,
        )

    def decode_address_short_is0_packet(self) -> Packet:
        if not self.check_remaining_trace(2):
            return self.create_incomplete_packet()

        address: int = self.address_regs[0]
        # Lower part extraction
        address = address & ~0x1FF
        address = address | ((self.trace_data[self.trace_offset + 1] & 0x7F) << 2)

        packet_size: int = 2
        if self.trace_data[self.trace_offset + 1] & 0x80:
            packet_size = 3
            if not self.check_remaining_trace(packet_size):
                return self.create_incomplete_packet()

            address = address & ~0x1FE00
            address = address | (self.trace_data[self.trace_offset + 2] << 9)

        self.update_addresses(new_address=address)

        return AddressPacket.addr_s_is0(
            packet_info=self.create_packet_info(packet_size),
            address=address,
        )

    def decode_address_long_64_is0_packet(self) -> Packet:
        packet_size: int = 9
        if not self.check_remaining_trace(packet_size):
            return self.create_incomplete_packet()

        # Rebuild address
        address: int = self.extract_address(
            raw_data=self.trace_data[self.trace_offset + 1 : self.trace_offset + packet_size]
        )
        self.update_addresses(address)

        return AddressPacket.addr_l_64is0(
            packet_info=self.create_packet_info(packet_size),
            address=address,
        )

    def decode_address_exact_match_packet(self) -> Packet:
        address_reg: int = self.trace_data[self.trace_offset] & 0b11

        return AddressPacket.addr_match(self.create_packet_info(1), self.address_regs[address_reg])

    # Atom packets
    # \_____________

    def decode_atom_f1_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b1
        elements_list: list[str] = self.create_element_list(en_bits=en_bits, bit_length=1)

        return AtomPacket.atom_format(
            packet_info=self.create_packet_info(1),
            elements=elements_list,
        )

    def decode_atom_f2_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b11
        elements_list: list[str] = self.create_element_list(en_bits=en_bits, bit_length=2)

        return AtomPacket.atom_format(
            packet_info=self.create_packet_info(1),
            elements=elements_list,
        )

    def decode_atom_f3_packet(self) -> Packet:
        # The list of elements is encoded in the header
        en_bits: int = self.trace_data[self.trace_offset] & 0b111
        elements_list: list[str] = self.create_element_list(en_bits=en_bits, bit_length=3)

        return AtomPacket.atom_format(
            packet_info=self.create_packet_info(1),
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
            packet_info=self.create_packet_info(1),
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
            packet_info=self.create_packet_info(1),
            elements=elements_list,
        )

    def decode_atom_f6_packet(self) -> Packet:
        # Get the number of Es encoded
        header: int = self.trace_data[self.trace_offset]
        e_count: int = (header & 0b11111) + 3

        elements_list: list[str] = ["E"] * e_count + (["N"] if header & 0b10000 else ["E"])

        return AtomPacket.atom_format(
            packet_info=self.create_packet_info(1),
            elements=elements_list,
        )


# Recursive type def for the tree
NibbleTree = dict[int, Union[str, "NibbleTree"]]


class STMDecoder(Decoder):
    NIBBLE_TREE: ClassVar[NibbleTree] = {
        # Nibble 1
        0x0: "decode_null",
        0x1: "decode_m8",
        0x2: "decode_merr",
        0x3: "decode_c8",
        0x4: "decode_d8",
        0x5: "decode_d16",
        0x6: "decode_d32",
        0x7: "decode_d64",
        0x8: "decode_d8mts",
        0x9: "decode_d16mts",
        0xA: "decode_d32mts",
        0xB: "decode_d64mts",
        0xC: "decode_d4",
        0xD: "decode_d4mts",
        0xE: "decode_flag_ts",
        0xF: {
            # Nibble 2
            0x0: {
                # Nibble 3
                0x0: "decode_version",
                0x1: "decode_coresight_unimplemented",  # NULL_TS
                0x2: "decode_coresight_unimplemented",  # USER
                0x3: "decode_coresight_unimplemented",  # USER_TS
                0x4: "decode_coresight_unimplemented",  # TIME
                0x5: "decode_coresight_unimplemented",  # TIME_TS
                0x6: "decode_trig",
                0x7: "decode_trig_ts",
                0x8: "decode_freq",
                0x9: "decode_coresight_unimplemented",  # FREQ_TS
                0xA: "decode_coresight_unimplemented",  # XSYNC
                0xB: "decode_coresight_unimplemented",  # XSYNC_TS
                0xC: "decode_reserved",
                0xD: "decode_reserved",
                0xE: "decode_reserved",
                0xF: {
                    # Nibble 4
                    0x0: "decode_coresight_unimplemented",  # FREQ_40
                    0x1: "decode_coresight_unimplemented",  # FREQ_40_TS
                    0x2: "decode_coresight_unimplemented",  # DIP
                    0x3: "decode_coresight_unimplemented",  # CERR
                    0x4: "decode_reserved",
                    0x5: "decode_reserved",
                    0x6: "decode_reserved",
                    0x7: "decode_reserved",
                    0x8: "decode_reserved",
                    0x9: "decode_reserved",
                    0xA: "decode_reserved",
                    0xB: "decode_reserved",
                    0xC: "decode_reserved",
                    0xD: "decode_reserved",
                    0xE: "decode_reserved",
                    0xF: "decode_reserved",
                },
            },
            # Nibble 2 (cont.)
            0x1: "decode_coresight_unimplemented",  # M16
            0x2: "decode_gerr",
            0x3: "decode_c16",
            0x4: "decode_d8ts",
            0x5: "decode_d16ts",
            0x6: "decode_d32ts",
            0x7: "decode_d64ts",
            0x8: "decode_d8m",
            0x9: "decode_d16m",
            0xA: "decode_d32m",
            0xB: "decode_d64m",
            0xC: "decode_d4ts",
            0xD: "decode_d4m",
            0xE: "decode_flag",
            0xF: {
                # Nibble 3
                0x0: "decode_reserved",
                0x1: "decode_coresight_unimplemented",  # PDID_DATA
                0x2: "decode_coresight_unimplemented",  # PDID_TYPE_TS
                0x3: "decode_reserved",
                0x4: "decode_reserved",
                0x5: "decode_reserved",
                0x6: "decode_reserved",
                0x7: "decode_reserved",
                0x8: "decode_reserved",
                0x9: "decode_reserved",
                0xA: "decode_reserved",
                0xB: "decode_reserved",
                0xC: "decode_reserved",
                0xD: "decode_reserved",
                0xE: "decode_reserved",
                0xF: "decode_async",
            },
        },
    }

    def __init__(self, trace_data: bytearray, sid: int) -> None:
        super().__init__(trace_data=trace_data, sid=sid)
        self.nibble_selector: int = 0  # 0, low nibble / 1, high nibble
        self.remaining_nibbles: int = self.remaining_trace * 2
        self.header_size: int = 0

    # Helpers
    # \________

    def compute_next_offset(self, packet: Packet) -> None:
        # Unlike the ETM decoder were all packets are byte-aligned, STM packets are nibble-aligned
        # and their packet size corresponds to the NUMBER OF NIBBLE.
        self.trace_offset += packet.packet_info.size // 2
        self.nibble_selector = packet.packet_info.size % 2

    def access_nibble_at_offset(self, nibble_offset: int) -> int:
        # Offset is in nibbles, so *2 for byte trace offset
        trace_offset: int = self.trace_offset + (nibble_offset // 2)
        # Follows this truth table (which is XOR):
        # nibble_selector  |  offset % 2  || expected
        # -----------------+--------------++----------
        #        1         |       1      ||     0
        #        1         |       0      ||     1
        #        0         |       1      ||     1
        #        0         |       0      ||     0
        nibble_selector: int = self.nibble_selector ^ (nibble_offset % 2)

        byte: int = self.trace_data[trace_offset]
        if nibble_selector == 0:
            return byte & 0xF
        return byte >> 4

    def check_remaining_trace(self, n_nibbles: int) -> bool:
        # The list of elements is encoded in the header
        self.remaining_trace = self.trace_size - self.trace_offset
        self.remaining_nibbles = self.remaining_trace * 2 - self.nibble_selector
        # Check for required bytes
        return self.remaining_nibbles >= n_nibbles

    def create_packet_info(self, size: int) -> STMPacketInfo:
        return STMPacketInfo(index=self.trace_offset, sid=self.sid, size=size)

    def create_incomplete_packet(self) -> STMIncompletePacket:
        return STMIncompletePacket(packet_info=self.create_packet_info(1))

    # Main decoding method
    # \______________________

    def decode_packet(self) -> Packet:
        # Start with the base decode tree
        node: str | NibbleTree = STMDecoder.NIBBLE_TREE

        # Reset header size, increments on tree traversal
        header_size: int = 0

        while isinstance(node, dict):
            # Get the first byte, check for which nibble to start decoding from
            nibble: int = self.access_nibble_at_offset(header_size)
            try:
                node = node[nibble]
                header_size += 1
            except KeyError as err:
                raise UnknownSTMOpcodeError(self.trace_offset, self.nibble_selector) from err

        self.header_size = header_size
        handler: Callable[[STMDecoder], Packet] = getattr(STMDecoder, node)
        packet: Packet = handler(self)
        return packet

    # Sync/Misc packets
    # \___________________

    def decode_async(self) -> STMPacket:
        # expecting 21Fs in total then 0, we're already at nibble 3
        if not self.check_remaining_trace(19):
            return self.create_incomplete_packet()

        return STMSynchronizationPacket.asynch(packet_info=self.create_packet_info(22))

    def decode_null(self) -> STMSynchronizationPacket:
        return STMSynchronizationPacket.null(packet_info=self.create_packet_info(1))

    def decode_version(self) -> STMVersionPacket:
        # Info Nibble:         3           2         0
        #                payload present? | ts_format
        version_info_nibble: int = self.access_nibble_at_offset(self.header_size)
        packet_size: int = self.header_size + 1

        # Default values
        endianness: str = "BE"
        version: int = 0

        ts_format: int = version_info_nibble & 0x7
        if version_info_nibble >> 3:
            endianness = "LE" if (self.access_nibble_at_offset(self.header_size + 1) >> 3) else "BE"
            version = self.access_nibble_at_offset(self.header_size + 2) & 0x3
            packet_size += 2

        return STMVersionPacket.version(
            packet_info=self.create_packet_info(packet_size),
            version=version,
            ts_format=ts_format,
            endianness=endianness,
        )

    # Data packets
    # \______________

    def decode_data_value(self, size: int) -> int:
        data_value: int = 0
        for nibble_idx in range(size // 4):
            # A succession of values 0x0 0x1 0x2 0x3 should come out as 0x0123
            # Placing the nibble correctly means shifting it by size - (running index * 4)
            data_value |= self.access_nibble_at_offset(nibble_offset=nibble_idx) << (size - (nibble_idx * 4))

        return data_value

    def decode_data_packet(self, size: int) -> STMDataPacket:
        packet_size: int = self.header_size + (size // 4)
        return STMDataPacket.data(
            packet_info=self.create_packet_info(packet_size),
            data_size=size,
            data_value=self.decode_data_value(size),
        )

    def decode_mdata_packet(self, size: int) -> STMDataMPacket:
        packet_size: int = self.header_size + (size // 4)
        return STMDataMPacket.m_data(
            packet_info=self.create_packet_info(packet_size),
            data_size=size,
            data_value=self.decode_data_value(size),
        )

    def decode_tsdata_packet(self, size: int) -> STMDataTSPacket:
        packet_size: int = self.header_size + (size // 4) + 1
        return STMDataTSPacket.ts_data(
            packet_info=self.create_packet_info(packet_size),
            data_size=size,
            data_value=self.decode_data_value(size=size),
            timestamp=self.access_nibble_at_offset(nibble_offset=(size // 4) + 1),
        )

    def decode_mtsdata_packet(self, size: int) -> STMDataMTSPacket:
        packet_size: int = self.header_size + (size // 4) + 1
        return STMDataMTSPacket.mts_data(
            packet_info=self.create_packet_info(packet_size),
            data_size=size,
            data_value=self.decode_data_value(size=size),
            timestamp=self.access_nibble_at_offset(nibble_offset=(size // 4) + 1),
        )

    def decode_d4(self) -> STMDataPacket:
        return self.decode_data_packet(4)

    def decode_d8(self) -> STMDataPacket:
        return self.decode_data_packet(8)

    def decode_d16(self) -> STMDataPacket:
        return self.decode_data_packet(16)

    def decode_d32(self) -> STMDataPacket:
        return self.decode_data_packet(32)

    def decode_d64(self) -> STMDataPacket:
        return self.decode_data_packet(64)

    def decode_d4m(self) -> STMDataMPacket:
        return self.decode_mdata_packet(4)

    def decode_d8m(self) -> STMDataMPacket:
        return self.decode_mdata_packet(8)

    def decode_d16m(self) -> STMDataMPacket:
        return self.decode_mdata_packet(16)

    def decode_d32m(self) -> STMDataMPacket:
        return self.decode_mdata_packet(32)

    def decode_d64m(self) -> STMDataMPacket:
        return self.decode_mdata_packet(64)

    def decode_d4ts(self) -> STMDataTSPacket:
        return self.decode_tsdata_packet(4)

    def decode_d8ts(self) -> STMDataTSPacket:
        return self.decode_tsdata_packet(8)

    def decode_d16ts(self) -> STMDataTSPacket:
        return self.decode_tsdata_packet(16)

    def decode_d32ts(self) -> STMDataTSPacket:
        return self.decode_tsdata_packet(32)

    def decode_d64ts(self) -> STMDataTSPacket:
        return self.decode_tsdata_packet(64)

    def decode_d4mts(self) -> STMDataMTSPacket:
        return self.decode_mtsdata_packet(4)

    def decode_d8mts(self) -> STMDataMTSPacket:
        return self.decode_mtsdata_packet(8)

    def decode_d16mts(self) -> STMDataMTSPacket:
        return self.decode_mtsdata_packet(16)

    def decode_d32mts(self) -> STMDataMTSPacket:
        return self.decode_mtsdata_packet(32)

    def decode_d64mts(self) -> STMDataMTSPacket:
        return self.decode_mtsdata_packet(64)
