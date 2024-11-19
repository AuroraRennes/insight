from __future__ import annotations

from dataclasses import dataclass

from onsight.helpers import format_to


@dataclass
class PacketInfo:
    index: int
    vmid: int  # FIXME: VMID? CID?
    header: int
    cpu_nb: int


class Packet:
    def __init__(self, name: str, packet_info: PacketInfo) -> None:
        self.name: str = name
        self.packet_info: PacketInfo = packet_info

    # TODO: Decode header!!
    @classmethod
    def from_header(cls, header: int) -> None:
        pass


# Synchronization Packets
# \________________________


class SynchronizationPacket(Packet):
    @classmethod
    def trace_on(cls, packet_info: PacketInfo) -> SynchronizationPacket:
        return cls(name="Trace On", packet_info=packet_info)

    # asynch to avoid shadowing async
    @classmethod
    def asynch(cls, packet_info: PacketInfo) -> SynchronizationPacket:
        return cls(name="Async", packet_info=packet_info)


# Info fields in the TraceInfo packet:
# > Extracted from ARM ETMv4 spec 2023, p.6-260
# [0]   cc_enabled     enables cycle counting (0 disabled, 1 enabled)
# [3:1] cond_enabled   conditional non-branching instruction transfer
#                      0b000 - tracing of conditional non-branch disabled
#                      0b001 - conditional loads are traced
#                      0b010 - conditional stores are traced
#                      0b011 - conditional loads and stores are traced
#                      0b100/0b101/0b110 - reserved
#                      0b111 - all conditional non-branch instructions are traced
# [4]  p0_load         load instructions traced explicitely (0 disabled, 1 enabled)
# [5]  p0_store        store instructions traced explicitely (0 disabled, 1 enabled)
# > Note: for the last two, this means stores/loads result in P0 elements.
class InfoFields:
    def __init__(self, info_bits: int) -> None:
        self.cc_enabled: int = format_to(info_bits, 1)
        self.cond_enabled: int = format_to(info_bits >> 1, 3)
        self.p0_load: int = format_to(info_bits >> 4, 1)
        self.p0_store: int = format_to(info_bits >> 5, 1)


class InfoPacket(SynchronizationPacket):
    def __init__(self, name: str, packet_info: PacketInfo, info_fields: InfoFields) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.info_fields: InfoFields = info_fields

    @classmethod
    def trace_info(cls, packet_info: PacketInfo, info_fields: InfoFields) -> InfoPacket:
        return cls(name="Trace Info", packet_info=packet_info, info_fields=info_fields)


# Address Packets
# \________________


class AddressPacket(Packet):
    def __init__(self, name: str, packet_info: PacketInfo, address: int) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.address: int = address

    @classmethod
    def addr_l_64is0(cls, packet_info: PacketInfo, address: int) -> AddressPacket:
        return cls(name="Long Address 64bit IS0", packet_info=packet_info, address=address)

    @classmethod
    def addr_s_is0(cls, packet_info: PacketInfo, address: int) -> AddressPacket:
        return cls(name="Short Address 64bit IS0", packet_info=packet_info, address=address)


# Address with Context Packets
# \______________________________


@dataclass
class Context:
    architecture: str  # ISA
    exception_level: str  # EL0, EL1, EL2
    security_state: str  # Secure/S or Not Secure/NS


class AddressContextPacket(AddressPacket):
    def __init__(self, name: str, packet_info: PacketInfo, address: int, context: Context) -> None:
        super().__init__(name=name, packet_info=packet_info, address=address)
        self.context: Context = context

    @classmethod
    def addr_ctxt_l_64is0(
        cls, packet_info: PacketInfo, address: int, context: Context
    ) -> AddressContextPacket:
        return cls(
            name="Long Address 64bit IS0 with Context",
            packet_info=packet_info,
            address=address,
            context=context,
        )


# Atom Packets
# \_____________


class AtomPacket(Packet):
    def __init__(
        self,
        name: str,
        packet_info: PacketInfo,
        format: int,
        elements: list[str],
    ) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.format: int = format
        self.elements: list[str] = elements

        # TODO: Check number of elements == format

    @classmethod
    def atom_format(cls, packet_info: PacketInfo, elements: list[str]) -> AtomPacket:
        atom_format: int = min(6, len(elements))
        return cls(
            name=f"Atom F{atom_format}",
            packet_info=packet_info,
            format=atom_format,
            elements=elements,
        )

    @staticmethod
    def check_format_size(format: int, elements_nb: int) -> bool:
        # format 6 holds 4-24 values
        atom_format_6: int = 6
        if format == atom_format_6:
            return elements_nb in range(4, 24)
        return format == elements_nb
