from __future__ import annotations

from dataclasses import dataclass

from insight.helpers import format_to


@dataclass
class PacketInfo:
    index: int  # Index of the packet in the trace
    sid: int  # Trace source id, from deformatter
    size: int  # Packet size


@dataclass
class ETMPacketInfo(PacketInfo):
    vmid: int  # Virtual memory id, from context packet
    cid: int  # Context id, from context packet


@dataclass
class STMPacketInfo(PacketInfo): ...


class Packet:
    def __init__(self, name: str, packet_info: PacketInfo) -> None:
        self.name: str = name
        self.packet_info: PacketInfo = packet_info

    # TODO: Decode header!!
    @classmethod
    def from_header(cls, header: int) -> None:
        pass


# Unknown Packets
# \________________


class UnknownPacket(Packet):
    def __init__(self, packet_info: PacketInfo) -> None:
        super().__init__(name="Unknown", packet_info=packet_info)


class IncompletePacket(Packet):
    def __init__(self, packet_info: PacketInfo) -> None:
        super().__init__(name="Incomplete", packet_info=packet_info)


# Synchronization Packets
# \________________________


class ETMSynchronizationPacket(Packet):
    @classmethod
    def trace_on(cls, packet_info: PacketInfo) -> ETMSynchronizationPacket:
        return cls(name="Trace On", packet_info=packet_info)

    # asynch to avoid shadowing async
    @classmethod
    def asynch(cls, packet_info: PacketInfo) -> ETMSynchronizationPacket:
        return cls(name="Async", packet_info=packet_info)

    @classmethod
    def notsync(cls, packet_info: PacketInfo) -> ETMSynchronizationPacket:
        return cls(name="Not Sync", packet_info=packet_info)

    @classmethod
    def end(cls, packet_info: PacketInfo) -> ETMSynchronizationPacket:
        return cls(name="End Trace", packet_info=packet_info)

    @classmethod
    def resynchronization(cls, packet_info: PacketInfo) -> ETMSynchronizationPacket:
        return cls(name="Resynchronization", packet_info=packet_info)


# Info/Version/


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
@dataclass
class InfoFields:
    def __init__(self, info_bits: int) -> None:
        self.cc_enabled: int = format_to(info_bits, 1)
        self.cond_enabled: int = format_to(info_bits >> 1, 3)
        self.p0_load: int = format_to(info_bits >> 4, 1)
        self.p0_store: int = format_to(info_bits >> 5, 1)


class InfoPacket(Packet):
    def __init__(self, name: str, packet_info: PacketInfo, info_fields: InfoFields) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.info_fields: InfoFields = info_fields

    @classmethod
    def trace_info(cls, packet_info: PacketInfo, info_fields: InfoFields) -> InfoPacket:
        return cls(name="Trace Info", packet_info=packet_info, info_fields=info_fields)


# Version packets
# \_______________


class VersionPacket(Packet):
    def __init__(self, name: str, packet_info: PacketInfo, version_number: str) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.version_number: str = version_number

    # avoid shadowing base version() method
    @classmethod
    def version_nb(cls, packet_info: PacketInfo, version_number: str) -> VersionPacket:
        return cls(name="Version", packet_info=packet_info, version_number=version_number)


# Exception packets
# \_________________


class ExceptionPacket(Packet):
    def __init__(self, name: str, packet_info: PacketInfo, description: str) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.description: str = description

    @classmethod
    def exception(cls, packet_info: PacketInfo, description: str) -> ExceptionPacket:
        return cls(name="Exception", packet_info=packet_info, description=description)

    @classmethod
    def return_exception(cls, packet_info: PacketInfo) -> ExceptionPacket:
        return cls(name="Return Exception", packet_info=packet_info, description="return from exception")

    @classmethod
    def overflow(cls, packet_info: PacketInfo) -> ExceptionPacket:
        return cls(name="Overflow", packet_info=packet_info, description="overflow")


# Timestamp packets
# \_________________


class TimestampPacket(Packet):
    def __init__(self, packet_info: PacketInfo, timestamp: int) -> None:
        super().__init__(name="Timestamp", packet_info=packet_info)
        self.timestamp = timestamp


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

    @classmethod
    def addr_match(cls, packet_info: PacketInfo, address: int) -> AddressPacket:
        return cls(name="Exact Address Match", packet_info=packet_info, address=address)

    @classmethod
    def addr_l_32is0(cls, packet_info: PacketInfo, address: int) -> AddressPacket:
        return cls(name="Long Address 32bit IS0", packet_info=packet_info, address=address)


# Context Packets
# \________________


@dataclass
class Context:
    architecture: str  # ISA
    exception_level: str  # EL0, EL1, EL2
    security_state: str  # Secure/S or Not Secure/NS


class ContextPacket(Packet):
    def __init__(self, name: str, packet_info: PacketInfo, context: Context) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.context_info: Context = context

    @classmethod
    def context(cls, packet_info: PacketInfo, context: Context) -> ContextPacket:
        return cls(name="Context", packet_info=packet_info, context=context)


class AddressContextPacket(AddressPacket):
    def __init__(self, name: str, packet_info: PacketInfo, address: int, context: Context) -> None:
        super().__init__(name=name, packet_info=packet_info, address=address)
        self.context_info: Context = context

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

    @classmethod
    def atom_format(cls, packet_info: PacketInfo, elements: list[str]) -> AtomPacket:
        # FIXME: F6 atoms can have 4-24 elements
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


# STM Packets
# \____________


class STMPacket(Packet):
    def __init__(self, name: str, packet_info: STMPacketInfo) -> None:
        super().__init__(name="STM - " + name, packet_info=packet_info)


class STMVersionPacket(STMPacket):
    def __init__(
        self, name: str, packet_info: STMPacketInfo, version: int, ts_format: int, endianness: str
    ) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.version_info: int = version
        self.ts_format: int = ts_format
        self.endianness: str = endianness

    @classmethod
    def version(
        cls, packet_info: STMPacketInfo, version: int, ts_format: int, endianness: str
    ) -> STMVersionPacket:
        return cls(
            name="Version",
            packet_info=packet_info,
            version=version,
            ts_format=ts_format,
            endianness=endianness,
        )


class STMSynchronizationPacket(STMPacket):
    @classmethod
    def asynch(cls, packet_info: STMPacketInfo) -> STMSynchronizationPacket:
        return cls(name="Async", packet_info=packet_info)

    @classmethod
    def null(cls, packet_info: STMPacketInfo) -> STMSynchronizationPacket:
        return cls(name="Null", packet_info=packet_info)

    @classmethod
    def flag(cls, packet_info: STMPacketInfo) -> STMSynchronizationPacket:
        return cls(name="Flag", packet_info=packet_info)


class STMErrorPacket(STMPacket):
    def __init__(self, name: str, packet_info: STMPacketInfo, err_code: int) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.err_code = err_code

    @classmethod
    def merr(cls, packet_info: STMPacketInfo, err_code: int) -> STMErrorPacket:
        return cls(name="MERR", packet_info=packet_info, err_code=err_code)

    @classmethod
    def gerr(cls, packet_info: STMPacketInfo, err_code: int) -> STMErrorPacket:
        return cls(name="GERR", packet_info=packet_info, err_code=err_code)


class STMMasterPacket(STMPacket):
    def __init__(self, name: str, packet_info: STMPacketInfo, master_channel: int) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.master_channel = master_channel

    @classmethod
    def master(cls, packet_info: STMPacketInfo, master_channel: int) -> STMMasterPacket:
        return cls(name="Master", packet_info=packet_info, master_channel=master_channel)


class STMChannelPacket(STMPacket):
    def __init__(self, name: str, packet_info: STMPacketInfo, channel: int) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.channel_nb = channel

    @classmethod
    def channel(cls, packet_info: STMPacketInfo, channel: int) -> STMChannelPacket:
        return cls(name="Channel", packet_info=packet_info, channel=channel)


# FIXME: We handle all data packets (plain, timestamp, marker, or combined) as plain data packets
class STMDataPacket(STMPacket):
    def __init__(self, name: str, packet_info: STMPacketInfo, data_size: int, data_value: int) -> None:
        super().__init__(name=name, packet_info=packet_info)
        self.data_size: int = data_size
        self.data_value: int = data_value

    @classmethod
    def data(cls, packet_info: STMPacketInfo, data_size: int, data_value: int) -> STMDataPacket:
        return STMDataPacket(
            name=f"Data {data_size}", packet_info=packet_info, data_size=data_size, data_value=data_value
        )


class STMDataMPacket(STMDataPacket):
    @classmethod
    def m_data(cls, packet_info: STMPacketInfo, data_size: int, data_value: int) -> STMDataMPacket:
        return cls(
            name=f"Marked Data {data_size}",
            packet_info=packet_info,
            data_size=data_size,
            data_value=data_value,
        )


class STMDataTSPacket(STMDataPacket):
    def __init__(
        self, name: str, packet_info: STMPacketInfo, data_size: int, data_value: int, timestamp: int
    ) -> None:
        super().__init__(name=name, packet_info=packet_info, data_size=data_size, data_value=data_value)
        self.timestamp = timestamp

    @classmethod
    def ts_data(
        cls, packet_info: STMPacketInfo, data_size: int, data_value: int, timestamp: int
    ) -> STMDataTSPacket:
        return cls(
            name=f"Timestamped Data {data_size}",
            packet_info=packet_info,
            data_size=data_size,
            data_value=data_value,
            timestamp=timestamp,
        )


class STMDataMTSPacket(STMDataTSPacket, STMDataMPacket):
    def __init__(
        self, name: str, packet_info: STMPacketInfo, data_size: int, data_value: int, timestamp: int
    ) -> None:
        super().__init__(
            name=name,
            packet_info=packet_info,
            data_size=data_size,
            data_value=data_value,
            timestamp=timestamp,
        )

    @classmethod
    def mts_data(
        cls, packet_info: STMPacketInfo, data_size: int, data_value: int, timestamp: int
    ) -> STMDataMTSPacket:
        return cls(
            name=f"Marked Timestamped Data {data_size}",
            packet_info=packet_info,
            data_size=data_size,
            data_value=data_value,
            timestamp=timestamp,
        )


# STM Unknown Packets
# \________________


class STMUnknownPacket(STMPacket):
    def __init__(self, packet_info: STMPacketInfo) -> None:
        super().__init__(name="Unknown", packet_info=packet_info)


class STMIncompletePacket(STMPacket):
    def __init__(self, packet_info: STMPacketInfo) -> None:
        super().__init__(name="Incomplete", packet_info=packet_info)
