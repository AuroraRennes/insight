import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from insight.exceptions import (
    MatchNoParseError,
    NoMatchingAddressContextError,
    NoMatchingAddressError,
    NoMatchingChannelError,
    NoMatchingDataError,
    NoMatchingDescriptionError,
    NoMatchingElementsError,
    NoMatchingInfoError,
    NoMatchingVersionError,
    NoPacketMatchError,
    WrongSizeAtomPacketError,
)
from insight.helpers import string_to_int
from insight.model.packets import (
    Context,
    ETMAddressContextPacket,
    ETMAddressPacket,
    ETMAtomPacket,
    ETMExceptionPacket,
    ETMInfoPacket,
    ETMPacketInfo,
    ETMSynchronizationPacket,
    ETMVersionPacket,
    InfoFields,
    Packet,
    PacketInfo,
    STMDataPacket,
    STMMasterPacket,
    STMPacket,
    STMPacketInfo,
    STMSynchronizationPacket,
)

if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger("insight")


@dataclass
class ParseInfo:
    parse_method: str
    regex: str


class PacketParser:
    # Base regex, then composed:
    PACKET_BASE_REGEX: str = (
        r"(Idx:(?P<index>\d+); )?ID:(?P<id>\d+);?\s(?P<name>\w*)(\s*:\s*(?P<description>[\s\w,&]*).)?"
    )
    # Note: The base regex was designed around the packets decoded by OpenCSD's trc_packet_lister
    #       which has varying levels of consistency. For END TRACE PACKETS, they look like:
    #       ID:13	END OF TRACE DATA
    #       ID:20	END OF TRACE DATA
    #       and have no index (the first optional group), no semicolon ;? and no description.
    #       This is the reason why so many optional groups are present here.

    # REGEXES /

    # Address packets
    ADDR_REGEX: str = r"Addr=(?P<address>0x\w+)"  # Address, in address    ...; Addr=0xFFFF800008AA4BE0;
    # TODO: Catch cid and update attribute
    CTXT_REGEX: str = r"Ctxt: (?P<context>[,\s\w]*)"  # Context, in address    ...; Ctxt: AArch64,EL0, NS;
    # Atom packets
    ELTS_REGEX: str = r"(?P<atom_elements>[EN]+)"  # Basic blocks, in atoms ...;  Atom format 3.; ENE
    # Info/Exception packets
    INFO_REGEX: str = (
        r"INFO=(?P<info_bitfield>0x\w+) \{[\s\w.]*\}"  # Info, in trace info    ...; INFO=0x0 { CC.0 };
    )
    EXCP_REGEX: str = r"Exception.;\s*(?P<description>[\s\w]*);"
    VERS_REGEX: str = r"Version packet; Ver=(?P<version_number>\w+)"
    # STM packets
    MAST_REGEX: str = r"Set current master; Master=(?P<master_channel>0x\w+)"
    DATA_REGEX: str = r"(?P<data_size>\d+)[\s\w+]*; Data=(?P<data_value>0x\w+)"

    # This dictionary takes the name as key and outputs the corresponding regexes needed
    # to extract the rest of the information. The syntax **dict.fromkeys(keys_list, value) maps multiple
    # keys to the same value in a more concise way.
    PACKETS_INFO: ClassVar[dict[str, ParseInfo]] = {
        # Address packets
        **dict.fromkeys(
            ["I_ADDR_L_64IS0", "I_ADDR_L_32IS0", "I_ADDR_S_IS0", "I_ADDR_MATCH"],
            ParseInfo("parse_addr", ADDR_REGEX),
        ),
        "I_ADDR_CTXT_L_64IS0": ParseInfo("parse_addr_ctxt", ADDR_REGEX + "; " + CTXT_REGEX),
        # Atom packets
        **dict.fromkeys([f"I_ATOM_F{i}" for i in range(7)], ParseInfo("parse_atom", ELTS_REGEX)),
        # Info/exception packets
        "I_TRACE_INFO": ParseInfo("parse_trace_info", INFO_REGEX),
        "I_EXCEPT": ParseInfo("parse_exception", EXCP_REGEX),
        "VERSION": ParseInfo("parse_version", VERS_REGEX),
        # Synchronization packets
        "I_TRACE_ON": ParseInfo("parse_trace_on", ""),
        **dict.fromkeys(["I_ASYNC", "ASYNC"], ParseInfo("parse_async", "")),
        **dict.fromkeys(["NOTSYNC", "I_NOT_SYNC"], ParseInfo("parse_notsync", "")),
        "I_OVERFLOW": ParseInfo("parse_overflow", ""),
        "END": ParseInfo("parse_end", ""),
        # STM packets
        "NULL": ParseInfo("parse_null", ""),
        "M8": ParseInfo("parse_master", MAST_REGEX),
        **dict.fromkeys(
            [f"D{i}" for i in [4, 8, 16, 32, 64]]
            + [f"D{i}M" for i in [4, 8, 16, 32, 64]]
            + [f"D{i}TS" for i in [4, 8, 16, 32, 64]]
            + [f"D{i}MTS" for i in [4, 8, 16, 32, 64]],
            ParseInfo("parse_data", DATA_REGEX),
        ),
    }

    def __init__(self) -> None:
        self.cid = 0

    # Main parsing
    # \_______________

    def parse_opencsd_file(self, trace_file_name: str) -> list[Packet]:
        # FIXME: Should handle the start and end lines that trc_pkt_lister adds and keep them
        packets: list[Packet] = []
        try:
            with Path(trace_file_name).open("r") as trace_file:
                packets = [self.parse_packet(line) for line in trace_file]
        except OSError:
            logger.exception("[-] Trace file opening failed.")
            sys.exit(1)
        return packets

    def parse_packet(self, line: str) -> Packet:
        match_line: re.Match[str] | None = re.search(PacketParser.PACKET_BASE_REGEX, line)
        if not match_line:
            raise NoPacketMatchError(line)
        group: dict[str, str] = match_line.groupdict()

        index: int = int(group["index"]) if group["index"] else (1 << 64)

        packet_info: PacketInfo = ETMPacketInfo(
            index=index,
            vmid=0,  # No VMID in our traces
            cid=self.cid,
            sid=int(group["id"], 16),
            size=0,  # Size unknown while parsing here
        )

        packet_name: str = group["name"]
        if packet_name not in PacketParser.PACKETS_INFO:
            raise MatchNoParseError(packet_name)

        parse_info: ParseInfo = PacketParser.PACKETS_INFO[packet_name]

        parse_method: Callable[..., Packet] = getattr(self, parse_info.parse_method)
        packet: Packet = parse_method(
            packet_info=packet_info, packet_name=packet_name, line=line, regex=parse_info.regex
        )

        return packet

    # Packet parsing
    # \_______________

    # Address packets /

    def parse_addr(
        self, packet_name: str, packet_info: PacketInfo, line: str, regex: str
    ) -> ETMAddressPacket:
        match_address: re.Match[str] | None
        if match_address := re.search(regex, line):
            group: dict[str, str] = match_address.groupdict()
            address: int = string_to_int(group["address"])
        else:
            raise NoMatchingAddressError

        constr_method: Callable[..., ETMAddressPacket] = getattr(ETMAddressPacket, packet_name[2:].lower())
        return constr_method(packet_info=packet_info, address=address)

    def parse_addr_ctxt(
        self, packet_name: str, packet_info: ETMPacketInfo, line: str, regex: str
    ) -> ETMAddressContextPacket:
        match_addr_ctxt: re.Match[str] | None
        if match_addr_ctxt := re.search(regex, line):
            group: dict[str, str] = match_addr_ctxt.groupdict()
            address: int = string_to_int(group["address"])
            context_str: list[str] = group["context"].split(",")
            context: Context = Context(
                architecture=context_str[0].strip(),
                exception_level=context_str[1].strip(),
                security_state=context_str[2].strip(),
            )
        else:
            raise NoMatchingAddressContextError

        constr_method: Callable[..., ETMAddressContextPacket] = getattr(
            ETMAddressContextPacket, packet_name[2:].lower()
        )
        return constr_method(packet_info=packet_info, address=address, context=context)

    # Info packets /

    def parse_trace_info(
        self, packet_info: ETMPacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> ETMInfoPacket:
        match_info: re.Match[str] | None
        if match_info := re.search(regex, line):
            group: dict[str, str] = match_info.groupdict()
            info_bits: int = string_to_int(group["info_bitfield"])
            info_fields: InfoFields = InfoFields(info_bits=info_bits)
        else:
            raise NoMatchingInfoError

        return ETMInfoPacket.trace_info(packet_info=packet_info, info_fields=info_fields)

    # Version packets /

    def parse_version(
        self, packet_info: ETMPacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> ETMVersionPacket:
        match_version: re.Match[str] | None
        if match_version := re.search(regex, line):
            group: dict[str, str] = match_version.groupdict()
            version_number: str = group["version_number"]
        else:
            raise NoMatchingVersionError

        return ETMVersionPacket.version_nb(packet_info=packet_info, version_number=version_number)

    # Atom packets /

    def parse_atom(
        self, packet_info: ETMPacketInfo, packet_name: str, line: str, regex: str
    ) -> ETMAtomPacket:
        match_elements: re.Match[str] | None
        if match_elements := re.search(regex, line):
            group: dict[str, str] = match_elements.groupdict()
            elements: list[str] = list(group["atom_elements"])
        else:
            raise NoMatchingElementsError

        # I_ATOM_F1 > [I, ATOM, F1] > 1, but atom format 6 can have more elements!
        format_extracted: str = packet_name.split("_")[-1][-1]
        if not ETMAtomPacket.check_format_size(format=int(format_extracted), elements_nb=len(elements)):
            raise WrongSizeAtomPacketError(expected_size=int(format_extracted), size=len(elements))
        return ETMAtomPacket.atom_format(packet_info=packet_info, elements=elements)

    # Synchronization packets /

    def parse_trace_on(
        self, packet_info: ETMPacketInfo, **kwargs: dict[str, Any]
    ) -> ETMSynchronizationPacket:
        return ETMSynchronizationPacket.trace_on(packet_info=packet_info)

    def parse_async(self, packet_info: ETMPacketInfo, **kwargs: dict[str, Any]) -> ETMSynchronizationPacket:
        return ETMSynchronizationPacket.asynch(packet_info=packet_info)

    def parse_notsync(self, packet_info: ETMPacketInfo, **kwargs: dict[str, Any]) -> ETMSynchronizationPacket:
        return ETMSynchronizationPacket.notsync(packet_info=packet_info)

    def parse_end(self, packet_info: ETMPacketInfo, **kwargs: dict[str, Any]) -> ETMSynchronizationPacket:
        return ETMSynchronizationPacket.end(packet_info=packet_info)

    # Exception packets /

    def parse_exception(
        self, packet_info: ETMPacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> ETMExceptionPacket:
        match_description: re.Match[str] | None
        if match_description := re.search(regex, line):
            group: dict[str, str] = match_description.groupdict()
            description: str = group["description"]
        else:
            raise NoMatchingDescriptionError
        return ETMExceptionPacket.exception(packet_info=packet_info, description=description)

    def parse_overflow(self, packet_info: ETMPacketInfo, **kwargs: dict[str, Any]) -> ETMExceptionPacket:
        return ETMExceptionPacket.overflow(packet_info=packet_info)

    # STM packets /

    def parse_null(self, packet_info: STMPacketInfo, **kwargs: dict[str, Any]) -> STMPacket:
        return STMSynchronizationPacket.null(packet_info=packet_info)

    def parse_master(
        self, packet_info: STMPacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> STMMasterPacket:
        match_channel: re.Match[str] | None
        if match_channel := re.search(regex, line):
            group: dict[str, str] = match_channel.groupdict()
            master_channel: int = string_to_int(group["master_channel"])
        else:
            raise NoMatchingChannelError
        return STMMasterPacket.master(packet_info=packet_info, master_channel=master_channel)

    def parse_data(
        self, packet_info: STMPacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> STMDataPacket:
        match_data: re.Match[str] | None
        if match_data := re.search(regex, line):
            group: dict[str, str] = match_data.groupdict()
            data_size: int = int(group["data_size"])
            data_value: int = string_to_int(group["data_value"])
        else:
            raise NoMatchingDataError
        return STMDataPacket.data(packet_info=packet_info, data_size=data_size, data_value=data_value)
