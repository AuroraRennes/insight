import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from onsight.exceptions import (
    NoMatchingAddressContextError,
    NoMatchingAddressError,
    NoMatchingElementsError,
    NoMatchingInfoError,
    NoPacketMatchError,
    WrongSizeAtomPacketError,
)
from onsight.helpers import string_to_int
from onsight.packets import (
    AddressContextPacket,
    AddressPacket,
    AtomPacket,
    Context,
    InfoFields,
    InfoPacket,
    Packet,
    PacketInfo,
    SynchronizationPacket,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class ParseInfo:
    parse_method: str
    regex: str


class PacketParser:
    # Base regex, then composed:
    PACKET_BASE_REGEX: str = (
        r"Idx:(?P<index>\d+); ID:(?P<id>\d+);\s(?P<name>\w*)\s: (?P<description>[\s\w,&]*)."
    )

    # REGEXES
    ADDR_REGEX: str = r"Addr=(?P<address>0x\w+)"  # Address, in address    ...; Addr=0xFFFF800008AA4BE0;
    CTXT_REGEX: str = r"Ctxt: (?P<context>[,\s\w]*)"  # Context, in address    ...; Ctxt: AArch64,EL0, NS;
    ELTS_REGEX: str = r"(?P<atom_elements>[EN]+)"  # Basic blocks, in atoms ...;  Atom format 3.; ENE
    INFO_REGEX: str = (
        r"INFO=(?P<info_bitfield>0x\w+) \{[\s\w.]*\}"  # Info, in trace info    ...; INFO=0x0 { CC.0 };
    )

    # This dictionary takes the name as key and outputs the corresponding regexes needed
    # to extract the rest of the information. The syntax **dict.fromkeys(keys_list, value) maps multiple
    # keys to the same value in a more concise way.
    PACKETS_INFO: ClassVar[dict[str, ParseInfo]] = {
        **dict.fromkeys(
            ["I_ADDR_L_64IS0", "I_ADDR_S_IS0", "I_ADDR_MATCH"], ParseInfo("parse_addr", ADDR_REGEX)
        ),
        "I_ADDR_CTXT_L_64IS0": ParseInfo("parse_addr_ctxt", ADDR_REGEX + "; " + CTXT_REGEX),
        "I_TRACE_INFO": ParseInfo("parse_trace_info", INFO_REGEX),
        **dict.fromkeys([f"I_ATOM_F{i}" for i in range(7)], ParseInfo("parse_atom", ELTS_REGEX)),
        # These don't need additional parameters
        "I_TRACE_ON": ParseInfo("parse_trace_on", ""),
        "I_ASYNC": ParseInfo("parse_async", ""),
    }

    def parse_packet(self, line: str, cpu_nb: int | None) -> Packet:
        match_line: re.Match[str] | None = re.search(PacketParser.PACKET_BASE_REGEX, line)
        if not match_line:
            raise NoPacketMatchError(line)
        group: dict[str, str] = match_line.groupdict()

        # if cpu_nb is None, use the id - 10 or stm
        # TODO: put in a function, explain
        if cpu_nb is None:
            cpu_nb = int(group["id"]) - 10

        packet_info: PacketInfo = PacketInfo(
            index=int(group["index"]),
            vmid=int(group["id"]),
            header=0x0,  # No header as it is already disassembled by perf
            cpu_nb=cpu_nb,
        )

        packet_name: str = group["name"]
        parse_info: ParseInfo = PacketParser.PACKETS_INFO[packet_name]

        parse_method: Callable[..., Packet] = getattr(self, parse_info.parse_method)
        packet: Packet = parse_method(
            packet_info=packet_info, packet_name=packet_name, line=line, regex=parse_info.regex
        )

        return packet

    # Packet parsing
    # \_______________

    def parse_addr(self, packet_name: str, packet_info: PacketInfo, line: str, regex: str) -> AddressPacket:
        match_address: re.Match[str] | None
        if match_address := re.search(regex, line):
            group: dict[str, str] = match_address.groupdict()
            address: int = string_to_int(group["address"])
        else:
            raise NoMatchingAddressError

        constr_method: Callable[..., AddressPacket] = getattr(AddressPacket, packet_name[2:].lower())
        return constr_method(packet_info=packet_info, address=address)

    def parse_addr_ctxt(
        self, packet_name: str, packet_info: PacketInfo, line: str, regex: str
    ) -> AddressContextPacket:
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

        constr_method: Callable[..., AddressContextPacket] = getattr(
            AddressContextPacket, packet_name[2:].lower()
        )
        return constr_method(packet_info=packet_info, address=address, context=context)

    def parse_trace_info(
        self, packet_info: PacketInfo, line: str, regex: str, **kwargs: dict[str, Any]
    ) -> InfoPacket:
        match_info: re.Match[str] | None
        if match_info := re.search(regex, line):
            group: dict[str, str] = match_info.groupdict()
            info_bits: int = string_to_int(group["info_bitfield"])
            info_fields: InfoFields = InfoFields(info_bits=info_bits)
        else:
            raise NoMatchingInfoError

        return InfoPacket.trace_info(packet_info=packet_info, info_fields=info_fields)

    def parse_atom(self, packet_info: PacketInfo, packet_name: str, line: str, regex: str) -> AtomPacket:
        match_elements: re.Match[str] | None
        if match_elements := re.search(regex, line):
            group: dict[str, str] = match_elements.groupdict()
            elements: list[str] = list(group["atom_elements"])
        else:
            raise NoMatchingElementsError

        # I_ATOM_F1 > [I, ATOM, F1] > 1, but atom format 6 can have more elements!
        format_extracted: str = packet_name.split("_")[-1][-1]
        if not AtomPacket.check_format_size(format=int(format_extracted), elements_nb=len(elements)):
            raise WrongSizeAtomPacketError(expected_size=int(format_extracted), size=len(elements))
        return AtomPacket.atom_format(packet_info=packet_info, elements=elements)

    def parse_trace_on(self, packet_info: PacketInfo, **kwargs: dict[str, Any]) -> SynchronizationPacket:
        return SynchronizationPacket.trace_on(packet_info=packet_info)

    def parse_async(self, packet_info: PacketInfo, **kwargs: dict[str, Any]) -> SynchronizationPacket:
        return SynchronizationPacket.asynch(packet_info=packet_info)
