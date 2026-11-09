import re
import sys
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


@dataclass
class AddressPacket:
    index: int
    address: int


class SymbolDict(dict[int, str]):
    def function_for_address(self, address: int) -> str:
        func_address: int = max((addr for addr in self if addr <= address), default=0)
        function: str = ""
        try:
            function = self[func_address]
        except KeyError:
            function = "?"
        offset: int = address - func_address
        return f"{function} + 0x{offset:x}" if offset > 0 else function


def extract_symbol_dict(elf_file_name: str) -> SymbolDict:

    symbol_dict: SymbolDict = SymbolDict()

    with Path(elf_file_name).open("rb") as raw_elf_file:
        elf_file: ELFFile = ELFFile(raw_elf_file)
        symtab_data = elf_file.get_section_by_name(".symtab")
        if not isinstance(symtab_data, SymbolTableSection):
            print("[-] symtab section missing, the binary might be stripped.")
            return symbol_dict

        for symbol in symtab_data.iter_symbols():
            # Only keep symbolss
            if symbol["st_info"]["type"] == "STT_FUNC":
                symbol_dict[symbol["st_value"]] = symbol.name
    return symbol_dict



def parse_opencsd_trace(trace_file_name: str) -> list[AddressPacket]:
    packets: list[AddressPacket] = []
    addr_regex: str = r"Idx:(?P<index>\d+);.*Addr=(?P<address>0x\w+)"

    with Path(trace_file_name).open("r") as trace_file:
        for line in trace_file:
            match_line: re.Match[str] | None = re.search(addr_regex, line)
            if match_line:
                group: dict[str, str] = match_line.groupdict()
                index: int = int(group["index"])
                address: int = int(group["address"], 16)
                packets.append(AddressPacket(index, address))
    return packets


def label_packets(packets: list[AddressPacket], symbol_dict: SymbolDict) -> None:
    for packet in packets:
        symbol: str = symbol_dict.function_for_address(packet.address)
        print(
            f"Packet {packet.index:6} points to {hex(packet.address):18} in {symbol}"
        )



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <elf-file> <trace-file>")
        sys.exit(1)

    elf_file = sys.argv[1]
    trace_file = sys.argv[2]

    symbol_dict: SymbolDict = extract_symbol_dict(elf_file)
    packets: list[AddressPacket] = parse_opencsd_trace(trace_file)

    label_packets(packets, symbol_dict)
