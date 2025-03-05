from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from onsight.helpers import reverse_endianness32, string_to_bytes, string_to_int

if TYPE_CHECKING:
    from io import TextIOWrapper

logger = logging.getLogger("onsight")


@dataclass
class FunctionInfo:
    name: str
    address: int
    instructions: list[bytes]

    @classmethod
    def default(cls) -> FunctionInfo:
        return FunctionInfo(name="default", address=0, instructions=[])


class FunctionDict(dict[int, FunctionInfo]):
    def find_function_by_address(self, address: int) -> FunctionInfo | None:
        func_info: FunctionInfo
        for func_info in self.values():
            func_end: int = func_info.address + len(func_info.instructions) * 4
            if func_info.address <= address < func_end:
                return func_info
        return None


class ObjdumpParser:
    # The objdump parser is responsible for extracting a function dictionary from
    # a dump file. It extracts a FunctionDict object that uses function addresses
    # as keys and FunctionInfo as values.

    # Alternative with offset from function symbol
    START_FUNCTION_REGEX: str = r"([\w\._]*) <([\w\._]+)>:"
    # Regex line   828:  b9801fe0  ldrsw  x0, [sp, #28]
    #  matches     828   b9801fe0  ldrsw
    DISASM_LINE_REGEX: str = r"(\w+):\s+(\w+)\s+(\w+[\.\w*]*)"

    @staticmethod
    def parse_dump(dump_file_name: str) -> FunctionDict:
        logger.info("[+] Extracting function info from dump.")
        function_dict: FunctionDict = FunctionDict()
        try:
            with Path(dump_file_name).open() as objdump_file:
                for line in objdump_file:
                    # Match the start of a function
                    match_start: re.Match[str] | None = re.search(ObjdumpParser.START_FUNCTION_REGEX, line)
                    if match_start:
                        function_address: int = string_to_int(match_start.group(1))
                        function_name: str = match_start.group(2)
                        function_info: FunctionInfo = ObjdumpParser.extract_function_info(
                            dump_file=objdump_file,
                            function_address=function_address,
                            function_name=function_name,
                        )
                        function_dict[function_address] = function_info

        except OSError:
            logger.exception("[-] Objdump Parsing Failed.")
            raise

        return function_dict

    @staticmethod
    def extract_function_info(
        dump_file: TextIOWrapper, function_address: int, function_name: str
    ) -> FunctionInfo:
        line: str = next(dump_file)
        match_line: re.Match[str] | None = re.search(ObjdumpParser.DISASM_LINE_REGEX, line)
        instructions: list[bytes] = []
        while match_line:
            instr_bytes: bytes = reverse_endianness32(string_to_bytes(match_line.group(2)))
            instructions.append(instr_bytes)
            # Next one!
            try:
                line = next(dump_file)
                match_line = re.search(ObjdumpParser.DISASM_LINE_REGEX, line)
            except StopIteration:
                break
        return FunctionInfo(name=function_name, address=function_address, instructions=instructions)
