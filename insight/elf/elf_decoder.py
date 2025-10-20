import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

from insight.annotations.annotation_parser import AnnotationParseInfo, AnnotationParser, Assignment
from insight.exceptions import EmptySectionError, MissingSectionError

logger = logging.getLogger("insight")


@dataclass
class BBAnnotationsInfo:
    bb_offset: int
    annotation_offset: int
    annotations: list[str]
    assignments: list[Assignment]
    function_name: str | None
    ends_with_end: bool
    contains_svc: bool


@dataclass
class SectionInfo:
    data: bytes
    address: int


class AnnotationDict(dict[int, BBAnnotationsInfo]):
    def next_key(self, current_key: int) -> int:
        sorted_keys = sorted(self.keys())
        return sorted_keys[sorted_keys.index(current_key) + 1]


class SymbolDict(dict[int, str]):
    def function_for_address(self, address: int) -> str:
        func_address: int = max((addr for addr in self if addr <= address), default=0)
        return self[func_address]


@dataclass
class ELFInfo:
    annotation_dict: AnnotationDict
    symbol_dict: SymbolDict | None


class ELFDecoder:
    ANNOTATION_SECTION = ".hbngannot"
    BBT_SECTION = ".hbngbbt"

    def __init__(self) -> None:
        self.annotation_parser: AnnotationParser = AnnotationParser()
        self.section_infos: dict[str, SectionInfo] = {}

    def get_section_info(self, elf_file: ELFFile, section_name: str) -> SectionInfo:
        section = elf_file.get_section_by_name(section_name)
        if section is None:
            raise MissingSectionError(section_name)

        section_data = section.data()
        if len(section_data) == 0:
            raise EmptySectionError(section_name)

        section_info: SectionInfo = SectionInfo(data=section_data, address=section["sh_addr"])

        self.section_infos[section_name] = section_info

        return section_info

    def decode_elf_file(self, elf_file_name: str) -> ELFInfo:
        try:
            with Path(elf_file_name).open("rb") as raw_file:
                elf_file: ELFFile = ELFFile(raw_file)
                symbol_dict: SymbolDict | None = self.decode_func_symbols(elf_file)
                try:
                    bbt: list[tuple[int, int]] = self.decode_bbt_section(elf_file)
                    annotations_section: str = self.decode_annotation_section(elf_file)
                except (MissingSectionError, EmptySectionError):
                    logger.warning("[-] Empty or missing section.")
                    annotations_section = ""
                    bbt = []
        except OSError:
            logger.exception("[-] ELF file opening failed.")
            sys.exit(1)

        annot_section_start_addr: int = self.section_infos[".hbngannot"].address
        annotation_dict: AnnotationDict = AnnotationDict()
        bbt_entry: tuple[int, int]
        for i, bbt_entry in enumerate(bbt):
            # Extract the annotation offset and basic block address
            bb_address: int
            annotation_address: int
            next_annotation_address: int
            bb_address, annotation_address = bbt_entry

            if i == len(bbt) - 1:
                # Mitigate the address
                next_annotation_address = len(annotations_section) + annot_section_start_addr
            else:
                _, next_annotation_address = bbt[i + 1]

            if symbol_dict:
                function_name: str = symbol_dict.function_for_address(bb_address)
            # Annotations are split from an offset to the next one
            bb_annotations: list[str] = self.separate_annotations_from_offset(
                annotations_section,
                annotation_address - annot_section_start_addr,
                next_annotation_address - annot_section_start_addr,
            )

            bb_assignments_parse_info: AnnotationParseInfo = self.annotation_parser.parse_annotations(
                bb_annotations
            )

            annotation_dict[bb_address] = BBAnnotationsInfo(
                bb_offset=bb_address,
                annotation_offset=annotation_address,
                annotations=bb_annotations,
                assignments=bb_assignments_parse_info.assignments,
                function_name=function_name,
                ends_with_end=bb_assignments_parse_info.ends_with_end,
                contains_svc=bb_assignments_parse_info.contains_svc,
            )

        return ELFInfo(annotation_dict=annotation_dict, symbol_dict=symbol_dict)

    def separate_annotations_from_offset(self, annotations: str, offset: int, next_offset: int) -> list[str]:
        bb_fragment: str = annotations[offset:next_offset]
        return bb_fragment.split("\n")[:-1]

    def decode_annotation_section(self, elf_file: ELFFile) -> str:
        annotation_data = self.get_section_info(elf_file, ELFDecoder.ANNOTATION_SECTION).data
        return annotation_data.decode("utf-8")

    def decode_bbt_section(self, elf_file: ELFFile) -> list[tuple[int, int]]:
        # Extract the section
        bbt_section = self.get_section_info(elf_file, ELFDecoder.BBT_SECTION).data
        bbt = []
        # The bbt section is composed of a succession of double words pairs:
        # (address of the basic block, offset of the annotations linked to it)
        for idx in range(0, len(bbt_section), 16):
            bb_addr = int.from_bytes(bbt_section[idx : idx + 8], byteorder="little")
            annot_offset = int.from_bytes(bbt_section[idx + 8 : idx + 16], byteorder="little")
            bbt.append((bb_addr, annot_offset))
        return bbt

    def decode_func_symbols(self, elf_file: ELFFile) -> SymbolDict | None:
        symtab_data = elf_file.get_section_by_name(".symtab")
        if not symtab_data:
            logger.warning("[-] symtab section missing, the binary might be stripped.")
            return None

        symbol_dict: SymbolDict = SymbolDict()
        for symbol in symtab_data.iter_symbols():
            # Only keep symbols
            if symbol["st_info"]["type"] == "STT_FUNC":
                symbol_dict[symbol["st_value"]] = symbol.name
        return symbol_dict
