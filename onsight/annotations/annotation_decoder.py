import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

from onsight.annotations.annotation_parser import AnnotationParser, Assignment
from onsight.exceptions import EmptySectionError, MissingSectionError

logger = logging.getLogger("onsight")


@dataclass
class AnnotationInfo:
    bb_offset: int
    annotation_offset: int
    annotations: list[str]
    assignments: list[Assignment]


class AnnotationDict(dict[int, AnnotationInfo]):
    def next_key(self, current_key: int) -> int:
        sorted_keys = sorted(self.keys())
        return sorted_keys[sorted_keys.index(current_key) + 1]


# Similar to str.split(char) but for lists
def split_list_on_sep(lst: list[str], sep: str) -> list[list[str]]:
    result: list[list[str]] = []
    current: list[str] = []
    for item in lst:
        current.append(item)
        if item == sep:
            result.append(current)
            current = []
    if current and current[0] != "":
        result.append(current)
    return result


class AnnotationDecoder:
    ANNOTATION_SECTION = ".hbngannot"
    BBT_SECTION = ".hbngbbt"

    def __init__(self) -> None:
        self.annotation_parser: AnnotationParser = AnnotationParser()

    def get_section_data(self, elf_file: ELFFile, section_name: str) -> bytes:
        section = elf_file.get_section_by_name(section_name)
        if section is None:
            raise MissingSectionError

        section_data = section.data()
        if len(section_data) == 0:
            raise EmptySectionError

        return section_data

    def decode_elf_file(self, elf_file_name: str) -> AnnotationDict:
        try:
            with Path(elf_file_name).open("rb") as raw_file:
                elf_file = ELFFile(raw_file)
                bbt_section = self.decode_bbt_section(elf_file)
                annotations_section = self.decode_annotation_section(elf_file)
        except OSError:
            logger.exception("[-] ELF file opening failed.")
            sys.exit(1)
        except (MissingSectionError, EmptySectionError):
            logger.exception("[-] Empty of missing section.")
            sys.exit(1)

        # Format results
        bbt: list[tuple[int, int]] = bbt_section
        bb_annotations: list[list[str]] = split_list_on_sep(annotations_section.split("\n"), "END")
        bb_assignments: list[list[Assignment]] = [
            self.annotation_parser.parse_annotations(bb_annotation) for bb_annotation in bb_annotations
        ]

        if len(bbt) != len(bb_annotations):
            logger.exception("[-] BBT and annotation sections size mismatch.")
            sys.exit(1)

        annotation_dict: AnnotationDict = AnnotationDict()
        for annotations, assignments, bbt_entry in zip(bb_annotations, bb_assignments, bbt, strict=False):
            bb_offset, annotation_offset = bbt_entry
            annotation_dict[bb_offset] = AnnotationInfo(
                bb_offset=bb_offset,
                annotation_offset=annotation_offset,
                annotations=annotations,
                assignments=assignments,
            )
        return annotation_dict

    def decode_annotation_section(self, elf_file: ELFFile) -> str:
        annotation_data = self.get_section_data(elf_file, AnnotationDecoder.ANNOTATION_SECTION)
        return annotation_data.decode("utf-8")

    def decode_bbt_section(self, elf_file: ELFFile) -> list[tuple[int, int]]:
        # Extract the section
        bbt_section = self.get_section_data(elf_file, AnnotationDecoder.BBT_SECTION)
        bbt = []
        # The bbt section is composed of a succession of double words pairs:
        # (address of the basic block, offset of the annotations linked to it)
        for idx in range(0, len(bbt_section), 16):
            bb_addr = int.from_bytes(bbt_section[idx : idx + 8], byteorder="little")
            annot_offset = int.from_bytes(bbt_section[idx + 8 : idx + 16], byteorder="little")
            bbt.append((bb_addr, annot_offset))
        return bbt
