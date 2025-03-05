import logging
from pathlib import Path

from elftools.elf.elffile import ELFFile

from onsight.exceptions import EmptySectionError, MissingSectionError

logger = logging.getLogger("onsight")


class AnnotationParser:
    ANNOTATION_SECTION = ".hbngannot"
    BBT_SECTION = ".hbngbbt"

    def get_section_data(self, elf_file: ELFFile, section_name: str) -> bytes:
        section = elf_file.get_section_by_name(section_name)
        if section is None:
            raise MissingSectionError

        section_data = section.data()
        if len(section_data) == 0:
            raise EmptySectionError

        return section_data

    def parse_elf_file(self, elf_file_name: str) -> None:
        try:
            with Path(elf_file_name).open("rb") as raw_file:
                elf_file = ELFFile(raw_file)
                self.parse_bbt_section(elf_file)
                self.parse_annotation_section(elf_file)
        except OSError:
            logger.exception("[-] ELF file opening failed.")
        except (MissingSectionError, EmptySectionError):
            logger.exception("[-] Empty of missing section.")

    def parse_annotation_section(self, elf_file: ELFFile) -> str:
        annotation_data = self.get_section_data(elf_file, AnnotationParser.ANNOTATION_SECTION)
        return annotation_data.decode("utf-8")

    def parse_bbt_section(self, elf_file: ELFFile) -> list[tuple[int, int]]:
        # Extract the section
        bbt_section = self.get_section_data(elf_file, AnnotationParser.BBT_SECTION)
        bbt = []
        # The bbt section is composed of a succession of double words pairs:
        # (address of the basic block, offset of the annotations linked to it)
        for idx in range(0, len(bbt_section), 16):
            bb_addr = int.from_bytes(bbt_section[idx : idx + 8], byteorder="little")
            annot_offset = int.from_bytes(bbt_section[idx + 8 : idx + 16], byteorder="little")
            bbt.append((bb_addr, annot_offset))
        return bbt


if __name__ == "__main__":
    ann_parser = AnnotationParser()
    ann_parser.parse_elf_file("data/annotations/bin/fib")
