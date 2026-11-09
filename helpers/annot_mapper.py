import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re

# Define register name pattern
REGISTER_PATTERN = re.compile(r"<(X[0-9]+|W[0-9]+|Q[0-9]+|D[0-9]+|S[0-9]+|H[0-9]+|B[0-9]+|ZR|NZCV)>")

def count_registers(annotation_block):
    matches = REGISTER_PATTERN.findall(annotation_block)
    return sum(1 for r in matches if r != "SP")

def get_function_map(elf) -> dict[int, str]:
    func_map: dict[int, str] = {}
    symtab = elf.get_section_by_name('.symtab')
    if not isinstance(symtab, SymbolTableSection):
        return func_map

    for symbol in symtab.iter_symbols():
        if symbol['st_info']['type'] == 'STT_FUNC':
            addr = symbol['st_value']
            name = symbol.name
            func_map[addr] = name

    return func_map


def get_function_name(addr, func_map):
    candidates = [a for a in func_map if a <= addr]
    if not candidates:
        return "UNKNOWN"
    return func_map[max(candidates)]


def extract_section_data(elf, section_name):
    section = elf.get_section_by_name(section_name)
    if not section:
        print(f"Section '{section_name}' not found.")
        return None
    return section.data()


def parse_annotations(data):
    return data.decode("utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf-file>")
        sys.exit(1)

    elf_path = sys.argv[1]

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        func_map = get_function_map(elf)

        annot_section = elf.get_section_by_name(".hbngannot")
        annot_data = extract_section_data(elf, ".hbngannot")
        bbt_data = extract_section_data(elf, ".hbngbbt")

        if annot_section is None or annot_data is None or bbt_data is None:
            sys.exit(1)
        annot_start_address = annot_section["sh_addr"]

        annotations = parse_annotations(annot_data)

        print("Combined BBT and Annotation Info:\n")

        bbt = []

        for idx in range(0, len(bbt_data), 16):
            bb_addr = int.from_bytes(bbt_data[idx : idx + 8], byteorder="little")
            annot_offset = int.from_bytes(bbt_data[idx + 8 : idx + 16], byteorder="little")
            bbt.append((bb_addr, annot_offset))

        for i, bbt_entry in enumerate(bbt):
            bb_addr, annot_addr = bbt_entry

            func_name = get_function_name(bb_addr, func_map)

            if i == len(bbt) - 1:
                next_annot_addr = len(annotations) + annot_start_address
            else:
                _, next_annot_addr = bbt[i + 1]

            bb_raw_annotations = annotations[
                annot_addr - annot_start_address : next_annot_addr - annot_start_address
            ]

            print(f"└ {hex(bb_addr)} ({func_name})", end='')

            reg_count = count_registers(bb_raw_annotations)
            print(f" [{reg_count} registers]")

            bb_annotations = bb_raw_annotations.split("\n")[:-1]
            for line_annot in bb_annotations:
                print(f"  ├ {line_annot}")
