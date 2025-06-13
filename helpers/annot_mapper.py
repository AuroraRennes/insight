import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re

# Define register name pattern
REGISTER_PATTERN = re.compile(r"<(X[0-9]+|W[0-9]+|Q[0-9]+|D[0-9]+|S[0-9]+|H[0-9]+|B[0-9]+|ZR|NZCV)>")

def count_registers(annotation_block):
    matches = REGISTER_PATTERN.findall(annotation_block)
    return sum(1 for r in matches if r != "SP")

def get_function_map(elf):
    func_map = {}
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

        annot_data = extract_section_data(elf, ".hbngannot")
        annot_start_address = elf.get_section_by_name(".hbngannot")["sh_addr"]
        bbt_data = extract_section_data(elf, ".hbngbbt")

        if annot_data is None or bbt_data is None:
            sys.exit(1)

        annotations = parse_annotations(annot_data)

        print("Combined BBT and Annotation Info:\n")

        for idx in range(0, len(bbt_data), 16):
            bb_addr = int.from_bytes(bbt_data[idx:idx+8], byteorder="little")
            annot_offset = int.from_bytes(bbt_data[idx+8:idx+16], byteorder="little") - annot_start_address

            func_name = get_function_name(bb_addr, func_map)
            try:
                bb_raw_annotation: str = annotations[annot_offset:].split("END")[0] + "END"

            except IndexError:
                bb_raw_annotation = "INVALID_OFFSET"

            print(f"└ {hex(bb_addr)} ({func_name})", end='')

            bb_annotations = bb_raw_annotation.split("\n")
            all_lines = "\n".join(bb_annotations)
            reg_count = count_registers(all_lines)
            print(f" [{reg_count} registers]")

            for line_annot in bb_annotations:
                print(f"  ├ {line_annot}")
