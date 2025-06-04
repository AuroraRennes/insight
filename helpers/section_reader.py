import sys

from elftools.elf.elffile import ELFFile


def extract_section(file_path, section_name):
    with open(file_path, "rb") as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(section_name)
        if not section:
            print(f"Section '{section_name}' not found.")
            return None

        return section.data()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <elf-file> <section-name>")
        sys.exit(1)

    elf_file = sys.argv[1]
    section_name = sys.argv[2]

    data = extract_section(elf_file, section_name)

    if data:
        if section_name == ".hbngannot":
            print(f"ASCII Output from section '{section_name}':\n")
            print(data.decode("utf-8"))
        elif section_name == ".hbngbbt":
            bbt = []
            for idx in range(0, len(data), 16):
                bb_addr = int.from_bytes(data[idx : idx + 8], byteorder="little")
                annot_offset = int.from_bytes(data[idx + 8 : idx + 16], byteorder="little")
                bbt.append((bb_addr, annot_offset))
            print(f"Raw Output from section '{section_name}':\n")
            for entry in bbt:
                print(f"BB addr: {hex(entry[0])} | Offset: {hex(entry[1])}")
