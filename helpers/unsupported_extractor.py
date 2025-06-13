from pathlib import Path
import re
import sys
from elftools.elf.elffile import ELFFile

def extract_section(file_path, section_name):
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            section = elf.get_section_by_name(section_name)
            if not section:
                print(f"Section '{section_name}' not found.")
                return None
            return section.data().decode("utf-8")
    except OSError:
        print("[-] File not found")


def extract_unsupported_instructions(elf_file_name: str):
    annot_section: str = extract_section(elf_file_name, ".hbngannot")
    unsupported_regex = r"Unsupported: (?P<instruction>\w+)"
    unsupported_instructions: set[str] = set()

    matches = re.finditer(unsupported_regex, annot_section)
    unsupported_instructions.update(match.group("instruction") for match in matches)

    return unsupported_instructions


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf-file>")
        sys.exit(1)

    elf_file = sys.argv[1]
    print(f"Unsupported instructions (i.e. no annotations) in binary {elf_file}")
    print(extract_unsupported_instructions(elf_file))