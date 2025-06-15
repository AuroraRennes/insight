from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict
import re
import sys

@dataclass
class InfoData:
    address: int
    name: str
    reg_num: int
    ends_with_branch: bool


def extract_annotation_data(annotation_text):
    pattern = r"└ (?P<address>0x[0-9a-f]+) \((?P<name>[^)]+)\) \[(?P<reg_num>\d+) registers\]"
    results = {}
    for line in annotation_text:
        match = re.match(pattern, line.strip())
        if match:
            group = match.groupdict()
            address = int(group["address"], 16)
            results[address] =(
                InfoData(
                    address,
                    group["name"],
                    int(group["reg_num"]),
                    False # unused
                )
            )
    return results

def process_annot_file(annot_file_path: str):
    with Path(annot_file_path).open("r") as annot_file:
        annotation = annot_file.readlines()
        return extract_annotation_data(annotation)


def extract_dump_data(dump_text):
    label_re = re.compile(r"^0*(?P<address>[0-9a-f]+) <(?P<name>[^>]+)>:$")
    instr_re = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+(\w+).*\[x26\]")
    branch_re = re.compile(r"\b(svc|b|bl|blr|br|cbz|cbnz|tbz|tbnz|ret|b|b.eq|b.hi)\b")

    results = {}
    current_count = 0
    current_address = 0
    current_name = ""
    current_branch = False

    cleaned_text = [
        line for line in dump_text if (
            line != "\n" and "udf" not in line
        )
        ]


    for line in cleaned_text:
        # try to match the function name and update the current one
        label_match = label_re.match(line.strip())
        if label_match:
            # emit the previous function info
            if current_name:
                results[current_address] = InfoData(
                    current_address,
                    current_name,
                    current_count,
                    current_branch
                )
            group = label_match.groupdict()
            current_name = group["name"]
            current_address = int(group["address"], 16)
            current_count = 0
        else:
            # check if there is a store to [x26]
            instr_match = instr_re.search(line)
            branch_match = branch_re.search(line)
            current_branch = False
            if instr_match:
                instr = instr_match.group(1)
                if instr.startswith("stp"):
                    current_count += 2
                elif instr.startswith("str"):
                    current_count += 1
            # check if there is a branch instruction
            elif branch_match:
                current_branch = True

    # Last one!
    results[current_address] = InfoData(
        current_address,
        current_name,
        current_count,
        current_branch
    )

    return results


def patch_dump_results(results):
    sorted_keys = sorted(results.keys())
    for i, address in enumerate(sorted_keys[:-1]):
        if not results[address].ends_with_branch:
            j = 1
            while not results[sorted_keys[i + j]].ends_with_branch:
                results[address].reg_num += results[sorted_keys[i + j]].reg_num
                j += 1
            # Last one
            results[address].reg_num += results[sorted_keys[i + j]].reg_num
    return results


def process_dump_file(dump_file_path: str):
    with Path(dump_file_path).open("r") as dump_file:
        dump = dump_file.readlines()
        return extract_dump_data(dump)



if __name__ == "__main__":
    # if len(sys.argv) != 3:
    #     print(f"Usage: {sys.argv[0]} <dump-file> <annot-file>")
    #     sys.exit(1)

    annot_dict = process_annot_file("data/annotations/bin/fib.annot")
    dump_dict = process_dump_file("data/annotations/bin/fib.dump")

    res_dict = {}

    for address in annot_dict.keys():
        annot_num_reg = annot_dict[address].reg_num
        dump_num_reg = dump_dict[address].reg_num
        if annot_num_reg != dump_num_reg:
            res_dict[address] = (dump_num_reg, annot_num_reg)

    if res_dict:
        print("Issues found:\n____________________")
        for address in res_dict.keys():
            print(
                f"{hex(address)} - Issue in {dump_dict[address].name:35}"
                f" | {res_dict[address][0]:2} (dump) | {res_dict[address][1]:2} (annot) |"
            )
    else:
        print("No issues found!")