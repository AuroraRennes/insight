"""Instruction forms, and a corpus of their encodings taken from AArch64 executables.

A form is a mnemonic and the shape of its operands: 'ldr x0, [x1, #8]' is 'ldr x, [x, #]'.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import (
    ARM64_EXT_INVALID,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
    ARM64_SFT_INVALID,
)
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from capstone import CsInsn

EXT_NAMES = {1: "uxtb", 2: "uxth", 3: "uxtw", 4: "uxtx", 5: "sxtb", 6: "sxth", 7: "sxtw", 8: "sxtx"}
SHIFT_NAMES = {1: "lsl", 2: "msl", 3: "lsr", 4: "asr", 5: "ror"}
INSTANCES_PER_FORM = 4


def register_class(name: str) -> str:
    """x, w, sp, wsp, xzr, wzr, or the name with its number dropped (v.16b, d, q, ...)."""
    if name in {"sp", "wsp", "xzr", "wzr"}:
        return name
    if name in {"fp", "lr"}:
        return "x"
    return "".join(char for char in name if not char.isdigit()) or name


def operand_shape(insn: CsInsn, index: int) -> str:
    op = insn.operands[index]
    if op.type == ARM64_OP_REG:
        text = register_class(insn.reg_name(op.reg))
    elif op.type == ARM64_OP_IMM:
        text = "#"
    elif op.type == ARM64_OP_MEM:
        parts = [register_class(insn.reg_name(op.mem.base))]
        if op.mem.index:
            parts.append(register_class(insn.reg_name(op.mem.index)))
        elif op.mem.disp:
            parts.append("#")
        text = "[" + ", ".join(parts)
        if op.ext != ARM64_EXT_INVALID:
            text += f" {EXT_NAMES.get(op.ext, op.ext)}"
        if op.shift.type != ARM64_SFT_INVALID:
            text += " #"
        text += "]"
        return text
    else:
        # System registers, prefetch operations, barriers: the name is the form.
        return insn.op_str.split(",")[index].strip() if index < len(insn.op_str.split(",")) else "?"
    if op.ext != ARM64_EXT_INVALID:
        text += f" {EXT_NAMES.get(op.ext, op.ext)}"
    if op.shift.type != ARM64_SFT_INVALID and op.type == ARM64_OP_REG:
        text += f" {SHIFT_NAMES.get(op.shift.type, op.shift.type)}"
    return text


def form_of(insn: CsInsn) -> str:
    """The form of a decoded instruction, as text: 'ldr x, [x, #]!'."""
    shapes = [operand_shape(insn, i) for i in range(len(insn.operands))]
    mem = [i for i, op in enumerate(insn.operands) if op.type == ARM64_OP_MEM]
    if insn.writeback and mem:
        last = mem[-1]
        if last == len(shapes) - 2 and insn.operands[-1].type == ARM64_OP_IMM:
            shapes[last] += " post"
        else:
            shapes[last] += "!"
    text = insn.mnemonic
    if insn.cc:
        text += " cc"
    return f"{text} {', '.join(shapes)}".strip()


# Corpus
# \_______


@dataclass
class Corpus:
    """Encodings per form, and the files they were taken from (name, sha256, origin)."""

    forms: dict[str, list[str]] = field(default_factory=dict)
    sources: list[dict[str, str]] = field(default_factory=list)


def executable_instructions(elf: ELFFile) -> Iterator[CsInsn]:
    """Every instruction of the executable sections; words that do not decode are skipped."""
    if elf["e_machine"] != "EM_AARCH64":
        msg = f"not an AArch64 file: {elf['e_machine']}"
        raise ValueError(msg)
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    disassembler.detail = True
    disassembler.skipdata = True
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_PROGBITS" and section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
            yield from (
                insn for insn in disassembler.disasm(section.data(), section["sh_addr"]) if insn.id != 0
            )


def add_file(corpus: Corpus, path: Path, origin: str) -> None:
    """Up to INSTANCES_PER_FORM distinct encodings per form, in the order met; the file is
    recorded as a source, once."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if any(source["sha256"] == digest for source in corpus.sources):
        return
    corpus.sources.append({"file": path.name, "sha256": digest, "origin": origin})
    with path.open("rb") as file:
        for insn in executable_instructions(ELFFile(file)):
            encodings = corpus.forms.setdefault(form_of(insn), [])
            encoding = bytes(insn.bytes).hex()
            if len(encodings) < INSTANCES_PER_FORM and encoding not in encodings:
                encodings.append(encoding)


def save_corpus(corpus: Corpus, path: Path) -> None:
    data = {"sources": corpus.sources, "forms": dict(sorted(corpus.forms.items()))}
    path.write_text(json.dumps(data, indent=1) + "\n")


def load_corpus(path: Path) -> Corpus:
    data = json.loads(path.read_text())
    return Corpus(forms=data["forms"], sources=data["sources"])
