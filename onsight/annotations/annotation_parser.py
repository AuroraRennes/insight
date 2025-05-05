import re
from dataclasses import dataclass
from typing import Any

from onsight.exceptions import (
    MissingENDBlockError,
    MissingOperatorError,
    NoMatchDestinationError,
    NoMatchOperandError,
    WrongOffsetValueError,
)


@dataclass
class Tagged: ...


@dataclass
class UOp(Tagged): ...


@dataclass
class Immediate(Tagged):
    value: int


@dataclass
class Register(Tagged):
    name: str


@dataclass
class MemoryAccess(Tagged):
    base: Register
    offset: Immediate | Register
    scale: int
    shift_op: str | None
    shift_val: int | None
    access_size: int


@dataclass
class Assignment:
    destination: Register | MemoryAccess
    operator: str  # "ari", "sto", "loa", "bra"
    sources: list[Tagged]


class AnnotationParser:
    # Note: ?P<value> lets us define named value to be extracted from the matched group
    OPE_RE = re.compile(r"(?P<op>ari|sto|loa|bra)")
    IMM_RE = re.compile(r"Imm\(?P<value>-?\d+\)")
    REG_RE = re.compile(r"(?P<name>[A-Z0-9]+)")
    MEM_RE = re.compile(
        r"""
        \[                          # Opening bracket
        <(?P<base>[A-Z0-9]+)>       # Base register
        \s*\+\s*                    # +
        (?P<scale>[248])\*          # Scale (2, 4, 8)
        (?P<offset><[A-Z0-9]+>|Imm\(-?\d+\))  # Offset register or immediate
        (?:\s+(?P<shiftop>uxtx|uxtw|sxtx|sxtw)\s+(?P<shiftval>2|4|8))?  # Optional shift
        \]_
        (?P<accesssize>\d+)         # Access size (e.g., 32)
        """,
        re.VERBOSE,
    )

    # LHS is either a register or a memory access
    def parse_annotations(self, annotations: list[str]) -> list[Assignment]:
        assignments: list[Assignment] = []
        for line in annotations:
            if line == "END":
                return assignments
            lhs: str
            rhs: str
            lhs, rhs = line.split("<-")
            # Compute destination
            destination: Register | MemoryAccess = self.parse_lhs(lhs)
            # Get operator
            operator: str = self.parse_operator(rhs)
            # Use operator to split the sources and parse the operands
            sources: list[Tagged] = [self.parse_operand(operand) for operand in rhs.split(operator)]
            if len(sources) == 1 and operator != "noop":
                raise MissingOperatorError(rhs)
            # Create a new Assignment and add it to the list
            assignments.append(Assignment(destination=destination, operator=operator, sources=sources))
        raise MissingENDBlockError

    # Extract the operator from the RHS
    def parse_operator(self, rhs: str) -> str:
        rhs = rhs.strip()
        if match := AnnotationParser.OPE_RE.search(rhs):
            groups = match.groupdict()
            return groups["op"]
        return "noop"

    def parse_lhs(self, lhs: str) -> Register | MemoryAccess:
        dest = lhs.strip()
        if match := AnnotationParser.REG_RE.match(dest):
            groups = match.groupdict()
            return Register(groups["name"])
        if match := AnnotationParser.MEM_RE.match(dest):
            groups = match.groupdict()
            return self.parse_memory_operand(groups)
        raise NoMatchDestinationError(lhs)

    def parse_operand(self, operand: str) -> Tagged:
        operand = operand.strip()
        if match := AnnotationParser.IMM_RE.match(operand):
            groups = match.groupdict()
            return Immediate(int(groups["value"]))
        if match := AnnotationParser.REG_RE.match(operand):
            groups = match.groupdict()
            return Register(groups["name"])
        if match := AnnotationParser.MEM_RE.match(operand):
            groups = match.groupdict()
            return self.parse_memory_operand(groups)
        if operand == "UOp":
            return UOp()
        raise NoMatchOperandError(operand)

    def parse_memory_operand(self, groups: dict[str, str | Any]) -> MemoryAccess:
        base = Register(groups["base"])
        scale = int(groups["scale"])
        offset_raw = groups["offset"]
        shift_op = groups["shiftop"]
        shift_val = int(groups["shiftval"]) if groups["shiftval"] else None
        access_size = int(groups["accesssize"])

        # Interpret offset
        offset: Immediate | Register
        if offset_raw.startswith("<") and offset_raw.endswith(">"):
            offset = Register(offset_raw[1:-1])
        elif offset_raw.startswith("Imm("):
            offset = Immediate(int(offset_raw[4:-1]))
        else:
            raise WrongOffsetValueError

        return MemoryAccess(
            base=base,
            scale=scale,
            offset=offset,
            shift_op=shift_op,
            shift_val=shift_val,
            access_size=access_size,
        )


if __name__ == "__main__":
    from onsight.annotations.annotation_decoder import AnnotationDecoder

    decoder = AnnotationDecoder()
    annot_dict = decoder.decode_elf_file("data/annotations/bin/fib")

    test_annotations = annot_dict[1940].annotations

    parser = AnnotationParser()
    parser.parse_annotations(test_annotations)
