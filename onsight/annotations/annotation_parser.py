from __future__ import annotations

import abc
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from annotations.annotation_interpreter import AnnotationInterpreter


from onsight.exceptions import (
    MissingENDBlockError,
    MissingOperatorError,
    NoMatchDestinationError,
    NoMatchOperandError,
    WrongOffsetValueError,
)


@dataclass
class Tagged:
    @abc.abstractmethod
    def accept_eval(self, _: AnnotationInterpreter) -> int: ...


@dataclass
class UOp(Tagged):
    def accept_eval(self, interpreter: AnnotationInterpreter) -> int:
        return interpreter.get_uop_tag(self)


@dataclass
class Immediate(Tagged):
    value: int

    def accept_eval(self, interpreter: AnnotationInterpreter) -> int:
        return interpreter.get_immediate_tag(self)


@dataclass
class Register(Tagged):
    name: str

    def accept_eval(self, interpreter: AnnotationInterpreter) -> int:
        return interpreter.get_register_tag(self)


@dataclass
class MemoryAccess(Tagged):
    base: Register
    offset: Immediate | Register
    scale: int
    shift_op: str | None
    shift_val: int
    access_size: int

    def accept_eval(self, interpreter: AnnotationInterpreter) -> int:
        return interpreter.get_memory_tag(self)


@dataclass
class Assignment:
    destination: Register | MemoryAccess
    operator: str  # "ari", "sto", "loa", "bra"
    sources: list[Tagged]
    raw_annot: str


class AnnotationParser:
    # Note: ?P<value> lets us define named value to be extracted from the matched group
    OPE_RE = re.compile(r"(?P<op>ari|sto|loa|bra)")
    IMM_RE = re.compile(r"Imm\((?P<value>-?\d+)\)")
    REG_RE = re.compile(r"(?P<name>[A-Z0-9]+)")
    MEM_RE = re.compile(
        r"""
        \[                          # Opening bracket
        <(?P<base>[A-Z0-9]+)>       # Base register
        \s*\+\s*                    # +
        ((?P<scale>[248])\*)?          # Scale (2, 4, 8)
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
            assignments.append(
                Assignment(destination=destination, operator=operator, sources=sources, raw_annot=line)
            )
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
        if operand == "UOp":
            return UOp()
        if match := AnnotationParser.IMM_RE.match(operand):
            groups = match.groupdict()
            return Immediate(int(groups["value"]))
        if match := AnnotationParser.REG_RE.match(operand):
            groups = match.groupdict()
            return Register(groups["name"])
        if match := AnnotationParser.MEM_RE.match(operand):
            groups = match.groupdict()
            return self.parse_memory_operand(groups)
        raise NoMatchOperandError(operand)

    def parse_memory_operand(self, groups: dict[str, str | Any]) -> MemoryAccess:
        base = Register(groups["base"])
        scale = int(groups["scale"]) if groups["scale"] else 1
        offset_raw = groups["offset"]
        shift_op = groups["shiftop"]
        shift_val = int(groups["shiftval"]) if groups["shiftval"] else 0
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
