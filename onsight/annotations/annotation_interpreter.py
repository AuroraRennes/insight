import logging
from collections import deque
from collections.abc import Callable
from functools import reduce
from typing import ClassVar

from onsight.annotations.annotation_decoder import AnnotationDict
from onsight.annotations.annotation_parser import (
    AnnotationParser,
    Assignment,
    Immediate,
    MemoryAccess,
    Register,
    UOp,
)
from onsight.arm64_state import ARM64State
from onsight.exceptions import OperatorNotDefinedError, STMFIFOEmptyError, UnknownSPUpdateError
from onsight.packets import AddressPacket, AtomPacket, DataPacket, Packet

# Data classes to represent a minimal AST


logger = logging.getLogger("onsight")


class STMFIFO:
    def __init__(self) -> None:
        self.queue: deque = deque()

    def enqueue(self, item: int) -> None:
        self.queue.append(item)

    def dequeue(self) -> int:
        if self.queue:
            return self.queue.popleft()
        raise STMFIFOEmptyError

    def __len__(self) -> int:
        return len(self.queue)


class AnnotationInterpreter:
    OPERATORS: ClassVar[dict[str, Callable[[int, int], int]]] = {
        "and": lambda a, b: a & b,
        "or": lambda a, b: a | b,
        "lhs": lambda a, _: a,
        "rhs": lambda _, b: b,
    }

    def __init__(self) -> None:
        self.state: ARM64State = ARM64State()
        self.config: dict[str, str] = {
            "ari": "or",
            "add": "or",
            "sub": "or",
            "sto": "or",
            "loa": "or",
            "bra": "or",
        }

        self.stm_addresses: STMFIFO = STMFIFO()
        self.annot_parser: AnnotationParser = AnnotationParser()

    def interpret_packet_trace(
        self, packet_trace: list[Packet], annotation_dict: AnnotationDict, start_address: int
    ) -> None:
        current_address: int = start_address
        current_offset: int = 0

        # Execute annotations one by one
        for packet in packet_trace:
            if isinstance(packet, AddressPacket):
                current_address = packet.address
                current_offset = current_address - start_address

            elif isinstance(packet, AtomPacket):
                bb_offset = current_offset

                for atom_element in packet.elements:
                    # If the address is not present in the annotation dictionary, the info
                    # should come from a fucntion outside of the annotated binary (libraries, etc.)
                    if bb_offset not in annotation_dict:
                        logger.warning(
                            "Atom element reached but no corresponding annotations "
                            f"were found for address {hex(bb_offset)}"
                        )
                        continue
                    bb_assignments: list[Assignment] = annotation_dict[bb_offset].assignments
                    self.interpret_block(bb_assignments)
                    # If the atom element is E, branch broadcasting SHOULD be enabled and
                    # produce another address packet
                    if atom_element == "N":
                        bb_offset = annotation_dict.next_key(bb_offset)

            elif isinstance(packet, DataPacket):
                self.stm_addresses.enqueue(packet.data_value)

    def interpret_block(self, assignments: list[Assignment]) -> None:
        assignment: Assignment
        for assignment in assignments:
            operator: str = assignment.operator
            tag_value: int
            if operator == "noop" and len(assignment.sources) == 1:
                tag_value = assignment.sources[0].accept_eval(self)
            else:
                if operator not in self.config:
                    raise OperatorNotDefinedError(operator)
                tag_value = reduce(
                    AnnotationInterpreter.OPERATORS[self.config[operator]],
                    [operand.accept_eval(self) for operand in assignment.sources],
                )

            destination: Register | MemoryAccess = assignment.destination
            if isinstance(destination, Register):
                reg_destination: Register = destination
                self.state.write_register(register_name=reg_destination.name, tag=tag_value)
                # Check if the destination register is the SP, in which case it should
                # be computed and stored as the new stack value
                self.update_sp(assignment, reg_destination)

            if isinstance(destination, MemoryAccess):
                mem_destination: MemoryAccess = destination
                access_address: int = self.compute_memory_access_address(memory_access=mem_destination)
                self.state.memory_write(
                    address=access_address, size=mem_destination.access_size, tag=tag_value
                )

    def update_sp(self, assignment: Assignment, reg_destination: Register) -> None:
        if not reg_destination.is_sp():
            return
        # RHS should be in the form SP op Imm
        if isinstance(assignment.sources[0], Register) and isinstance(assignment.sources[1], Immediate):
            reg_source: Register = assignment.sources[0]
            if not reg_source.is_sp():
                raise UnknownSPUpdateError(assignment.raw_annot)

            imm_source: Immediate = assignment.sources[1]
            match assignment.operator:
                case "add":
                    self.state.stack_value += imm_source.value
                case "sub":
                    self.state.stack_value -= imm_source.value
        else:
            raise UnknownSPUpdateError(assignment.raw_annot)

    def get_register_tag(self, register: Register) -> int:
        return self.state.read_register(register.name)

    def get_immediate_tag(self, _: Immediate) -> int:
        return 0

    def get_uop_tag(self, _: UOp) -> int:
        return 0

    def get_memory_tag(self, memory_access: MemoryAccess) -> int:
        memory_access_address: int = self.compute_memory_access_address(memory_access=memory_access)
        return self.state.memory_read(address=memory_access_address, size=memory_access.access_size)

    def compute_memory_access_address(self, memory_access: MemoryAccess) -> int:
        # Base register
        base_value: int = self.stm_addresses.dequeue()
        # Offset
        offset: Immediate | Register = memory_access.offset
        offset_value: int
        if isinstance(offset, Immediate):
            imm_offset: Immediate = offset
            offset_value = imm_offset.value
        if isinstance(offset, Register):
            offset_value = self.stm_addresses.dequeue()
        # Scale offset
        scale_value: int = memory_access.scale
        # Compute address
        address_value: int = base_value + scale_value * offset_value
        # Optional shift
        shift_op: str | None = memory_access.shift_op
        shift_val: int = memory_access.shift_val
        if shift_op:
            match shift_op:
                case "uxtx":
                    address_value = address_value << shift_val
                case "uxtw":
                    address_value = address_value << shift_val
                case "sxtx":
                    address_value = address_value << shift_val
        return address_value
