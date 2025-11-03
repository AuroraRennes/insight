import logging
from collections import deque
from collections.abc import Callable
from functools import reduce
from typing import ClassVar

from insight.annotations.annotation_parser import (
    AnnotationParser,
    Assignment,
    Immediate,
    MemoryAccess,
    Register,
    UOp,
)
from insight.elf.elf_decoder import AnnotationDict, ELFInfo, SymbolDict
from insight.exceptions import (
    OperatorNotDefinedError,
    STMFIFOEmptyError,
    TagCheckingRuleError,
    UnknownSPUpdateError,
)
from insight.helpers import COLOG
from insight.model.arm64_state import ARM64State
from insight.model.packets import AddressPacket, AtomPacket, ExceptionPacket, Packet, STMDataPacket

logger = logging.getLogger("insight")


class STMFIFO:
    def __init__(self) -> None:
        self.queue: deque = deque()

    def enqueue(self, item: int) -> None:
        self.queue.append(item)

    def dequeue(self) -> int:
        if self.queue:
            value: int = self.queue.popleft()
            return value
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

    def __init__(self, elf_info: ELFInfo) -> None:
        self.state: ARM64State = ARM64State()
        self.config: dict[str, str] = {
            "ari": "or",
            "add": "or",
            "sub": "or",
            "sto": "or",
            "loa": "or",
            "bra": "or",
            "ret": "or",
        }

        self.stm_addresses: STMFIFO = STMFIFO()
        self.annot_parser: AnnotationParser = AnnotationParser()
        self.first_stm_packet: bool = True
        self.elf_info: ELFInfo = elf_info
        self.annotation_dict: AnnotationDict = elf_info.annotation_dict
        self.symbol_dict: SymbolDict | None = elf_info.symbol_dict

    # Packet processing
    # \____________________

    def interpret_packet_trace(self, packet_trace: list[Packet], start_address: int) -> None:
        current_address: int = start_address
        current_offset: int = 0
        bb_offset: int = 0

        # Execute annotations one by one
        for packet in packet_trace:
            if isinstance(packet, AddressPacket):
                current_address = packet.address
                current_offset = current_address - start_address

            elif isinstance(packet, ExceptionPacket):
                bb_offset = current_offset

            elif isinstance(packet, AtomPacket):
                bb_offset = current_offset
                self.process_atom_packet(packet, bb_offset)

            elif isinstance(packet, STMDataPacket):
                self.process_data_packet(packet)

    def process_atom_packet(self, packet: AtomPacket, bb_offset: int) -> None:
        falled_through: bool = False
        falled_through_msg: str = "(falling through, N atom)"

        for atom_element in packet.elements:
            # If the address is not present in the annotation dictionary, the info
            # should come from a fucntion outside of the annotated binary (libraries, etc.)
            function_name: str = (
                self.symbol_dict.function_for_address(bb_offset) if self.symbol_dict else "no symbol"
            )
            if bb_offset not in self.annotation_dict:
                logger.warning(
                    f"{COLOG['warning']} Packet {packet.packet_info.index} - "
                    f"Atom element reached but no annotations were found at address "
                    f"{hex(bb_offset)} ({function_name})"
                )
                continue

            # FIXME: For now, the attribute hbng_no_instrument still produces the annotations as
            # if they were deactivated, most labels would not be emitted...
            if function_name == "_start_c":
                logger.warning(
                    f"{COLOG['warning']} Packet {packet.packet_info.index} - _start_c function ignored"
                )
                continue

            # Executing current block assignments
            bb_assignments: list[Assignment] = self.annotation_dict[bb_offset].assignments

            logger.info(
                f"{COLOG['success']} Packet {packet.packet_info.index} "
                f"{falled_through_msg if falled_through else ''}"
                " - Atom element reached and annotations found at address "
                f"{hex(bb_offset)} ({function_name})"
            )
            self.interpret_block(bb_assignments)
            self.check_svc(bb_offset)
            falled_through = False

            # If it is not ending with an END annotation, fall through the next annotations
            bb_offset = self.interpret_blocks_until_end(bb_offset, packet.packet_info.index)

            # If the atom element is E, branch broadcasting SHOULD be enabled and
            # produce another address packet
            if atom_element == "N":
                falled_through = True
                bb_offset = self.annotation_dict.next_key(bb_offset)
                # If it is not ending with an END annotation, fall through the next annotations
                bb_offset = self.interpret_blocks_until_end(bb_offset, packet.packet_info.index)

    def process_exception_packet(self, packet: ExceptionPacket, bb_offset: int) -> None:
        function_name: str = (
            self.symbol_dict.function_for_address(bb_offset) if self.symbol_dict else "no symbol"
        )

        if function_name == "preload_stm_region":
            logger.warning(
                f"{COLOG['warning']} Packet {packet.packet_info.index} - preload_stm_region svc ignored"
            )
            return
        bb_assignments = self.annotation_dict[bb_offset].assignments
        logger.info(
            f"{COLOG['success']} Packet {packet.packet_info.index} "
            " - Exception packet reached (svc) and annotations found at address "
            f"{hex(bb_offset)} ({function_name})"
        )
        self.interpret_block(bb_assignments)
        self.check_svc(bb_offset)

    def process_data_packet(self, packet: STMDataPacket) -> None:
        if self.first_stm_packet:
            self.state.stack_value = packet.data_value
            logger.info(
                f"{COLOG['success']} Packet {packet.packet_info.index} - "
                f"STM data packet, initial stack value {hex(packet.data_value)}"
            )
            self.first_stm_packet = False
        else:
            self.stm_addresses.enqueue(packet.data_value)
            logger.info(
                f"{COLOG['success']} Packet {packet.packet_info.index} - "
                f"STM data packet, pushing value {hex(packet.data_value)}"
            )

    # Annotation Interpretation
    # \___________________________

    def interpret_blocks_until_end(self, bb_offset: int, packet_index: int) -> int:
        while not self.annotation_dict[bb_offset].ends_with_end:
            bb_offset = self.annotation_dict.next_key(bb_offset)
            bb_assignments = self.annotation_dict[bb_offset].assignments
            logger.info(
                f"{COLOG['success']} Packet {packet_index} (falling through, no end)"
                " - Atom element reached and annotations found at address "
                f"{hex(bb_offset)} ({self.annotation_dict[bb_offset].function_name})"
            )
            self.interpret_block(bb_assignments)
            self.check_svc(bb_offset)
        return bb_offset

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

            # Check if tag rules have not been broken
            self.check_tag_rules()

    def check_tag_rules(self) -> None:
        try:
            self.state.check_tag_rules()
        except TagCheckingRuleError as e:
            logger.warning(f"{COLOG['failure']} Tag rule broken, stopping execution: {e}")
            raise

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

    # SVC Capture
    # \___________

    def check_svc(self, bb_offset: int) -> None: ...

    # Tag Access
    # \___________

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
        # Base register, check if it is SP and get its value from the execution state,
        # otherwise get it from the STM fifo
        base_value: int
        if memory_access.base.is_sp():
            base_value = self.state.stack_value
            logger.info(f"{COLOG['success']} \t├ 📚 SP State - Register value of SP ({hex(base_value)})")
        else:
            base_value = self.stm_addresses.dequeue()
            logger.info(
                f"{COLOG['success']} \t├ 💬 STM ({hex(base_value)}) - "
                f"Register value of {memory_access.base.name} needed"
            )
        # Offset
        offset: Immediate | Register | UOp = memory_access.offset
        offset_value: int
        address_value: int
        if isinstance(offset, Immediate):
            imm_offset: Immediate = offset
            offset_value = imm_offset.value
            # Scale offset
            scale_value: int = memory_access.scale
            offset_value = offset_value * scale_value
        elif isinstance(offset, Register):
            offset_value = self.stm_addresses.dequeue()
            logger.info(
                f"{COLOG['success']} \t├ 💬 STM ({hex(offset_value)}) - "
                f"Register value of {offset.name} needed"
            )

            # Optional shift
            shift_op: str | None = memory_access.shift_op
            shift_val: int = memory_access.shift_val
            if shift_op:
                offset_value = self.process_shift_operator(
                    offset_value=offset_value, shift_value=shift_val, shift_op=shift_op
                )
        elif isinstance(offset, UOp):
            offset_value = 0
        # Compute address
        address_value = base_value + offset_value
        return address_value

    def process_shift_operator(self, offset_value: int, shift_value: int, shift_op: str) -> int:
        match shift_op:
            case "uxtx":
                # Zero-extend 64-bit value, then shift
                offset_value = (offset_value & 0xFFFFFFFFFFFFFFFF) << shift_value
                offset_value &= 0xFFFFFFFFFFFFFFFF  # Ensure 64-bit masking

            case "uxtw":
                # Zero-extend 32-bit value, then shift
                offset_value = (offset_value & 0xFFFFFFFF) << shift_value
                offset_value &= 0xFFFFFFFFFFFFFFFF  # Still constrained to 64-bit

            case "sxtx":
                # Sign-extend from 64 bits (already 64-bit), then shift
                offset_value = (
                    offset_value if offset_value < (1 << 63) else offset_value - (1 << 64)
                ) << shift_value
                offset_value &= 0xFFFFFFFFFFFFFFFF  # Truncate to 64-bit

            case "sxtw":
                # Sign-extend from 32 bits, then shift
                offset_value = offset_value & 0xFFFFFFFF
                if offset_value & 0x80000000:
                    offset_value |= ~0xFFFFFFFF  # Sign-extend
                offset_value = offset_value << shift_value
                offset_value &= 0xFFFFFFFFFFFFFFFF  # Final 64-bit mask
        return offset_value
