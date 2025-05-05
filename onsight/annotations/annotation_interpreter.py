from onsight.annotations.annotation_decoder import AnnotationDict
from onsight.packets import AddressPacket, AtomPacket, Packet

# Data classes to represent a minimal AST


class AnnotationInterpreter:
    def __init__(self) -> None:
        ...
        # state: ARM64State = ARM64State()

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

            if isinstance(packet, AtomPacket):
                bb_offset = current_offset

                for atom_element in packet.elements:
                    bb_annotations: list[str] = annotation_dict[bb_offset].annotations
                    self.interpret_block(bb_annotations)
                    # If the atom element is E, branch broadcasting SHOULD be enabled and
                    # produce another address packet
                    if atom_element == "N":
                        bb_offset = annotation_dict.next_key(bb_offset)

    def interpret_block(self, annotations: list[str]) -> None: ...
