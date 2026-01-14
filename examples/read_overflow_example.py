import contextlib

from insight.annotations.annotation_interpreter import AnnotationInterpreter
from insight.elf.elf_decoder import ELFDecoder, ELFInfo
from insight.model.packet_parser import PacketParser
from insight.model.packets import Packet


class ROAnnotationInterpreter(AnnotationInterpreter):
    def __init__(self, elf_info: ELFInfo) -> None:
        super().__init__(elf_info=elf_info)

    def check_svc(self, bb_offset: int) -> None:
        function_name: str = (
            self.symbol_dict.function_for_address(bb_offset) if self.symbol_dict else "no symbol"
        )

        # When reaching the next svc instruction, tag memory related to the x1 value
        if function_name == "read":
            x1_value: int = self.state.stack_value + 8
            self.state.memory_write(x1_value, 32, 1)


if __name__ == "__main__":
    from insight.exceptions import TagCheckingRuleError

    BIN_NAME = "read_overflow"
    ELF_FILE_PATH = "examples/read_overflow/" + BIN_NAME
    TRACE_PATH = "examples/read_overflow/" + BIN_NAME + ".opencsd"

    # Decode elf file and sections
    elf_decoder: ELFDecoder = ELFDecoder()
    elf_info: ELFInfo = elf_decoder.decode_elf_file(ELF_FILE_PATH)

    # Parse packets into objects
    packet_parser: PacketParser = PacketParser()
    packets: list[Packet] = packet_parser.parse_opencsd_file(TRACE_PATH)
    packets_dict: dict[int, list[Packet]] = {}
    # Parse packets into objects
    for packet in packets:
        packets_dict.setdefault(packet.packet_info.sid, []).append(packet)

    # Interpret both
    interpreter: AnnotationInterpreter = AnnotationInterpreter(elf_info)
    interpreter.interpret_packet_trace(packets_dict[0x20], 0)  # STM

    # Interpret Core 0 packets
    with contextlib.suppress(TagCheckingRuleError):
        interpreter.interpret_packet_trace(packets_dict[0x10], 0)  # Core 0
