import contextlib

from insight.annotation_interpreter import AnnotationInterpreter
from insight.elf_decoder import ELFInfo
from insight.packets import Packet


class ROAnnotationInterpreter(AnnotationInterpreter):
    def __init__(self, elf_info: ELFInfo) -> None:
        super().__init__(elf_info=elf_info)

    def check_svc(self, bb_offset: int) -> None:
        function_name: str = (
            self.symbol_dict.function_for_address(bb_offset) if self.symbol_dict else "no symbol"
        )

        # When reaching the next svc instruction, tag memory related to the x1 value
        if function_name == "__syscall_cp_c":
            x1_value: int = self.state.stack_value + 8
            self.state.memory_write(x1_value, 32, 1)


if __name__ == "__main__":
    from insight.elf_decoder import ELFDecoder
    from insight.exceptions import TagCheckingRuleError
    from insight.parsers.packet_parser import PacketParser

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
    for packet in packets:
        cpu = packet.packet_info.cpu_nb
        if cpu in {0, 1, 2, 3, 10}:
            packets_dict.setdefault(cpu, []).append(packet)

    # Interpret both
    interpreter: ROAnnotationInterpreter = ROAnnotationInterpreter(elf_info)
    interpreter.interpret_packet_trace(packets_dict[10], 0)
    with contextlib.suppress(TagCheckingRuleError):
        interpreter.interpret_packet_trace(packets_dict[0], 0)
