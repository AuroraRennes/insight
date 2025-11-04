from typing import TYPE_CHECKING

import pytest

from insight.decoder.decoder import STMDecoder
from insight.model.packets import STMDataPacket

if TYPE_CHECKING:
    from insight.model.packets import STMPacket

STM_HEADERS: dict[str, int] = {
    # 1 nibble
    "NULL": 0x0,
    "M8": 0x1,
    "MERR": 0x2,
    "C8": 0x3,
    "D8": 0x4,
    "D16": 0x5,
    "D32": 0x6,
    "D64": 0x7,
    "D8MTS": 0x8,
    "D16MTS": 0x9,
    "D32MTS": 0xA,
    "D64MTS": 0xB,
    "D4": 0xC,
    "D4MTS": 0xD,
    "FLAG_TS": 0xE,
    # 2 nibbles
    "GERR": 0xF2,
    "C16": 0xF3,
    "D8TS": 0xF4,
    "D16TS": 0xF5,
    "D32TS": 0xF6,
    "D64TS": 0xF7,
    "D8M": 0xF8,
    "D16M": 0xF9,
    "D32M": 0xFA,
    "D64M": 0xFB,
    "D4TS": 0xFC,
    "D4M": 0xFD,
    "FLAG": 0xFE,
    # 3 nibbles
    "VERSION": 0xF00,
    "TRIG": 0xF06,
    "TRIG_TS": 0xF07,
    "FREQ": 0xF08,
    # 22 nibbles
    "ASYNC": 0xFFFFFFFFFFFFFFFFFFFFF0,
}


def make_stm_trace(header: int, payload: int, total_len: int = 20) -> bytes:
    # Convert header and payload to hex strings
    header_hex = f"{header:X}"
    payload_hex = f"{payload:X}"

    # Combine as hex string
    hex_str = header_hex + payload_hex

    # Ensure even length for bytes.fromhex
    if len(hex_str) % 2 != 0:
        hex_str = hex_str + "0"

    # Swap nibbles in each byte
    swapped: str = "".join(hex_str[i + 1] + hex_str[i] for i in range(0, len(hex_str), 2))

    # Convert to bytes
    trace = bytes.fromhex(swapped)

    # Pad to total_len
    if len(trace) < total_len:
        trace += bytes(total_len - len(trace))

    return trace


# Check size and name
@pytest.mark.parametrize(
    ("trace_data", "size", "name"),
    [
        (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x0f", 22, "STM - Async"),
        (make_stm_trace(STM_HEADERS["ASYNC"], 0x0), 22, "STM - Async"),
        (b"\x00", 1, "STM - Null"),
        (make_stm_trace(STM_HEADERS["NULL"], 0x0), 1, "STM - Null"),
        (b"\x41\x08", 3, "STM - Master"),
        (make_stm_trace(STM_HEADERS["M8"], 0x0), 3, "STM - Master"),
        (b"\x0f\x30", 4, "STM - Version"),
        (b"\xd7\xae\xbd\xee\xdf\xae\xbd\xee\x0f", 17, "STM - Data 64"),
    ],
)
def test_packet_decode(trace_data, size, name):
    decoder: STMDecoder = STMDecoder(trace_data=trace_data, sid=0x20)
    packet: STMPacket = decoder.decode_packet()

    assert packet.packet_info.size == size
    assert packet.name == name


@pytest.mark.parametrize(
    ("trace_data", "data_value"),
    [
        (b"\xdc\x00\x00\x00\x00\x00\x00\x00\x00\x00", 0xD),  # D4
        (make_stm_trace(STM_HEADERS["D4"], 0xD), 0xD),  # D4
        (make_stm_trace(STM_HEADERS["D4M"], 0xD), 0xD),  # D4M
        (make_stm_trace(STM_HEADERS["D4TS"], 0xD1), 0xD),  # D4TS
        (make_stm_trace(STM_HEADERS["D4MTS"], 0xD1), 0xD),  # D4MTS
        (b"\xd4\x0e\x00\x00\x00\x00\x00\x00\x00\x00", 0xDE),  # D8
        (make_stm_trace(STM_HEADERS["D8"], 0xDE), 0xDE),  # D8
        (make_stm_trace(STM_HEADERS["D8M"], 0xDE), 0xDE),  # D8M
        (make_stm_trace(STM_HEADERS["D8TS"], 0xDE1), 0xDE),  # D8TS
        (make_stm_trace(STM_HEADERS["D8MTS"], 0xDE1), 0xDE),  # D8MTS
        (b"\xd5\xae\x0d\x00\x00\x00\x00\x00\x00\x00", 0xDEAD),  # D16
        (make_stm_trace(STM_HEADERS["D16"], 0xDEAD), 0xDEAD),  # D16
        (make_stm_trace(STM_HEADERS["D16M"], 0xDEAD), 0xDEAD),  # D16M
        (make_stm_trace(STM_HEADERS["D16TS"], 0xDEAD), 0xDEAD),  # D16TS
        (make_stm_trace(STM_HEADERS["D16MTS"], 0xDEAD), 0xDEAD),  # D16MTS
        (b"\xd6\xae\xbd\xee\x0f\x00\x00\x00\x00\x00", 0xDEADBEEF),  # D32
        (make_stm_trace(STM_HEADERS["D32"], 0xDEADBEEF), 0xDEADBEEF),  # D32
        (make_stm_trace(STM_HEADERS["D32M"], 0xDEADBEEF), 0xDEADBEEF),  # D32M
        (make_stm_trace(STM_HEADERS["D32TS"], 0xDEADBEEF), 0xDEADBEEF),  # D32TS
        (make_stm_trace(STM_HEADERS["D32MTS"], 0xDEADBEEF), 0xDEADBEEF),  # D32MTS
        (b"\xd7\xae\xbd\xee\xdf\xae\xbd\xee\x0f\x00", 0xDEADBEEFDEADBEEF),  # D64
        (make_stm_trace(STM_HEADERS["D64"], 0xDEADBEEFDEADBEEF), 0xDEADBEEFDEADBEEF),  # D64
        (b"\xbf\xed\xda\xeb\xfe\xed\xda\xeb\xfe\x00", 0xDEADBEEFDEADBEEF),  # D64M
        (make_stm_trace(STM_HEADERS["D64M"], 0xDEADBEEFDEADBEEF), 0xDEADBEEFDEADBEEF),  # D64M
        (b"\x7f\xed\xda\xeb\xfe\xed\xda\xeb\xfe\x01", 0xDEADBEEFDEADBEEF),  # D64TS
        (make_stm_trace(STM_HEADERS["D64TS"], 0xDEADBEEFDEADBEEF1), 0xDEADBEEFDEADBEEF),  # D64TS
        (b"\xdb\xae\xbd\xee\xdf\xae\xbd\xee\x0f\x00", 0xDEADBEEFDEADBEEF),  # D64MTS
        (make_stm_trace(STM_HEADERS["D64MTS"], 0xDEADBEEFDEADBEEF1), 0xDEADBEEFDEADBEEF),  # D64MTS
    ],
)
def test_data_value(trace_data, data_value):
    decoder: STMDecoder = STMDecoder(trace_data=trace_data, sid=0x20)
    packet: STMPacket = decoder.decode_packet()

    assert isinstance(packet, STMDataPacket)
    assert packet.data_value == data_value
