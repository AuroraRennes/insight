import pytest

from insight.decoder.deformatter import Deformatter

# Example taken from CoreSight Architecture Specification, v3.0, D4.2.1 Frame example

@pytest.mark.parametrize(
    ("trace_data", "expected"),
    [
        (bytes([
            0x07, 0xAA, 0xA6, 0xA7, 0x2B, 0xA8, 0x54, 0x52,
            0x52, 0x54, 0x07, 0xCA, 0xC6, 0xC7, 0xC8, 0x1C
        ]),
        {
            0x3: bytearray([0xAA, 0xA6, 0xA7, 0xA8, 0xCA, 0xC6, 0xC7, 0xC8]),
            0x15: bytearray([0x55, 0x52, 0x53, 0x54])
        })
    ]
)
def test_frame_deformatting(trace_data, expected):
    deformatter: Deformatter = Deformatter()
    assert deformatter.deformat(trace_data) == expected
