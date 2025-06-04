import pytest

from insight.basic_block import BasicBlock
from insight.execution_trace import ExecutionTrace

MAIN_ADDRESS = 0x100

# Basic block 1
BB1_ADDRESS = 0x100
BB1_INSTRUCTIONS = [
    b"\x20\x00\x80\xd2",  # mov x0, #1
    b"\x1f\x00\x00\xf1",  # cmp x0, #0
    b"\x00\x01\x00\x54",  # b.eq #0x8
]

# Basic block 2
BB2_ADDRESS = 0x10C
BB2_INSTRUCTIONS = [
    b"\x21\x00\x80\xd2",  # mov x1, #1
    b"\x0f\x00\x00\x14",  # b #0x3c
]

# Basic block 3
BB3_ADDRESS = 0x150
BB3_INSTRUCTIONS = [
    b"\xc0\x03\x5f\xd6",  # ret
]


@pytest.fixture
def basic_block_setup():
    basic_blocks: dict[int, BasicBlock] = {
        BB1_ADDRESS: BasicBlock(
            address=BB1_ADDRESS,
            function_address=MAIN_ADDRESS,
            function_name="main",
            instructions=BB1_INSTRUCTIONS,
        ),
        BB2_ADDRESS: BasicBlock(
            address=BB2_ADDRESS,
            function_address=MAIN_ADDRESS,
            function_name="main",
            instructions=BB2_INSTRUCTIONS,
        ),
        BB3_ADDRESS: BasicBlock(
            address=BB3_ADDRESS,
            function_address=MAIN_ADDRESS,
            function_name="main",
            instructions=BB3_INSTRUCTIONS,
        ),
    }
    return basic_blocks


def test_check_taken_not_taken(basic_block_setup):
    # Scenario [BB1] -> [BB2] -> [BB3]
    address_trace: list[int] = [BB1_ADDRESS, BB2_ADDRESS, BB3_ADDRESS]
    exec_trace: ExecutionTrace = ExecutionTrace(address_trace=address_trace, basic_blocks=basic_block_setup)
    assert not exec_trace.trace[0].taken  # addr bb2 follows end of bb1
    assert exec_trace.trace[1].taken  # addr bb3 does not follow end of bb2
    assert exec_trace.trace[2].taken  # last one is always taken
