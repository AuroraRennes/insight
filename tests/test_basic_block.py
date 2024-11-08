import pytest

from onsight.basic_block import BasicBlock

# Basic block used for the fixture:
# 00000000000007f8 <main+0x20>:
# 7f8:	b9801fe0 	ldrsw	x0, [sp, #28]
# 7fc:	d37ef400 	lsl	x0, x0, #2
# 800:	910043e1 	add	x1, sp, #0x10
# 804:	b8606820 	ldr	w0, [x1, x0]
# 808:	7100281f 	cmp	w0, #0xa
# 80c:	540000ed 	b.le	828 <main+0x50>
# NOT THIS ONE
# ------------------
# THIS ONE
# 810:	b9801fe0 	ldrsw	x0, [sp, #28]
# 814:	d37ef400 	lsl	x0, x0, #2
# 818:	910023e1 	add	x1, sp, #0x8
# 81c:	52800022 	mov	w2, #0x1
# 820:	b8206822 	str	w2, [x1, x0]
# 824:	14000005 	b	838 <main+0x60>

BB_ADDRESS = 0x810
MAIN_ADDRESS = 0x7D8
BB_INSTRUCTIONS = [
    b"\xe0\x1f\x80\xb9",
    b"\x00\xf4\x7e\xd3",
    b"\xe1\x23\x00\x91",
    b"\x22\x00\x80\x52",
    b"\x22\x68\x20\xb8",
    b"\x05\x00\x00\x14",
]


@pytest.fixture
def basic_block_setup():
    address: int = BB_ADDRESS
    function_name: str = "main"
    function_address: int = MAIN_ADDRESS
    instructions = BB_INSTRUCTIONS
    return BasicBlock(
        address=address, function_address=function_address, function_name=function_name, instructions=instructions
    )


def test_initialization(basic_block_setup):
    bb = basic_block_setup
    assert bb.address == BB_ADDRESS
    assert bb.function_name == "main"
    assert bb.function_address == MAIN_ADDRESS
    assert bb.ending_instruction == b"\x05\x00\x00\x14"
    assert bb.size == len(BB_INSTRUCTIONS) * 4
