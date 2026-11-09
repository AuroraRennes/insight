import pytest

from insight.annotations.framing import (
    FramingError,
    OldFormatError,
    block_table,
    block_texts,
    read_block,
)
from insight.dsl.locations import Reg
from tests.annotation_fixtures import fixture_blocks, fixture_files


def test_fixtures_exist():
    assert len(fixture_files()) == 20


@pytest.mark.parametrize("path", fixture_files(), ids=lambda path: path.stem)
def test_fixtures_frame(path):
    blocks = fixture_blocks(path)
    assert blocks
    for block in blocks.values():
        assert [group.offset for group in block.groups] == list(range(0, block.size, 4))


def test_groups_and_empty_groups():
    block = read_block("@0\nsend X0\n@4\nX0 <- M[<X0> .. +8]\n@8\nEND\n", 0x400)
    assert block.size == 12
    assert block.groups[0].form.sends == (Reg(0),)
    assert not block.groups[2].form.tags


def test_comments_and_blank_lines():
    block = read_block("@0   # str x0, [x18]\nsend X0\n\n@4   # ret\nEND\n", 0x400)
    assert len(block.groups) == 2


def test_old_format_is_rejected():
    with pytest.raises(OldFormatError, match=r"rebuild with hbng-23\.x"):
        read_block("X0 <- [<X0> + 8*Imm(0)]_64\nEND\n", 0x400)
    with pytest.raises(OldFormatError):
        read_block("END\n", 0x400)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("@4\nEND\n", "first group is @4"),
        ("@0\n@8\nEND\n", "@8 where @4 was expected"),
        ("@0\n@0\nEND\n", "@0 where @4 was expected"),
        ("@0\nX0 <- 0\n", "no END"),
        ("@0\nEND\nX0 <- 0\n", "after END"),
        ("@0\nX0 <- [<X0> + Imm(0)]_64\nEND\n", r"block 0x400 @0: line 1"),
    ],
)
def test_framing_errors(text, message):
    with pytest.raises(FramingError, match=message):
        read_block(text, 0x400)


def test_block_table_and_texts():
    table = block_table(bytes.fromhex("0010000000000000 0020000000000000 0410000000000000 0820000000000000"))
    assert table == [(0x1000, 0x2000), (0x1004, 0x2008)]
    annotations = b"@0\nEND\n\n@0\nEND\n"
    texts = block_texts(table, annotations, 0x2000)
    assert texts == [(0x1000, "@0\nEND\n\n"), (0x1004, "@0\nEND\n")]


def test_block_text_outside_the_section():
    with pytest.raises(FramingError, match="outside"):
        block_texts([(0x1000, 0x3000)], b"@0\nEND\n", 0x2000)
