import pytest

from insight.annotations.framing import (
    Entry,
    FramingError,
    OldFormatError,
    block_table,
    block_texts,
    format_version,
    read_block,
    table_issues,
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
        ("@0\n@0\nEND\n", "group @0 after @0"),
        ("@0\nX0 <- 0\n", "no END"),
        ("@0\nEND\nX0 <- 0\n", "after END"),
        ("@0\nX0 <- [<X0> + Imm(0)]_64\nEND\n", r"block 0x400 @0: line 1"),
    ],
)
def test_framing_errors(text, message):
    with pytest.raises(FramingError, match=message):
        read_block(text, 0x400)


TABLE = bytes.fromhex(
    "00100000 00200000 0100 0000"  # one instruction, no send, no waypoint
    "04100000 08200000 0280 0200 0100 0100"  # an stp send, ending in a waypoint
)


def test_block_table_and_texts():
    table = block_table(TABLE)
    assert table == [Entry(0x1000, 0x2000, 1, ()), Entry(0x1004, 0x2008, 2, (1, 1), waypoint=True)]
    annotations = b"@0\nEND\n\n@0\nEND\n"
    texts = block_texts(table, annotations, 0x2000)
    assert [(entry.address, text) for entry, text in texts] == [
        (0x1000, "@0\nEND\n\n"),
        (0x1004, "@0\nEND\n"),
    ]


def test_table_and_its_index():
    index = bytes.fromhex("00100000 00000000 04100000 0c000000")
    assert table_issues(TABLE, index) == []
    assert table_issues(TABLE, None) == [(0, "no .hbngidx")]
    assert table_issues(TABLE, index[:8]) == [(0, ".hbngidx of 8 bytes for 2 entries")]
    wrong = bytes.fromhex("00100000 00000000 04100000 10000000")
    assert table_issues(TABLE, wrong) == [
        (0x1004, ".hbngidx record 1 is (0x1004, 16), the entry at 12 is this block")
    ]
    unsorted = TABLE[12:] + TABLE[:12]
    assert table_issues(unsorted, None)[0] == (0x1000, "entry after 0x1004: not sorted, or overlapping")


class _Section:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def data(self) -> bytes:
        return self._data


class _Elf:
    def __init__(self, info: bytes | None) -> None:
        self.info = info

    def get_section_by_name(self, name: str) -> _Section | None:
        return _Section(self.info) if name == ".hbnginfo" and self.info is not None else None


def test_format_version():
    format_version(_Elf(b"\x01\x00"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"no \.hbnginfo: an old table"):
        format_version(_Elf(None))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="version 2, InSight reads version 1"):
        format_version(_Elf(b"\x02\x00"))  # type: ignore[arg-type]


def test_old_block_table():
    # Two 16-byte entries: the second's address read as an instruction count.
    with pytest.raises(ValueError, match="an old table"):
        block_table(bytes.fromhex("0010400000000000 0020400000000000 0410400000000000 0820400000000000"))


def test_block_text_outside_the_section():
    with pytest.raises(FramingError, match="outside"):
        block_texts([Entry(0x1000, 0x3000, 1, ())], b"@0\nEND\n", 0x2000)


def test_block_forms_cover_their_instructions():
    block = read_block("@0\nsend X1\n@12\nEND\n", 0x400, Entry(0x400, 0, 4, (2,)))
    groups = [(group.offset, group.count, group.send_at) for group in block.groups]
    assert groups == [(0, 3, (8,)), (12, 1, ())]
    assert block.size == 16
    assert block.block_forms


def test_sends_must_agree_with_the_block_table():
    with pytest.raises(FramingError, match="1 send lines, the block table lists 0 sends here"):
        read_block("@0\nsend X0\n@4\nEND\n", 0x400, Entry(0x400, 0, 2, (1,)))
