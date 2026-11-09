"""The annotation fixtures (data/annotations) parse, group by group.

The fixtures are blocks of the compiler's lit tests and musl's hand-annotated assembly, written in
the DSL as the compiler is to emit it. Until the framing reader exists, blocks are split here on
their label, '@<offset>' and 'END' lines, and every group is parsed as one transfer.
"""

import re
from pathlib import Path

import pytest

from insight.dsl.syntax import parse
from insight.dsl.transfer import Transfer

FIXTURES = Path(__file__).parent.parent / "data" / "annotations"
LABEL_RE = re.compile(r"HBNG_\S+_annot:")
GROUP_RE = re.compile(r"@(0|[1-9][0-9]*)")


def split_blocks(text: str) -> dict[str, list[tuple[int, str]]]:
    """Each block's groups, as (offset, statements text), by label."""
    blocks: dict[str, list[tuple[int, list[str]]]] = {}
    current: list[tuple[int, list[str]]] | None = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if LABEL_RE.fullmatch(line):
            assert current is None, f"line {lineno}: block without END"
            current = blocks.setdefault(line[: -len("_annot:")], [])
        elif line == "END":
            assert current, f"line {lineno}: END outside a block, or a block without groups"
            current = None
        elif match := GROUP_RE.fullmatch(line):
            assert current is not None, f"line {lineno}: group outside a block"
            current.append((int(match.group(1)), []))
        else:
            assert current, f"line {lineno}: statement outside a group"
            current[-1][1].append(line)
    assert current is None, "last block without END"
    return {
        label: [(offset, "\n".join(lines)) for offset, lines in groups] for label, groups in blocks.items()
    }


def fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.annot"))


def test_fixtures_exist():
    assert len(fixture_files()) == 20


@pytest.mark.parametrize("path", fixture_files(), ids=lambda path: path.stem)
def test_every_group_parses(path):
    blocks = split_blocks(path.read_text())
    assert blocks
    for label, groups in blocks.items():
        offsets = [offset for offset, _ in groups]
        assert offsets == list(range(0, 4 * len(groups), 4)), f"{label}: offsets {offsets}"
        for offset, text in groups:
            assert isinstance(parse(text), Transfer), f"{label} @{offset}"


def test_repeated_sends_in_one_group():
    groups = dict(split_blocks((FIXTURES / "hbng-neon-ldst.annot").read_text())["HBNG_ld4"])
    assert len(parse(groups[0]).sends) == 2
    assert len(parse(groups[8]).tags) == 64


def test_splitter_rejects_a_missing_end():
    with pytest.raises(AssertionError, match="without END"):
        split_blocks("HBNG_a_annot:\n@0\nHBNG_b_annot:\n@0\nEND\n")
