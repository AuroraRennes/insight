"""Reading the annotation fixtures (data/annotations): blocks of section text under their labels."""

import re
from pathlib import Path

from insight.annotations.framing import Block, read_block

FIXTURES = Path(__file__).parent.parent / "data" / "annotations"
LABEL_RE = re.compile(r"(HBNG_\S+)_annot:")


def fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.annot"))


def fixture_texts(path: Path) -> dict[str, str]:
    """Each block's text, by label, as it sits in the section (the label is not part of it)."""
    texts: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in path.read_text().splitlines():
        if match := LABEL_RE.fullmatch(line.strip()):
            current = texts.setdefault(match.group(1), [])
        elif current is not None:
            current.append(line)
    return {label: "\n".join(lines) + "\n" for label, lines in texts.items()}


def fixture_blocks(path: Path) -> dict[str, Block]:
    """Each block read by the framing, at a made-up address."""
    return {
        label: read_block(text, 0x1000 * (index + 1))
        for index, (label, text) in enumerate(fixture_texts(path).items())
    }
