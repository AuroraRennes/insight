from pathlib import Path

import pytest

from insight.cli import main

ELFS = Path(__file__).parent.parent / "data" / "annotations" / "elf"


@pytest.mark.parametrize(("name", "code"), [("good", 0), ("bad", 1), ("old", 1)])
def test_command_exit_code(name, code, capsys):
    assert main(["check", str(ELFS / f"{name}.elf")]) == code
    assert f"{name}.elf: " in capsys.readouterr().out


def test_command_limits_the_printed_issues(capsys):
    main(["check", "--max-issues", "2", str(ELFS / "bad.elf")])
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 4
    assert out[2] == "... 4 more"
    assert out[3].endswith("5 blocks, 7 instructions, 0 sends, 6 issues")
