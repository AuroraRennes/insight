import pytest

from insight.cli import main


@pytest.mark.parametrize(("name", "code"), [("good", 0), ("bad", 1), ("old", 1)])
def test_command_exit_code(name, code, capsys, annotation_elfs):
    assert main(["check", str(annotation_elfs / f"{name}.elf")]) == code
    assert f"{name}.elf: " in capsys.readouterr().out


def test_command_limits_the_printed_issues(capsys, annotation_elfs):
    main(["check", "--max-issues", "2", str(annotation_elfs / "bad.elf")])
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 4
    assert out[2] == "... 3 more"
    assert out[3].endswith("5 blocks, 8 instructions, 2 sends, 5 issues")
