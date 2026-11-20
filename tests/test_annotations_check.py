from dataclasses import replace

import pytest
from elftools.elf.elffile import ELFFile

from insight.annotations.check import Report, check_elf, waypoint_issue
from insight.annotations.framing import block_table


@pytest.fixture
def report_of(annotation_elfs):
    def report(name: str, *, against_r: bool = False) -> Report:
        with (annotation_elfs / f"{name}.elf").open("rb") as file:
            return check_elf(ELFFile(file), against_r=against_r)

    return report


def test_good(report_of):
    report = report_of("good")
    assert report.ok
    assert (report.blocks, report.groups, report.sends) == (3, 13, 4)
    assert report.page_origins == {"from entry": 1}  # the pair's x16, set before its block


def test_bad_reports_every_block(report_of):
    report = report_of("bad")
    messages = [(issue.offset, issue.message.split(":")[0]) for issue in report.issues]
    assert messages == [
        (0, "ldr x0, [x0]"),
        (4, "str x0, [x16]"),
        (0, "<X1>"),
        (None, "group @8 past the block's 2 instructions"),
        (0, "line 1"),
    ]
    assert "lists send X0 but is not a send" in report.issues[0].message
    assert "x16 does not hold the channel page" in report.issues[1].message
    assert len({issue.address for issue in report.issues}) == 5


def test_old_format_stops_the_check(report_of):
    report = report_of("old")
    assert report.old_format
    assert not report.ok
    assert "an old table? rebuild" in report.issues[0].message


def test_not_an_hbng_executable(annotation_elfs):
    with (annotation_elfs / "good.elf").open("rb") as file:
        elf = ELFFile(file)
        elf.get_section_by_name = lambda name: None  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="not built with the HBNG"):
            check_elf(elf)


def test_waypoint_bits_against_the_instructions(annotation_elfs):
    with (annotation_elfs / "good.elf").open("rb") as file:
        elf = ELFFile(file)
        table = elf.get_section_by_name(".hbngbbt")
        assert table is not None
        entries = block_table(table.data())
        assert all(waypoint_issue(elf, entry) is None for entry in entries)
        load = next(entry for entry in entries if entry.count == 4)  # ends in ret
        issue = waypoint_issue(elf, replace(load, waypoint=False))
        assert issue is not None
        assert issue.message == "no waypoint bit, but the block ends in ret"


def test_index_issues_are_reported(annotation_elfs):
    with (annotation_elfs / "good.elf").open("rb") as file:
        elf = ELFFile(file)
        sections = elf.get_section_by_name
        elf.get_section_by_name = lambda name: None if name == ".hbngidx" else sections(name)  # type: ignore[method-assign]
        report = check_elf(elf)
    assert [issue.message for issue in report.issues] == ["no .hbngidx"]
