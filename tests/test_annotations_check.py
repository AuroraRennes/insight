import pytest
from elftools.elf.elffile import ELFFile

from insight.annotations.check import Report, check_elf


@pytest.fixture
def report_of(annotation_elfs):
    def report(name: str) -> Report:
        with (annotation_elfs / f"{name}.elf").open("rb") as file:
            return check_elf(ELFFile(file))

    return report


def test_good(report_of):
    report = report_of("good")
    assert report.ok
    assert (report.blocks, report.groups, report.sends) == (3, 11, 4)


def test_bad_reports_every_block(report_of):
    report = report_of("bad")
    messages = [(issue.offset, issue.message.split(":")[0]) for issue in report.issues]
    assert messages == [
        (0, "str x0, [x18] makes send X0, the group lists no send"),
        (4, "<X0>"),
        (0, "<X1>"),
        (None, "line 2"),
        (0, "mov x18, x0"),
        (0, "line 1"),
    ]
    assert len({issue.address for issue in report.issues}) == 5


def test_old_format_stops_the_check(report_of):
    report = report_of("old")
    assert report.old_format
    assert not report.ok
    assert "rebuild with hbng-23.x" in report.issues[0].message


def test_not_an_hbng_executable(annotation_elfs):
    with (annotation_elfs / "good.elf").open("rb") as file:
        elf = ELFFile(file)
        elf.get_section_by_name = lambda name: None  # type: ignore[method-assign]
        with pytest.raises(ValueError, match="not built with the HBNG"):
            check_elf(elf)
