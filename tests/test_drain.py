import pytest

from insight.annotations.framing import Entry
from insight.cli import main
from insight.drain.drain import Drain, Table
from insight.drain.events import OUTSIDE, Event, Kind

# The program of the post-link step's test: _start (untracked) branches to f, two instructions
# running into loop (3 instructions ending in b.lt, run 10 times), then call (bl g, one send),
# g (ret), noreturn (bl stop) and stop (b stop).
F, LOOP, CALL, NORETURN, G, STOP = 0x1000C, 0x1001C, 0x10028, 0x1002C, 0x10034, 0x10038
ENTRIES = [
    Entry(F, 0, 2, ()),
    Entry(LOOP, 0, 3, (), waypoint=True),
    Entry(CALL, 0, 1, (0,), waypoint=True),
    Entry(NORETURN, 0, 1, (), waypoint=True),
    Entry(G, 0, 1, (), waypoint=True),
    Entry(STOP, 0, 1, (), waypoint=True),
]


def table(entries=ENTRIES, skips=((0x10000, 0x10008),)) -> Table:
    return Table(list(entries), [(entry.address, k) for k, entry in enumerate(entries)], list(skips))


def branch(atoms: str, target: int) -> Event:
    return Event.atoms(list(atoms), target)


def at(address: int) -> Event:
    return Event(Kind.BRANCH, 0, 0, address)


def walk(*events: Event, entries=ENTRIES) -> Drain:
    drain = Drain(table(entries))
    drain.run(events)
    return drain


def test_the_example_program():
    drain = walk(
        at(0x10000),
        branch("E", F),
        *[branch("E", LOOP)] * 9,
        branch("NE", G),
        branch("E", NORETURN),
        branch("E", STOP),
        branch("E", STOP),
    )
    assert drain.visits == [F, *[LOOP] * 10, CALL, G, NORETURN, STOP, STOP]
    assert drain.sends == [CALL]
    assert drain.reports == []
    assert drain.stats["lookups"] == 15
    assert drain.stats["atoms untracked"] == 1
    assert drain.stats["hits 16"] == 9  # the loop's eight later targets, and stop's second


# A block of 4 instructions with sends at 0 and 2, an svc at 1, then a block ending in a branch.
SYSCALL = [
    Entry(0x1000, 0, 4, (0, 2)),
    Entry(0x1010, 0, 1, (), waypoint=True),
    Entry(0x2000, 0, 1, (), waypoint=True),
]


def test_an_exception_splits_the_sends_of_its_block():
    drain = walk(at(0x1000), Event(Kind.EXCEPTION, 2, 0, 0x1008), entries=SYSCALL)
    assert drain.sends == [0x1000]
    drain.run([at(0x1008), branch("E", 0x2000)])
    assert drain.visits == [0x1000, 0x1010, 0x2000]
    assert drain.sends == [0x1000, 0x1008]
    assert drain.reports == []


def test_an_exception_at_the_end_of_a_block_does_not_enter_the_next():
    drain = walk(at(0x1000), Event(Kind.EXCEPTION, 2, 0, 0x1010), entries=SYSCALL)
    assert drain.visits == [0x1000]
    drain.run([at(0x1010), branch("E", 0x2000)])
    assert drain.visits == [0x1000, 0x1010, 0x2000]


def test_a_signal_handler_returns_where_the_signal_interrupted():
    entries = [*SYSCALL, Entry(0x3000, 0, 2, (1,), waypoint=True)]
    drain = Drain(table(entries, skips=[(0x4000, 0x4008)]))
    drain.run(
        [
            at(0x1000),
            Event(Kind.EXCEPTION, 2, 0, 0x1008),
            at(0x3000),  # the handler, not where the syscall returns
            branch("E", 0x4000),  # its ret, to the untracked restorer
            Event(Kind.EXCEPTION, 2, 0, 0x4008),  # rt_sigreturn
            at(0x1008),
            branch("E", 0x2000),
        ]
    )
    assert drain.visits == [0x1000, 0x3000, 0x1010, 0x2000]
    assert drain.sends == [0x1000, 0x3004, 0x1008]
    assert drain.stats["signals"] == 1
    assert drain.reports == []


@pytest.mark.parametrize(
    ("event", "report"),
    [
        (branch("E", LOOP + 4), "a branch to 0x10020, neither the start of a block nor untracked code"),
        (branch("E", OUTSIDE), "a branch leaves the traced code"),
        (
            Event(Kind.EXCEPTION, 2, 0, CALL),
            "an exception at 0x10028, past the block at 0x1001c without an atom",
        ),
    ],
)
def test_what_the_drain_reports(event, report):
    assert walk(at(F), event).reports == [report]


def test_running_off_the_table():
    assert walk(at(STOP), Event.atoms(["N"])).reports == ["execution continues after the last entry, 0x10038"]


def test_an_overflow_loses_the_position_until_a_block_starts():
    drain = walk(at(F), Event(Kind.OVERFLOW), branch("NNE", LOOP), branch("E", G))
    assert drain.visits == [F, LOOP, G]
    assert drain.stats["atoms untracked"] == 3


@pytest.mark.parametrize("name", ["tiny", "forms", "signal", "fault"])
def test_the_walk_of_traced_programs_matches_qemu(name, traced, capsys):
    assert main(["drain", str(traced / f"{name}.elf"), str(traced / f"{name}.trace")]) == 0
    out = capsys.readouterr().out
    assert "blocks: the walk matches" in out
    assert "sends: the walk matches" in out
