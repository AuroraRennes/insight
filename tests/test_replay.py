import os
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from insight.dsl.locations import Mem, Reg, VByte
from insight.dsl.terms import Term
from insight.replay.replay import ReplayError, replay_file
from insight.replay.state import PAGE, Shadow, State
from insight.replay.trace import (
    FORMATS,
    HEADER,
    MAGIC,
    Stream,
    TraceError,
    TraceFile,
    parse_header,
    parse_records,
)

FIXTURES = Path(__file__).parent.parent / "data" / "replay"


@pytest.fixture(scope="session")
def traced(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The fixtures built and traced by flowsight-qemu in a temporary directory; skipped without
    HBNG_BIN (clang), MEASURE (the plugin) and qemu-aarch64."""
    missing = [name for name in ("HBNG_BIN", "MEASURE") if not os.environ.get(name)]
    if not shutil.which("qemu-aarch64"):
        missing.append("qemu-aarch64 on the PATH")
    if missing:
        pytest.skip(f"no flowsight-qemu trace without {', '.join(missing)}")
    out = tmp_path_factory.mktemp("replay")
    subprocess.run([FIXTURES / "build.sh", out], check=True)
    return out


# Trace format
# \_____________


def test_header():
    header = parse_header(HEADER.pack(MAGIC, 1, 0, 0x278000, 0x10000))
    assert (header.chan, header.chan_size) == (0x278000, 0x10000)
    with pytest.raises(TraceError, match="version"):
        parse_header(HEADER.pack(MAGIC, 2, 0, 0, 0))
    with pytest.raises(TraceError, match="not a FlowSight trace"):
        parse_header(HEADER.pack(b"FSTRACX\0", 1, 0, 0, 0))


def test_records_cut_anywhere():
    data = (
        b"B" + (0x1000).to_bytes(8, "little") + (2).to_bytes(4, "little") + b"S" + (7).to_bytes(8, "little")
    )
    chunks = [data[:5], data[5:14], data[14:]]
    assert list(parse_records(chunks)) == [("B", 0x1000, 2), ("S", 7)]


def test_signal_delivery_record():
    fields = (0x401000, 0x402000, 0x7FF0, 0x7FF8)
    data = b"G" + b"".join(v.to_bytes(8, "little") for v in fields)
    assert list(parse_records([data])) == [("G", *fields)]


def test_a_cut_record_is_dropped():
    data = b"S" + (7).to_bytes(8, "little") + b"S" + (8).to_bytes(4, "little")
    assert list(parse_records([data])) == [("S", 7)]


def test_unknown_record_type():
    with pytest.raises(TraceError, match="unknown record type"):
        list(parse_records([b"Z" + bytes(8)]))


def test_send_look_ahead_keeps_the_records_passed():
    stream = Stream([("A", 1, 2, 8, 0), ("S", 5), ("Y", 63)])
    assert stream.next_send() == 5
    assert stream.next() == ("A", 1, 2, 8, 0)
    assert stream.next() == ("Y", 63)
    assert stream.next() is None


def test_plugin_trace(traced: Path):
    """A trace written by flowsight-qemu: the format both sides agree on."""
    with (traced / "tiny.elf").open("rb") as f:
        symtab = ELFFile(f).get_section_by_name(".symtab")
        assert isinstance(symtab, SymbolTableSection)
        (chan,) = (sym["st_value"] for sym in symtab.iter_symbols() if sym.name == "__hbng_chan")
    with TraceFile(traced / "tiny.trace") as trace:
        records = list(trace.records)
        assert (trace.header.chan, trace.header.chan_size) == (chan, 0x10000)
    kinds = "".join(record[0] for record in records)
    # start code (SP then FP sent), the block in two pieces around write, exit_group
    assert kinds == "BRSSBRSAAAAYCBRY"
    sp = records[2][1]
    assert records[3] == ("S", 0)
    assert [r[2:] for r in records if r[0] == "A"] == [
        (records[6][1], 8, 1),
        (records[6][1] + 8, 8, 0),
        (sp - 16, 16, 1),
        (sp - 16, 16, 0),
    ]
    assert [r[1] for r in records if r[0] == "Y"] == [64, 94]


# Tag state
# \___________


def test_clean_memory_allocates_no_page():
    shadow = Shadow()
    shadow.set(0x1000, 0)
    shadow.fill(0x2000, 0x3000, 0)
    assert shadow.pages == {}
    assert shadow.get(0x1000) == 0


def test_fill_and_count_across_pages():
    shadow = Shadow()
    shadow.fill(PAGE - 0x10, 0x20, 1)
    assert len(shadow.pages) == 2
    assert shadow.count(PAGE - 0x40, 0x80) == (0x20, PAGE - 0x10)
    assert shadow.count(0, 0x100) == (0, None)
    shadow.fill(PAGE - 0x10, 0x10, 0)
    assert shadow.count(PAGE - 0x40, 0x80) == (0x10, PAGE)


def test_move_copies_the_tags():
    shadow = Shadow()
    shadow.fill(0x100, 4, 1)
    shadow.move(0x5000, 0xFE, 8)
    assert [shadow.get(0x5000 + i) for i in range(8)] == [0, 0, 1, 1, 1, 1, 0, 0]
    assert shadow.count(0x100, 4) == (4, 0x100)


def test_state_tags_by_location():
    state = State()
    addr = Term.of(0x2000)
    state.set_tag(Reg(3), 1, {})
    state.set_tag(VByte(2, 15), 1, {})
    state.set_tag(Mem(addr), 1, {addr: 0x2000})
    assert state.tag(Reg(3), {}) == 1
    assert state.tag(Reg(4), {}) == 0
    assert state.tag(VByte(2, 15), {}) == 1
    assert state.tag(VByte(2, 14), {}) == 0
    assert state.tag(Mem(addr), {addr: 0x2000}) == 1
    assert state.mem.get(0x2001) == 0


# Replay
# \________


def test_replay_tiny(traced: Path):
    """tiny's trace replayed: every address and SP/FP audited, no alarm (no source)."""
    result = replay_file(traced / "tiny.elf", traced / "tiny.trace")
    assert (result.blocks, result.groups, result.sends, result.accesses, result.syscalls) == (1, 17, 1, 4, 2)
    assert result.skipped_before_start == 4
    assert result.sends_left == 0
    assert result.alarms == []


def test_replay_stops_at_a_wrong_address(traced: Path, tmp_path: Path):
    """The same trace with the store's address moved by 8: the audit stops the replay there."""
    with TraceFile(traced / "tiny.trace") as trace:
        header = trace.header
        records = list(trace.records)
    i = next(k for k, record in enumerate(records) if record[0] == "A")
    records[i] = (*records[i][:2], records[i][2] + 8, *records[i][3:])
    data = HEADER.pack(MAGIC, 1, 0, header.chan, header.chan_size) + b"".join(
        record[0].encode() + FORMATS[ord(record[0])].pack(*record[1:]) for record in records
    )
    path = tmp_path / "wrong.trace"
    subprocess.run(["zstd", "-q", "-o", path], input=data, check=True)
    with pytest.raises(ReplayError, match="addresses differ"):
        replay_file(traced / "tiny.elf", path)


def test_replay_signal_through_ucontext(traced: Path):
    """signal.s: the handler stores the secret into the saved x19, and the reloaded x19 leaks it."""
    result = replay_file(traced / "signal.elf", traced / "signal.trace")
    assert (result.blocks, result.signals, result.syscalls) == (2, 1, 8)
    assert [(alarm.syscall, alarm.fd, alarm.tagged) for alarm in result.alarms] == [(64, 1, 8)]
