import os
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from insight.replay.trace import HEADER, MAGIC, Stream, TraceError, TraceFile, parse_header, parse_records

FIXTURES = Path(__file__).parent.parent / "data" / "replay"


@pytest.fixture(scope="session")
def tiny(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """tiny.s built and traced by flowsight-qemu (data/replay/build.sh), in a temporary directory.
    Needs HBNG_BIN (clang), MEASURE (flowsight-qemu's plugin) and qemu-aarch64; skipped without
    them."""
    missing = [name for name in ("HBNG_BIN", "MEASURE") if not os.environ.get(name)]
    if not shutil.which("qemu-aarch64"):
        missing.append("qemu-aarch64 on the PATH")
    if missing:
        pytest.skip(f"no flowsight-qemu trace without {', '.join(missing)}")
    out = tmp_path_factory.mktemp("replay")
    subprocess.run([FIXTURES / "build.sh", out], check=True)  # noqa: S603
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


def test_plugin_trace(tiny: Path):
    """A trace written by flowsight-qemu: the format both sides agree on."""
    with (tiny / "tiny.elf").open("rb") as f:
        symtab = ELFFile(f).get_section_by_name(".symtab")
        assert isinstance(symtab, SymbolTableSection)
        (chan,) = (sym["st_value"] for sym in symtab.iter_symbols() if sym.name == "__hbng_chan")
    with TraceFile(tiny / "tiny.trace") as trace:
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
