import pytest

from insight.replay.trace import HEADER, MAGIC, Stream, TraceError, parse_header, parse_records

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
