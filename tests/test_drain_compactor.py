import pytest

from insight.cli import main
from insight.drain.compactor import Compactor
from insight.drain.events import OUTSIDE, Error, Event, Kind
from insight.model.packet_parser import PacketParser

LOW, HIGH = 0xAAAAAAAA0000, 0xAAAAAABB4000

# Lines as trc_pkt_lister prints them, from captures of an A53 with branch broadcast in [LOW, HIGH).
ADDR = "ID:10;\tI_ADDR_S_IS0 : Address, Short, IS0.; Addr=0x{:016X} ~[0x0]"
CONTEXT = "ID:10;\tI_ADDR_CTXT_L_64IS0 : Address & Context, Long, 64 bit, IS0.; Addr=0x{:016X}; Ctxt: {}; "
VECTOR = CONTEXT.format(0xFFFF800080010C00, "AArch64,EL1, NS")
ATOMS = "ID:10;\tI_ATOM_F{} : Atom format {}.; {}"
EXCEPT = "ID:10;\tI_EXCEPT : Exception.;  {}; Ret Addr Follows;"
TRACE_ON = "ID:10;\tI_TRACE_ON : Trace On."
OVERFLOW = "ID:10;\tI_OVERFLOW : Overflow."


def atoms(elements: str) -> str:
    fmt = min(len(elements), 6)
    return ATOMS.format(fmt, fmt, elements)


def compact(*lines: str, base: int = LOW) -> list[Event]:
    parser = PacketParser()
    compactor = Compactor(LOW, HIGH, base)
    return list(compactor.run(parser.parse_packet(line) for line in lines))


def at(offset: int) -> str:
    return ADDR.format(LOW + offset)


def test_the_encoding_of_a_branch():
    event = Event.atoms(["N", "E"], 0x10034)
    assert event.encode() == 0x02000002_00010034
    assert Event.decode(event.encode()) == event
    assert str(event) == "BRANCH NE 0x10034"


def test_every_kind_survives_its_encoding():
    events = [
        Event.atoms(list("NNNE" * 6), 0xFFFF_FFFE),
        Event.atoms(list("NNNN")),
        Event(Kind.EXCEPTION, 0xE, 0, 0xDB44),
        Event(Kind.OVERFLOW),
        Event(Kind.LOST, 0, 1000),
        Event(Kind.CONTEXT, 0, 0, 0x1234),
        Event(Kind.ERROR, Error.WIDE),
    ]
    assert [Event.decode(event.encode()) for event in events] == events


def test_more_atoms_than_an_event_holds():
    with pytest.raises(ValueError, match="25 atoms"):
        Event.atoms(list("N" * 25))


def test_atoms_ending_in_e_take_the_next_address_as_target():
    assert compact(at(0xDB00), atoms("NNE"), at(0xD9E0), atoms("NN"), atoms("E"), at(0xD5A8)) == [
        Event(Kind.BRANCH, 0, 0, 0xDB00),
        Event.atoms(list("NNE"), 0xD9E0),
        Event.atoms(list("NN")),
        Event.atoms(list("E"), 0xD5A8),
    ]


def test_atoms_outside_the_range_are_dropped_until_execution_comes_back():
    events = compact(
        at(0xD5C0), atoms("E"), ADDR.format(0xFFFFF7FD4CE8), atoms("EEN"), atoms("E"), at(0xD5D4)
    )
    assert [str(event) for event in events] == ["BRANCH - 0xd5c0", "BRANCH E outside", "BRANCH - 0xd5d4"]
    assert events[1] == Event.atoms(["E"], OUTSIDE)


def test_an_exception_gives_the_address_execution_resumes_at():
    # A trap, then the kernel, which resumes one instruction further.
    events = compact(
        at(0x3800),
        atoms("NE"),
        EXCEPT.format("Trap"),
        at(0x3900),
        VECTOR,
        TRACE_ON,
        CONTEXT.format(LOW + 0x3904, "AArch64,EL0, NS"),
    )
    assert [str(event) for event in events] == [
        "BRANCH - 0x3800",
        "BRANCH NE 0x3900",
        "EXCEPTION 0x3 0x3900",
        "BRANCH - 0x3904",
    ]


def test_an_exception_after_a_branch_with_its_target():
    events = compact(at(0xDB34), atoms("E"), at(0xDB44), EXCEPT.format("IRQ"), at(0xDB44), VECTOR)
    assert [str(event) for event in events][1:] == ["BRANCH E 0xdb44", "EXCEPTION 0xe 0xdb44"]


def test_an_exception_outside_the_range_is_dropped():
    events = compact(
        ADDR.format(0xFFFFF7FD47AC), EXCEPT.format("Data Fault"), ADDR.format(0xFFFFF7FD47B0), VECTOR
    )
    assert events == []


def test_an_e_that_is_not_last_is_an_error():
    assert compact(at(0), atoms("EN"))[1:] == [Event(Kind.ERROR, Error.E_NOT_LAST)]


def test_an_e_without_an_address_is_an_error():
    assert compact(at(0), atoms("E"), atoms("N"))[1:] == [Event(Kind.ERROR, Error.NO_TARGET)]
    assert compact(at(0), atoms("E"), TRACE_ON)[1:] == [Event(Kind.ERROR, Error.NO_TARGET)]
    assert compact(at(0), atoms("E"))[1:] == [Event(Kind.ERROR, Error.NO_TARGET)]


def test_an_address_too_wide_for_32_bits_is_an_error():
    assert compact(at(0), base=0) == [Event(Kind.ERROR, Error.WIDE)]


def test_an_overflow_forgets_where_execution_is():
    events = compact(at(0), atoms("E"), OVERFLOW, atoms("NNE"), at(0x40))
    assert [str(event) for event in events] == ["BRANCH - 0x0", "OVERFLOW", "BRANCH - 0x40"]


def test_unknown_exception_names_are_refused():
    with pytest.raises(ValueError, match="no ETMv4 type"):
        compact(at(0), EXCEPT.format("Something"))


def test_the_compact_command(tmp_path, capsys):
    listing = tmp_path / "decode.opencsd"
    lines = ["Trace Packet Lister : reading snapshot from path .", at(0), atoms("NE"), at(0x40)]
    listing.write_text("\n".join(lines) + "\n")
    output = tmp_path / "events.hex"
    args = ["compact", str(listing), "--range", hex(LOW), hex(HIGH), "--base", hex(LOW)]
    assert main([*args, "-o", str(output), "--hex", "--print", "1"]) == 0
    assert output.read_text() == "0000000000000000\n0200000200000040\n"
    out = capsys.readouterr().out
    assert out.startswith("BRANCH - 0x0\n")
    assert "2 events (2 BRANCH), 1.00 atoms per event" in out
    binary = tmp_path / "events.bin"
    assert main([*args, "-o", str(binary)]) == 0
    assert binary.read_bytes()[8:] == (0x0200000200000040).to_bytes(8, "little")


def test_the_compact_command_fails_on_errors(tmp_path):
    listing = tmp_path / "decode.opencsd"
    listing.write_text(at(0) + "\n" + atoms("EN") + "\n")
    assert main(["compact", str(listing), "--range", hex(LOW), hex(HIGH), "--base", hex(LOW)]) == 1
