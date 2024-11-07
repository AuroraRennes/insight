from dataclasses import dataclass

import pytest

from onsight.packets import AtomPacket


@dataclass
class PacketData:
    index: int
    id: int
    header: int
    elements: list[str]


@pytest.fixture
def default_packet_data() -> PacketData:
    return PacketData(index=0, id=0, header=0xC0, elements=["1", "2"])


def test_packet_initialization(default_packet_data):
    f1_packet = AtomPacket.f1_atom(
        default_packet_data.index,
        default_packet_data.id,
        default_packet_data.header,
        default_packet_data.elements,
    )
    assert f1_packet.name == "Atom_F1"
