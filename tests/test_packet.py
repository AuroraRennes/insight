import pytest

from insight.model.packets import AtomPacket, PacketInfo


@pytest.fixture
def default_packet_info() -> PacketInfo:
    return PacketInfo(index=0, vmid=0, cid=0, sid=0x10, size=1)


def test_packet_initialization(default_packet_info):
    f1_packet = AtomPacket.atom_format(
        packet_info=default_packet_info,
        elements=["E"],
    )
    assert f1_packet.name == "Atom F1"
    assert f1_packet.format == 1
