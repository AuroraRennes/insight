from __future__ import annotations


class Packet:
    def __init__(self, name: str, index: int, id: int, header: int) -> None:
        self.name: str = name
        self.index: int = index
        self.id: int = id
        self.header: int = header

    @classmethod
    def from_header(cls, header: int) -> None:
        pass


class AtomPacket(Packet):
    def __init__(
        self,
        name: str,
        index: int,
        id: int,
        header: int,
        format: int,
        elements: list[str],
    ) -> None:
        super().__init__(name=name, index=index, id=id, header=header)
        self.format: int = format
        self.elements: list[str] = elements

    @classmethod
    def f1_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F1",
            format=1,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )

    @classmethod
    def f2_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F2",
            format=2,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )

    @classmethod
    def f3_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F3",
            format=3,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )

    @classmethod
    def f4_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F4",
            format=4,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )

    @classmethod
    def f5_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F5",
            format=5,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )

    @classmethod
    def f6_atom(cls, index: int, id: int, header: int, elements: list[str]) -> AtomPacket:
        return cls(
            name="Atom_F6",
            format=6,
            index=index,
            id=id,
            header=header,
            elements=elements,
        )
