"""Replay's tag state: one tag per X register (and SP), per V-register byte and per memory byte."""

from __future__ import annotations

from typing import TYPE_CHECKING

from insight.dsl.locations import Reg, VByte

if TYPE_CHECKING:
    from collections.abc import Mapping

    from insight.dsl.locations import Loc
    from insight.dsl.terms import Term

PAGE = 4096
MASK64 = (1 << 64) - 1


class Shadow:
    """Memory tags, one byte each."""

    def __init__(self) -> None:
        self.pages: dict[int, bytearray] = {}

    def get(self, addr: int) -> int:
        page = self.pages.get(addr >> 12)
        return page[addr & (PAGE - 1)] if page is not None else 0

    def set(self, addr: int, tag: int) -> None:
        page = self.pages.get(addr >> 12)
        if page is None:
            if not tag:
                return
            page = self.pages[addr >> 12] = bytearray(PAGE)
        page[addr & (PAGE - 1)] = tag

    def fill(self, addr: int, length: int, tag: int) -> None:
        end = addr + length
        while addr < end:
            n = min(end, (addr | (PAGE - 1)) + 1) - addr
            page = self.pages.get(addr >> 12)
            if page is None and tag:
                page = self.pages[addr >> 12] = bytearray(PAGE)
            if page is not None:
                start = addr & (PAGE - 1)
                page[start : start + n] = bytes([tag]) * n
            addr += n

    def count(self, addr: int, length: int) -> tuple[int, int | None]:
        """The number of tagged bytes in the range, and the first one."""
        tagged, first = 0, None
        end = addr + length
        while addr < end:
            n = min(end, (addr | (PAGE - 1)) + 1) - addr
            page = self.pages.get(addr >> 12)
            if page is not None:
                start = addr & (PAGE - 1)
                chunk = page[start : start + n]
                k = n - chunk.count(0)
                if k and first is None:
                    first = addr + next(i for i, b in enumerate(chunk) if b)
                tagged += k
            addr += n
        return tagged, first

    def move(self, dst: int, src: int, length: int) -> None:
        tags = bytes(self.get(src + i) for i in range(length))
        for i, tag in enumerate(tags):
            self.set(dst + i, tag)


class State:
    def __init__(self) -> None:
        self.x = [0] * 32  # X0-X30, SP as 31
        self.v = [bytearray(16) for _ in range(32)]
        self.mem = Shadow()
        self.sp = 0
        self.fp = 0

    def tag(self, loc: Loc, addrs: Mapping[Term, int]) -> int:
        """The tag of a location; addrs gives the value of each memory byte's address term."""
        if isinstance(loc, Reg):
            return self.x[loc.n]
        if isinstance(loc, VByte):
            return self.v[loc.n][loc.b]
        return self.mem.get(addrs[loc.addr])

    def set_tag(self, loc: Loc, tag: int, addrs: Mapping[Term, int]) -> None:
        if isinstance(loc, Reg):
            self.x[loc.n] = tag
        elif isinstance(loc, VByte):
            self.v[loc.n][loc.b] = tag
        else:
            self.mem.set(addrs[loc.addr], tag)
