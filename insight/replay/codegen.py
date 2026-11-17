"""Each group's transfer compiled once into Python functions, its memory handled as byte runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from insight.dsl.locations import Reg, VByte
from insight.dsl.terms import MASK, And, Ext, Sym, Term
from insight.replay.state import PAGE

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from insight.dsl.locations import Loc
    from insight.dsl.transfer import Transfer

ZERO_PAGE = bytes(PAGE)  # the tags of a page with no tagged byte


def symbol(sym: Sym) -> str:
    if sym.name == "<SP>":
        return "sp"
    if sym.name == "<FP>":
        return "fp"
    if sym.name.startswith("S"):
        return f"s[{int(sym.name[1:])}]"
    msg = f"{sym} left in a paired form"
    raise ValueError(msg)


def linear(term: Term, *, const: bool = True) -> str:
    """The term as a Python expression, not reduced modulo 2^64."""
    parts = []
    for atom, coef in term.coeffs:
        if isinstance(atom, Sym):
            text = symbol(atom)
        elif isinstance(atom, Ext):
            low = f"(({expression(atom.term)}) & 0xFFFFFFFF)"
            if atom.kind == "sxtw":
                low = f"(({low} ^ 0x80000000) - 0x80000000)"
            text = f"({low} << {atom.shift})" if atom.shift else low
        elif isinstance(atom, And):
            text = f"(({expression(atom.term)}) & {atom.mask:#x})"
        else:
            msg = f"unknown atom {atom!r}"
            raise TypeError(msg)
        parts.append(text if coef == 1 else f"{coef:#x} * {text}")
    if const and (term.const or not parts):
        parts.append(f"{term.const:#x}")
    return " + ".join(parts)


def expression(term: Term) -> str:
    """The term's value modulo 2^64."""
    if term.is_const:
        return f"{term.const:#x}"
    return f"({linear(term)}) & {MASK:#x}"


def tag_or(pages: dict[int, bytearray], a: int, n: int) -> int:
    """The OR of the tags of n bytes from a."""
    o = a & 0xFFF
    if o + n <= PAGE:
        page = pages.get(a >> 12)
        tag = 0
        if page is not None:
            for b in page[o : o + n]:
                tag |= b
        return tag
    tag = 0
    for i in range(n):
        b = (a + i) & MASK
        tag |= pages.get(b >> 12, ZERO_PAGE)[b & 0xFFF]
    return tag


def tag_fill(pages: dict[int, bytearray], a: int, n: int, tag: int) -> None:
    """n bytes from a get tag; a clean page with no tagged byte stays unallocated."""
    o = a & 0xFFF
    if o + n <= PAGE:
        page = pages.get(a >> 12)
        if page is None:
            if not tag:
                return
            page = pages[a >> 12] = bytearray(PAGE)
        page[o : o + n] = bytes((tag,)) * n
        return
    for i in range(n):
        tag_fill(pages, (a + i) & MASK, 1, tag)


@dataclass(frozen=True)
class Runs:
    """The memory bytes of a group as runs of consecutive bytes, one or more per address term:
    (coefficients, first constant, length), and where each byte is (run, offset)."""

    runs: tuple[tuple[tuple, int, int], ...]
    place: dict[Term, tuple[int, int]]


def runs_of(mems: Sequence[Term]) -> Runs:
    by_base: dict[tuple, list[int]] = {}
    for term in mems:
        by_base.setdefault(term.coeffs, []).append(term.const)
    runs: list[tuple[tuple, int, int]] = []
    place: dict[Term, tuple[int, int]] = {}
    for coeffs, consts in by_base.items():
        ordered = sorted(set(consts))
        first = 0
        for k in range(1, len(ordered) + 1):
            if k < len(ordered) and ordered[k] == ordered[k - 1] + 1:
                continue
            start = ordered[first]
            for const in ordered[first:k]:
                place[Term(coeffs, const)] = (len(runs), const - start)
            runs.append((coeffs, start, k - first))
            first = k
    return Runs(tuple(runs), place)


def where_source(runs: Runs) -> str:
    """where(sp, fp, s), s being the block's sends so far: ((start, length) per run, (start per
    run)); each base computed once."""
    lines = ["def where(sp, fp, s):"]
    bases: dict[tuple, str] = {}
    names = []
    for r, (coeffs, const, _) in enumerate(runs.runs):
        name = f"a{r}"
        names.append(name)
        if not coeffs:
            lines.append(f"    {name} = {const:#x}")
            continue
        base = bases.get(coeffs)
        if base is None:
            base = bases[coeffs] = f"b{len(bases)}"
            lines.append(f"    {base} = {linear(Term(coeffs, 0), const=False)}")
        offset = f" + {const:#x}" if const else ""
        lines.append(f"    {name} = ({base}{offset}) & {MASK:#x}")
    pairs = ", ".join(f"({name}, {n})" for name, (_, _, n) in zip(names, runs.runs, strict=True))
    lines.append(f"    return ({pairs},), ({', '.join(names)},)" if names else "    return (), ()")
    return "\n".join(lines)


def segments(offsets: Sequence[int]) -> list[tuple[int, int]]:
    """Sorted offsets as (first, length) of consecutive ones."""
    result: list[tuple[int, int]] = []
    for off in offsets:
        if result and result[-1][0] + result[-1][1] == off:
            result[-1] = (result[-1][0], result[-1][1] + 1)
        else:
            result.append((off, 1))
    return result


class ApplySource:
    """apply(a, sp, fp, s, x, v, pages, mset) -> (sp, fp): a is where's starts, x and v the register
    tags, pages and mset the shadow memory's pages and byte setter. Every source is read into a
    local first, then the writes, the bytes of a run that share their sources in one fill."""

    def __init__(self, form: Transfer, runs: Runs) -> None:
        self.runs = runs
        self.lines = ["def apply(a, sp, fp, s, x, v, pages, mset):"]
        if runs.runs:
            self.lines.append(f"    {', '.join(f'a{r}' for r in range(len(runs.runs)))}, = a")
        self.names: dict[object, str] = {}
        tags = [(loc, self.sources(dep.srcs)) for loc, dep in form.tags.items()]
        mem_writes: dict[int, dict[int, str]] = {}
        for loc, tag in tags:
            if isinstance(loc, Reg):
                self.lines.append(f"    x[{loc.n}] = {tag}")
            elif isinstance(loc, VByte):
                self.lines.append(f"    v[{loc.n}][{loc.b}] = {tag}")
            else:
                r, off = runs.place[loc.addr]
                mem_writes.setdefault(r, {})[off] = tag
        for r, by_off in sorted(mem_writes.items()):
            self.memory_writes(r, by_off)
        sp_text = expression(form.values["SP"]) if "SP" in form.values else "sp"
        fp_text = expression(form.values["FP"]) if "FP" in form.values else "fp"
        self.lines.append(f"    return {sp_text}, {fp_text}")

    @staticmethod
    def byte(r: int, off: int) -> str:
        return f"a{r}" if not off else f"((a{r} + {off:#x}) & {MASK:#x})"

    def value(self, key: object, text: str) -> str:
        """A local holding text, read once."""
        name = self.names.get(key)
        if name is None:
            name = self.names[key] = f"r{len(self.names)}"
            self.lines.append(f"    {name} = {text}")
        return name

    def sources(self, srcs: frozenset[Loc]) -> str:
        """The OR of the sources' tags, memory read by runs of consecutive bytes."""
        parts = []
        mem: dict[int, list[int]] = {}
        for src in sorted(srcs, key=str):
            if isinstance(src, Reg):
                parts.append(self.value(src, f"x[{src.n}]"))
            elif isinstance(src, VByte):
                parts.append(self.value(src, f"v[{src.n}][{src.b}]"))
            else:
                r, off = self.runs.place[src.addr]
                mem.setdefault(r, []).append(off)
        for r, offs in sorted(mem.items()):
            for off, n in segments(sorted(offs)):
                at = self.byte(r, off)
                one = f"pages.get({at} >> 12, ZERO_PAGE)[{at} & 0xFFF]"
                parts.append(self.value(("m", r, off, n), one if n == 1 else f"tag_or(pages, {at}, {n})"))
        return " | ".join(dict.fromkeys(parts)) or "0"

    def memory_writes(self, r: int, by_off: dict[int, str]) -> None:
        offs = sorted(by_off)
        k = 0
        while k < len(offs):
            j = k + 1
            while j < len(offs) and offs[j] == offs[j - 1] + 1 and by_off[offs[j]] == by_off[offs[k]]:
                j += 1
            tag, at = by_off[offs[k]], self.byte(r, offs[k])
            self.lines.append(
                f"    mset({at}, {tag})" if j == k + 1 else f"    tag_fill(pages, {at}, {j - k}, {tag})"
            )
            k = j

    def __str__(self) -> str:
        return "\n".join(self.lines)


def generate(form: Transfer, mems: Sequence[Term]) -> tuple[Callable, Callable]:
    """(where, apply) for a paired form whose memory bytes are mems."""
    runs = runs_of(mems)
    namespace: dict[str, Any] = {"ZERO_PAGE": ZERO_PAGE, "tag_or": tag_or, "tag_fill": tag_fill}
    source = f"{where_source(runs)}\n\n{ApplySource(form, runs)}"
    exec(compile(source, "<group>", "exec"), namespace)  # noqa: S102 (code generated from the form)
    return namespace["where"], namespace["apply"]
