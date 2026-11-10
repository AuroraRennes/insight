"""Text syntax of the DSL, the statements of one transfer, as described in grammar.ebnf.

The framing of the annotations (@ groups, END, send pairing) is read by insight.annotations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NoReturn

from insight.dsl.errors import DslSyntaxError
from insight.dsl.locations import SP_INDEX, Loc, Mem, Reg, VByte
from insight.dsl.terms import EXT_KINDS, SYMBOL_RE, Term
from insight.dsl.transfer import EMPTY, ZERO, Dep, Opaque, Transfer, ValueReg, ZeroReg

TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<str>"[^"]*")
      | (?P<op><-|\.\.|[\[\]()|+\-*&,:])
      | (?P<num>0x[0-9a-fA-F]+|[0-9]+)
      | (?P<sym><(?:X[0-9]+|SP|FP)>)
      | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    )""",
    re.VERBOSE,
)
REG_RE = re.compile(r"X([0-9]|[12][0-9]|30)")
REGISTER_NAMES = {"SP": SP_INDEX, "FP": 29, "LR": 30}
VREG_RE = re.compile(r"V([0-9]|[12][0-9]|3[01])")
VALUE_TARGETS: dict[str, ValueReg] = {"<SP>": "SP", "<FP>": "FP"}


@dataclass
class Token:
    kind: str
    text: str


def fail(message: str, lineno: int) -> NoReturn:
    raise DslSyntaxError(message, lineno)


def tokenize(line: str, lineno: int) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    line = line.split("#", 1)[0].rstrip()
    while pos < len(line):
        match = TOKEN_RE.match(line, pos)
        if not match or match.end() == pos:
            fail(f"unexpected {line[pos:].strip()!r}", lineno)
        kind = match.lastgroup or ""
        tokens.append(Token(kind, match.group(kind)))
        pos = match.end()
    return tokens


@dataclass
class Builder:
    tags: dict[Loc, Dep] = field(default_factory=dict)
    values: dict[ValueReg, Term] = field(default_factory=dict)
    opaque: list[Opaque] = field(default_factory=list)
    sends: list[Reg | ZeroReg] = field(default_factory=list)
    statements: int = 0


class Parser:
    def __init__(self, tokens: list[Token], lineno: int) -> None:
        self.tokens = tokens
        self.pos = 0
        self.lineno = lineno

    # Helpers
    # \________

    def fail(self, message: str) -> NoReturn:
        raise DslSyntaxError(message, self.lineno)

    def text(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.tokens[index].text if index < len(self.tokens) else ""

    def at(self, text: str) -> bool:
        return self.text() == text

    def take(self) -> Token:
        if self.done():
            self.fail("unexpected end of line")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expect(self, text: str) -> None:
        token = self.take()
        if token.text != text:
            self.fail(f"expected {text!r}, got {token.text!r}")

    def integer(self) -> int:
        negative = self.at("-")
        if negative:
            self.take()
        token = self.take()
        if token.kind != "num":
            self.fail(f"expected a number, got {token.text!r}")
        value = int(token.text, 0)
        return -value if negative else value

    def done(self) -> bool:
        return self.pos == len(self.tokens)

    def end(self) -> None:
        if not self.done():
            self.fail(f"unexpected {self.text()!r}")

    # Terms
    # \______

    def term(self) -> Term:
        negative = self.at("-")
        if negative:
            self.take()
        result = self.prod()
        if negative:
            result = -result
        while self.at("+") or self.at("-"):
            op = self.take().text
            right = self.prod()
            result = result + right if op == "+" else result - right
        return result

    def prod(self) -> Term:
        result = self.primary()
        while self.at("*"):
            self.take()
            right = self.primary()
            if result.is_const:
                result = right * result.const
            elif right.is_const:
                result = result * right.const
            else:
                self.fail("product of two non-constant terms")
        return result

    def primary(self) -> Term:
        token = self.take()
        if token.kind == "num":
            return Term.of(int(token.text, 0))
        if token.kind in {"sym", "name"} and SYMBOL_RE.fullmatch(token.text):
            return Term.sym(token.text)
        if token.text == "ext":
            self.expect("(")
            inner = self.term()
            self.expect(",")
            kind = self.take().text
            if kind not in EXT_KINDS:
                self.fail(f"unknown extension {kind!r}")
            self.expect(",")
            shift = self.integer()
            self.expect(")")
            return inner.ext(kind, shift)
        if token.text == "(":
            inner = self.term()
            if self.at("&"):
                self.take()
                inner = inner & self.integer()
            self.expect(")")
            return inner
        return self.fail(f"unexpected {token.text!r} in a term")

    # Locations
    # \__________

    def register(self) -> Reg | None:
        name = self.text()
        if name in REGISTER_NAMES:
            self.take()
            return Reg(REGISTER_NAMES[name])
        if REG_RE.fullmatch(name):
            self.take()
            return Reg(int(name[1:]))
        return None

    def group(self, *, descending: bool = False) -> list[Loc]:
        reg = self.register()
        if reg is not None:
            return [reg]
        name = self.take().text
        if VREG_RE.fullmatch(name):
            return self.vbytes(int(name[1:]), descending=descending)
        if name == "M":
            return self.mem_bytes()
        return self.fail(f"expected a location, got {name!r}")

    def vbytes(self, n: int, *, descending: bool) -> list[Loc]:
        self.expect("[")
        lo = hi = self.integer()
        if self.at(":"):
            self.take()
            hi = self.integer()
        self.expect("]")
        if not (0 <= lo <= 15 and 0 <= hi <= 15) or (hi < lo and not descending):
            self.fail(f"bad byte range V{n}[{lo}:{hi}]")
        order = range(lo, hi + 1) if lo <= hi else range(lo, hi - 1, -1)
        return [VByte(n, b) for b in order]

    def mem_bytes(self) -> list[Loc]:
        self.expect("[")
        addr = self.term()
        size, step, times = 1, 0, 1
        if self.at(".."):
            self.take()
            self.expect("+")
            size = self.integer()
            if size < 1:
                self.fail("empty memory range")
            if self.at("step"):
                self.take()
                step = self.integer()
                self.expect("times")
                times = self.integer()
                if step < 0 or times < 1:
                    self.fail(f"bad stride step {step} times {times}")
        self.expect("]")
        return [Mem(addr + i * step + k) for i in range(times) for k in range(size)]

    # Statements
    # \___________

    def statement(self, out: Builder) -> None:
        first = self.text()
        if first == "send":
            self.take()
            sent: Reg | ZeroReg
            if self.at("XZR"):
                self.take()
                sent = ZERO
            else:
                reg = self.register()
                if reg is None or reg.n == SP_INDEX:
                    self.fail("expected send X<n> or send XZR")
                sent = reg
            self.end()
            out.sends.append(sent)
        elif first == "svc":
            self.take()
            self.end()
            out.opaque.append(Opaque("svc"))
        elif first == "unsupported":
            self.take()
            token = self.take()
            if token.kind != "str":
                self.fail('expected unsupported "<reason>"')
            self.end()
            out.opaque.append(Opaque("unsupported", token.text[1:-1]))
        elif first in VALUE_TARGETS and self.text(1) == "<-":
            self.pos += 2
            reg_name = VALUE_TARGETS[first]
            if reg_name in out.values:
                self.fail(f"{first} written twice")
            out.values[reg_name] = self.term()
            self.end()
        else:
            self.tag_statement(out)
        out.statements += 1

    def tag_statement(self, out: Builder) -> None:
        dsts = self.group()
        self.expect("<-")
        srcs = self.part(dsts)
        excl = [EMPTY for _ in dsts]
        over: set[Loc] = set()
        if self.at("excl"):
            self.take()
            excl = self.part(dsts)
        if self.at("over"):
            self.take()
            while not self.done():
                over.update(self.group())
        self.end()
        covered: set[Loc] = set()
        for dst, src, exc in zip(dsts, srcs, excl, strict=True):
            mine = frozenset(over) & src
            covered |= mine
            if dst in out.tags:
                self.fail(f"{dst} written twice")
            out.tags[dst] = Dep(src, exc, mine)
        if over - covered:
            stray = ", ".join(sorted(map(str, over - covered)))
            self.fail(f"over-approximated locations that are not sources: {stray}")

    def part(self, dsts: list[Loc]) -> list[frozenset[Loc]]:
        """The locations each written location gets from one part (sources or exclusions)."""
        if self.at("["):
            return self.byte_map(dsts)
        if self.at("0"):
            self.take()
            if self.at("per"):
                self.per(dsts, [])
            return [EMPTY for _ in dsts]
        groups = [self.group()]
        while self.at("|"):
            self.take()
            groups.append(self.group())
        if self.at("per"):
            return self.per(dsts, groups)
        union = frozenset(loc for group in groups for loc in group)
        return [union for _ in dsts]

    def byte_map(self, dsts: list[Loc]) -> list[frozenset[Loc]]:
        self.expect("[")
        items: list[frozenset[Loc]] = []
        while not self.at("]"):
            if self.at("0"):
                self.take()
                items.append(EMPTY)
            else:
                items += [frozenset({loc}) for loc in self.group(descending=True)]
        self.expect("]")
        if len(items) != len(dsts):
            self.fail(f"byte map of {len(items)} for {len(dsts)} locations")
        return items

    def per(self, dsts: list[Loc], groups: list[list[Loc]]) -> list[frozenset[Loc]]:
        self.expect("per")
        e_in = e_out = self.integer()
        if self.at(":"):
            self.take()
            e_out = self.integer()
        if e_in < 1 or e_out < 1:
            self.fail("element sizes must be positive")
        if len(dsts) % e_out:
            self.fail(f"{len(dsts)} locations are not elements of {e_out}")
        count = len(dsts) // e_out
        for group in groups:
            if len(group) != count * e_in:
                self.fail(f"group of {len(group)} locations for {count} elements of {e_in}")
        result: list[frozenset[Loc]] = []
        for i in range(count):
            union = frozenset(loc for group in groups for loc in group[i * e_in : (i + 1) * e_in])
            result += [union] * e_out
        return result


def parse(text: str) -> Transfer:
    """The statements of one transfer, one per line."""
    out = Builder()
    for lineno, line in enumerate(text.splitlines(), 1):
        tokens = tokenize(line, lineno)
        if tokens:
            Parser(tokens, lineno).statement(out)
    if out.opaque and out.statements > 1:
        msg = f"{out.opaque[0]} must stand alone"
        raise DslSyntaxError(msg)
    return Transfer(out.tags, out.values, tuple(out.opaque), tuple(out.sends))
