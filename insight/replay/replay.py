"""Replay of a trace: the annotations run on what the coprocessor would receive, checked against
what QEMU actually did. The first difference stops the replay: past an out-of-step send, every
value would be wrong.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from insight.annotations.against_r import LO12, encoded_offset
from insight.annotations.framing import read_blocks
from insight.annotations.pairing import code_at, decode, pair_sends, register_writes
from insight.dsl.locations import Mem
from insight.dsl.terms import Sym, Term
from insight.replay.state import MASK64, State
from insight.replay.trace import Stream, TraceFile

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from capstone import CsInsn

    from insight.annotations.framing import Block
    from insight.dsl.locations import Loc
    from insight.dsl.transfer import Transfer
    from insight.replay.trace import Record

INSTRUCTION = 4
EVENTS = frozenset("YLCM")
GLOBAL = Sym("GLOBAL")


class ReplayError(Exception):
    """An audit mismatch or a block the replay cannot run: the replay stops."""


@dataclass(frozen=True)
class Alarm:
    syscall: int
    fd: int
    tagged: int
    first: int


@dataclass
class Result:
    blocks: int = 0  # block instances run
    groups: int = 0
    sends: int = 0
    accesses: int = 0
    syscalls: int = 0
    alarms: list[Alarm] = field(default_factory=list)
    skipped_before_start: int = 0  # instructions run before tracking started
    sends_left: int = 0


@dataclass(frozen=True)
class Group:
    address: int
    form: Transfer
    sends: tuple[int, ...]  # indices of the block's sends this group emits
    needs: int  # highest send index the group refers to or emits, -1 if none
    writes: tuple[tuple[Loc, tuple[Loc, ...]], ...]
    mems: tuple[Term, ...]  # every memory byte the group names


@dataclass(frozen=True)
class Compiled:
    block: Block
    groups: tuple[Group, ...]

    @property
    def end(self) -> int:
        return self.block.address + INSTRUCTION * len(self.groups)


def compile_block(block: Block, insns: list[CsInsn], image_base: int = 0) -> Compiled:
    """The block's groups paired with its sends, LO12 and GLOBAL replaced by their values."""
    paired = pair_sends(block, [register_writes(insn) for insn in insns])
    groups = []
    for k, paired_form in enumerate(paired.forms):
        form = paired_form.subst({LO12: Term.of(encoded_offset(insns[k])), GLOBAL: Term.of(image_base)})
        own = tuple(send.index for send in paired.sends if send.group == k)
        refs = [int(sym.name[1:]) for sym in form.symbols() if sym.name.startswith("S")]
        mems = [loc.addr for loc in form.locations() if isinstance(loc, Mem)]
        groups.append(
            Group(
                address=block.address + INSTRUCTION * k,
                form=form,
                sends=own,
                needs=max([*own, *refs], default=-1),
                writes=tuple((loc, tuple(dep.srcs)) for loc, dep in form.tags.items()),
                mems=tuple(dict.fromkeys(mems)),
            )
        )
    return Compiled(block, tuple(groups))


class Symbols:
    """Function names for messages."""

    def __init__(self, functions: Iterable[tuple[int, int, str]]) -> None:
        self.functions = sorted(functions)
        self.starts = [start for start, _, _ in self.functions]

    def name(self, addr: int) -> str:
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            start, size, name = self.functions[i]
            if addr < start + max(size, 1):
                return f"{name}+{addr - start:#x}"
        return "?"


@dataclass
class Instance:
    """A block being run: the send values taken so far."""

    code: Compiled
    next_group: int = 0
    sent: list[int] = field(default_factory=list)

    @property
    def finished(self) -> bool:
        return self.next_group == len(self.code.groups)


class Replay:
    def __init__(
        self,
        blocks: Iterable[Block],
        insns: Callable[[Block], list[CsInsn]],
        symbols: Symbols | None = None,
    ) -> None:
        self.blocks = {block.address: block for block in blocks}
        self.insns = insns
        self.symbols = symbols or Symbols([])
        self.compiled: dict[int, Compiled] = {}
        self.state = State()
        self.result = Result()
        self.current: Instance | None = None
        self.tracking = False
        self.syscall = 0  # number of the syscall whose events come
        self.alarm_syscall = -1  # index of the syscall the last alarm belongs to

    # Messages
    # \_________

    def where(self, addr: int) -> str:
        return f"{addr:#x} ({self.symbols.name(addr)})"

    def fail(self, message: str, group: Group | None = None) -> ReplayError:
        lines = [message]
        if group is not None and self.current is not None:
            block = self.current.code.block
            lines.append(f"  block {self.where(block.address)}, @{group.address - block.address}")
            lines.extend(f"    {line}" for line in str(group.form).splitlines())
            lines.append(f"  sends of this block so far: {[hex(v) for v in self.current.sent]}")
        lines.append(f"  tracked SP {self.state.sp:#x}, FP {self.state.fp:#x}")
        return ReplayError("\n".join(lines))

    # Running
    # \_________

    def code(self, addr: int) -> Compiled:
        code = self.compiled.get(addr)
        if code is None:
            block = self.blocks[addr]
            code = self.compiled[addr] = compile_block(block, self.insns(block))
        return code

    def run(self, stream: Stream) -> Result:
        while (record := stream.next()) is not None:
            kind = record[0]
            if kind == "B":
                self.run_tb(stream, record[1], record[2])
            elif kind in EVENTS:
                self.event(record)
            elif kind == "A" and not self.tracking:
                continue
            else:
                msg = f"unexpected record {record[0]} outside a block"
                raise self.fail(msg)
        left = 0
        while stream.next_send() is not None:
            left += 1
        self.result.sends_left = left
        return self.result

    def run_tb(self, stream: Stream, pc: int, n: int) -> None:
        """A block of n instructions from pc. Tracking starts at the first annotated block after the
        start code's SP and FP sends; from then on, a block outside the table stops the replay."""
        regs = stream.next()
        if regs is None or regs[0] != "R":
            msg = f"block record at {pc:#x} without its registers"
            raise self.fail(msg)
        _, sp, fp = regs
        if not self.tracking:
            if pc not in self.blocks or len(stream.sends) < 2:
                self.skip(stream, n)
                return
            self.state.sp = stream.sends.popleft()
            self.state.fp = stream.sends.popleft()
            self.tracking = True
        for i in range(n):
            addr = pc + INSTRUCTION * i
            group = self.enter(addr, sp, fp, audit=i == 0)
            self.run_group(stream, group)
            self.drain_events(stream)

    def skip(self, stream: Stream, n: int) -> None:
        """A block run untracked (the start code): its accesses are not audited, its events
        apply."""
        if not self.tracking:
            self.result.skipped_before_start += n
        while (record := stream.peek()) is not None and (record[0] == "A" or record[0] in EVENTS):
            stream.next()
            if record[0] in EVENTS:
                self.event(record)

    def enter(self, addr: int, sp: int, fp: int, *, audit: bool) -> Group:
        """The group of the instruction at addr: the next of the current block, or the first of
        a block entered."""
        cur = self.current
        if cur is not None and not cur.finished and cur.code.groups[cur.next_group].address == addr:
            group = cur.code.groups[cur.next_group]
            cur.next_group += 1
            return group
        if addr not in self.blocks:
            msg = f"block outside the table entered at {self.where(addr)}"
            raise self.fail(msg)
        if cur is not None and not cur.finished:
            msg = (
                f"block {self.where(cur.code.block.address)} left at @{INSTRUCTION * cur.next_group}"
                f" for {self.where(addr)}"
            )
            raise self.fail(msg)
        if audit and (sp != self.state.sp or fp != self.state.fp):
            msg = (
                f"at block {self.where(addr)}: SP/FP {self.state.sp:#x}/{self.state.fp:#x},"
                f" real {sp:#x}/{fp:#x}"
            )
            raise self.fail(msg)
        self.current = Instance(self.code(addr))
        self.result.blocks += 1
        self.current.next_group = 1
        return self.current.code.groups[0]

    def run_group(self, stream: Stream, group: Group) -> None:
        cur = self.current
        if cur is None:
            msg = "a group outside a block"
            raise self.fail(msg)
        self.take_sends(stream, cur, group)
        state = self.state
        env = {"<SP>": state.sp, "<FP>": state.fp}
        for i, value in enumerate(cur.sent):
            env[f"S{i}"] = value
        addrs = {term: term.evaluate(env) for term in group.mems}
        self.audit(stream, group, addrs)
        for opaque in group.form.opaque:
            if opaque.kind == "unsupported":
                msg = f"unsupported instruction run at {self.where(group.address)}: {opaque.text}"
                raise self.fail(msg, group)

        # Tags: a written location gets the OR of its sources' tags, all read at the group's entry
        new = []
        for loc, srcs in group.writes:
            tag = 0
            for src in srcs:
                tag |= state.tag(src, addrs)
            new.append((loc, tag))
        for loc, tag in new:
            state.set_tag(loc, tag, addrs)
        values = group.form.values
        if "SP" in values:
            state.sp = values["SP"].evaluate(env)
        if "FP" in values:
            state.fp = values["FP"].evaluate(env)
        self.result.groups += 1

    def take_sends(self, stream: Stream, cur: Instance, group: Group) -> None:
        """The block's sends up to the last one the group emits or refers to, from the FIFO. A
        group may need a later send than its own: a store-exclusive sends after itself."""
        while len(cur.sent) <= group.needs:
            value = stream.next_send()
            if value is None:
                msg = "the trace has no more sends"
                raise self.fail(msg, group)
            cur.sent.append(value)
            self.result.sends += 1

    def audit(self, stream: Stream, group: Group, addrs: dict[Term, int]) -> None:
        """The memory bytes the group names against the instruction's real accesses."""
        named = set(addrs.values())
        real: set[int] = set()
        while (record := stream.peek()) is not None and record[0] == "A" and record[1] == group.address:
            stream.next()
            _, _, base, size, _ = record
            self.result.accesses += 1
            real.update((base + i) & MASK64 for i in range(size))
        if real != named:
            msg = (
                f"addresses differ at {self.where(group.address)}: real {describe(real)},"
                f" annotated {describe(named)}"
            )
            raise self.fail(msg, group)

    # KSight's events
    # \_______________

    def drain_events(self, stream: Stream) -> None:
        while (record := stream.peek()) is not None and record[0] in EVENTS:
            stream.next()
            self.event(record)

    def event(self, record: Record) -> None:
        """One of KSight's events: a label sets the tags of a range, a move carries them along, and
        a check before an output syscall raises an alarm when a checked byte is tagged."""
        kind = record[0]
        mem = self.state.mem
        if kind == "Y":
            self.result.syscalls += 1
            self.syscall = record[1]
        elif kind == "L":
            _, addr, length, tag = record
            mem.fill(addr, length, tag)
        elif kind == "M":
            _, dst, src, length = record
            mem.move(dst, src, length)
        elif kind == "C":
            _, addr, length, fd = record
            tagged, first = mem.count(addr, length)
            # One alarm per syscall: the checks of one syscall follow each other
            alarms = self.result.alarms
            if tagged:
                last = alarms[-1] if alarms else None
                if last is not None and self.alarm_syscall == self.result.syscalls:
                    alarms[-1] = Alarm(last.syscall, last.fd, last.tagged + tagged, last.first)
                else:
                    alarms.append(Alarm(self.syscall, fd, tagged, addr if first is None else first))
                    self.alarm_syscall = self.result.syscalls


def describe(addrs: set[int]) -> str:
    """Byte addresses as ranges."""
    if not addrs:
        return "none"
    ranges = []
    ordered = sorted(addrs)
    start = prev = ordered[0]
    for a in ordered[1:]:
        if a != prev + 1:
            ranges.append((start, prev))
            start = a
        prev = a
    ranges.append((start, prev))
    return ", ".join(f"{s:#x}..+{e - s + 1}" for s, e in ranges)


def elf_symbols(elf: ELFFile) -> Symbols:
    symtab = elf.get_section_by_name(".symtab")
    if not isinstance(symtab, SymbolTableSection):
        return Symbols([])
    return Symbols(
        (sym["st_value"], sym["st_size"], sym.name)
        for sym in symtab.iter_symbols()
        if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"]
    )


def replay_file(elf_path: Path, trace_path: Path) -> Result:
    """Replays the trace of a run of the HBNG binary at elf_path."""
    with elf_path.open("rb") as f, TraceFile(trace_path) as trace:
        elf = ELFFile(f)
        if elf["e_type"] != "ET_EXEC":
            msg = "only static, non-PIE binaries (GLOBAL, the image base, is 0)"
            raise ReplayError(msg)

        def insns(block: Block) -> list[CsInsn]:
            return decode(code_at(elf, block.address, block.size), block.address)

        replay = Replay(read_blocks(elf), insns, elf_symbols(elf))
        return replay.run(Stream(trace.records))
