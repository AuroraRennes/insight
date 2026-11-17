"""Replay of a trace: the annotations run on what the coprocessor would receive, checked against
what QEMU actually did. The first difference stops the replay: past an out-of-step send, every
value would be wrong.
"""

from __future__ import annotations

import bisect
import contextlib
import functools
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from insight.annotations.against_r import LO12, encoded_offset
from insight.annotations.framing import annotation_texts, read_block
from insight.annotations.pairing import code_at, decode, pair_sends, register_writes
from insight.dsl.locations import Mem
from insight.dsl.terms import Sym, Term
from insight.replay.codegen import generate
from insight.replay.state import MASK64, State
from insight.replay.trace import NOT_PEEKED, Stream, TraceFile

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping
    from pathlib import Path

    from capstone import CsInsn

    from insight.annotations.framing import Block
    from insight.dsl.transfer import Transfer
    from insight.replay.trace import Record

INSTRUCTION = 4
NOP = bytes.fromhex("1f2003d5")
EVENTS = frozenset("YLCM")
SIGRETURN = 139  # rt_sigreturn
RESTORER_SIZE = 8  # the C library's restorer: mov x8, #139; svc 0
# The signal frame at the handler's SP: siginfo (128 bytes), then the ucontext, whose mcontext (at
# 176) holds the fault address then x0-x30, and whose first record after sp, pc and pstate holds
# fpsr, fpcr and the V registers.
FRAME_X = 128 + 176 + 8
FRAME_V = FRAME_X + 8 * 31 + 8 * 3 + 8 + 16
FRAME_END = FRAME_V + 16 * 32
GLOBAL = Sym("GLOBAL")


class ReplayError(Exception):
    """An audit mismatch or a block the replay cannot run: the replay stops."""


class FatalFault(Exception):  # noqa: N818 (an outcome, not an error)
    """The trace ends at an instruction that faulted: the process died there. The instruction made
    only some of its accesses (none for a load from an unmapped page) and nothing follows; its
    group's tags are not applied, as it did not complete."""


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
    signals: int = 0  # signals delivered and returned from
    padding: int = 0  # nops run outside the table
    readonly_loads: int = 0  # loads from read-only segments the annotations do not name
    discarded_loads: int = 0  # loads into the zero register
    fault: str | None = None  # where the instruction whose fatal fault ended the trace is


@dataclass(frozen=True)
class Group:
    address: int
    form: Transfer
    sends: tuple[int, ...]  # indices of the block's sends this group emits
    needs: int  # highest send index the group refers to or emits, -1 if none
    mems: tuple[Term, ...]  # every memory byte the group names
    where: Callable[..., tuple[tuple[tuple[int, int], ...], tuple[int, ...]]]  # their runs (codegen.py)
    apply: Callable[..., tuple[int, int]]  # the tags, then SP and FP (codegen.py)
    unsupported: str | None = None  # the text of an unsupported instruction
    discards: bool = False  # a load into the zero register: no tag changes, nothing to name


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
        insn = insns[k]
        discards = (
            insn.mnemonic.startswith("ld")
            and bool(insn.operands)
            and insn.reg_name(insn.operands[0].reg) in {"xzr", "wzr"}
        )
        unique = tuple(dict.fromkeys(mems))
        where, apply = generate(form, unique)
        unsupported = next((opaque.text for opaque in form.opaque if opaque.kind == "unsupported"), None)
        groups.append(
            Group(
                address=block.address + INSTRUCTION * k,
                form=form,
                sends=own,
                needs=max([*own, *refs], default=-1),
                mems=unique,
                where=where,
                apply=apply,
                unsupported=unsupported,
                discards=discards,
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


@dataclass
class Frame:
    """What a signal delivery interrupts, resumed at rt_sigreturn: the block being run and the
    tracked SP and FP; address is the signal frame's, which holds the saved registers."""

    instance: Instance | None
    sp: int
    fp: int
    restorer: int
    address: int


class Replay:
    def __init__(
        self,
        blocks: Mapping[int, str],
        insns: Callable[[Block], list[CsInsn]],
        symbols: Symbols | None = None,
        word: Callable[[int], bytes] | None = None,
        readonly: Iterable[tuple[int, int]] = (),
    ) -> None:
        self.blocks = blocks  # each block's annotation text, parsed when first entered
        self.insns = insns
        self.word = word or (lambda _: b"")
        self.readonly = sorted(readonly)  # (start, end) of the image's read-only segments
        self.symbols = symbols or Symbols([])
        self.compiled: dict[int, Compiled] = {}
        self.state = State()
        self.result = Result()
        self.current: Instance | None = None
        self.tracking = False
        self.frames: list[Frame] = []  # signals being handled
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
            block = read_block(self.blocks[addr], addr)
            code = self.compiled[addr] = compile_block(block, self.insns(block))
        return code

    def run(self, stream: Stream) -> Result:
        with contextlib.suppress(FatalFault):  # the result records where
            self.run_records(stream)
        left = 0
        while stream.next_send() is not None:
            left += 1
        self.result.sends_left = left
        return self.result

    def run_records(self, stream: Stream) -> None:
        while (record := stream.next()) is not None:
            kind = record[0]
            if kind == "B":
                self.run_tb(stream, record[1], record[2])
            elif kind in EVENTS:
                self.event(record)
            elif kind == "G" and self.tracking:
                self.deliver(record[2], record[3], record[4])
            elif kind == "G" or (kind == "A" and not self.tracking):
                continue
            else:
                msg = f"unexpected record {record[0]} outside a block"
                raise self.fail(msg)

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
        if self.frames and self.frames[-1].restorer <= pc < self.frames[-1].restorer + RESTORER_SIZE:
            self.skip(stream, n)  # its rt_sigreturn restores the interrupted context
            return
        i = 0
        while i < n:
            group = self.enter(pc + INSTRUCTION * i, sp, fp, audit=i == 0)
            i += 1
            if group is not None:
                self.run_group(stream, group)
            self.drain_events(stream)
            # The rest of the block follows group by group, as long as it is the current one (a
            # signal's return changes it)
            cur = self.current
            if group is None or cur is None:
                continue
            groups = cur.code.groups
            while i < n and cur.next_group < len(groups) and self.current is cur:
                group = groups[cur.next_group]
                cur.next_group += 1
                i += 1
                self.run_group(stream, group)
                head = stream.peek()
                if head is not None and head[0] in EVENTS:
                    self.drain_events(stream)

    def skip(self, stream: Stream, n: int) -> None:
        """A block run untracked (the start code, a signal's restorer): its accesses are not
        audited, its events apply."""
        if not self.tracking:
            self.result.skipped_before_start += n
        while (record := stream.peek()) is not None and (record[0] == "A" or record[0] in EVENTS):
            stream.next()
            if record[0] in EVENTS:
                self.event(record)

    def enter(self, addr: int, sp: int, fp: int, *, audit: bool) -> Group | None:
        """The group at addr: the current block's next, or a new block's first. None for an
        alignment nop between blocks, run when a block falls through it."""
        cur = self.current
        if cur is not None and not cur.finished and cur.code.groups[cur.next_group].address == addr:
            group = cur.code.groups[cur.next_group]
            cur.next_group += 1
            return group
        if addr not in self.blocks:
            if (cur is None or cur.finished) and self.word(addr) == NOP:
                self.result.padding += 1
                return None
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
        if len(cur.sent) <= group.needs:
            self.take_sends(stream, cur, group)
        state = self.state
        sent = cur.sent
        named, addrs = group.where(state.sp, state.fp, sent)
        head = stream.peek()
        if named or (head is not None and head[0] == "A" and head[1] == group.address):
            self.audit(stream, group, named)
        if group.unsupported is not None:
            msg = f"unsupported instruction run at {self.where(group.address)}: {group.unsupported}"
            raise self.fail(msg, group)
        state.sp, state.fp = group.apply(
            addrs, state.sp, state.fp, sent, state.x, state.v, state.mem.pages, state.mem.set
        )
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

    def audit(self, stream: Stream, group: Group, named: tuple[tuple[int, int], ...]) -> None:
        """The memory bytes the group names, as runs (start, length), against the instruction's
        real accesses: compared as runs, and as bytes when the runs are cut differently."""
        real: list[tuple[int, int]] = []
        address = group.address
        result = self.result
        while (record := stream.peek()) is not None and record[0] == "A" and record[1] == address:
            stream.head = NOT_PEEKED  # taken
            _, _, base, size, store = record
            result.accesses += 1
            if not store and not covers(named, base) and self.is_readonly(base, size):
                # Constant data (jump tables, literals): clean, the annotation need not name it
                result.readonly_loads += 1
                continue
            if not store and group.discards and not named:
                result.discarded_loads += 1
                continue
            if real and real[-1][0] + real[-1][1] == base:
                real[-1] = (real[-1][0], real[-1][1] + size)
            else:
                real.append((base, size))
        if tuple(real) == named or sorted(real) == sorted(named):
            return
        real_bytes, named_bytes = run_bytes(real), run_bytes(named)
        if real_bytes == named_bytes:
            return
        if real_bytes < named_bytes and record is None:
            result.fault = self.where(group.address)
            raise FatalFault
        msg = (
            f"addresses differ at {self.where(group.address)}: real {describe(real_bytes)},"
            f" annotated {describe(named_bytes)}"
        )
        raise self.fail(msg, group)

    def is_readonly(self, addr: int, size: int) -> bool:
        i = bisect.bisect_right(self.readonly, (addr, MASK64)) - 1
        return i >= 0 and self.readonly[i][0] <= addr and addr + size <= self.readonly[i][1]

    # KSight's events
    # \_______________

    def drain_events(self, stream: Stream) -> None:
        while (record := stream.peek()) is not None and record[0] in EVENTS:
            stream.next()
            self.event(record)

    def deliver(self, restorer: int, sp: int, fp: int) -> None:
        """A signal delivered: the register tags go where the kernel saves the registers, the rest
        of the frame is clean, and the handler starts with clean x0-x2 and x30."""
        state, mem = self.state, self.state.mem
        self.frames.append(Frame(self.current, state.sp, state.fp, restorer, sp))
        mem.fill(sp, FRAME_END, 0)
        for n in range(31):
            mem.fill(sp + FRAME_X + 8 * n, 8, state.x[n])
        for n in range(32):
            for b in range(16):
                mem.set(sp + FRAME_V + 16 * n + b, state.v[n][b])
        # The frame record x29 points at: the interrupted x29 and x30
        mem.fill(fp, 8, state.x[29])
        mem.fill(fp + 8, 8, state.x[30])
        state.sp, state.fp = sp, fp
        for n in (0, 1, 2, 30):
            state.x[n] = 0
        self.current = None

    def sigreturn(self) -> None:
        """The kernel reloads the registers from the frame, which the handler may have changed:
        their tags come from the frame's memory."""
        frame = self.frames.pop()
        state, mem = self.state, self.state.mem
        for n in range(31):
            tag = 0
            for i in range(8):
                tag |= mem.get(frame.address + FRAME_X + 8 * n + i)
            state.x[n] = tag
        for n in range(32):
            for b in range(16):
                state.v[n][b] = mem.get(frame.address + FRAME_V + 16 * n + b)
        self.current = frame.instance
        state.sp, state.fp = frame.sp, frame.fp
        self.result.signals += 1

    def event(self, record: Record) -> None:
        """One of KSight's events: a label sets the tags of a range, a move carries them along, and
        a check before an output syscall raises an alarm when a checked byte is tagged."""
        kind = record[0]
        mem = self.state.mem
        if kind == "Y":
            self.result.syscalls += 1
            self.syscall = record[1]
            if self.syscall == SIGRETURN and self.frames:
                self.sigreturn()
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


def covers(runs: Iterable[tuple[int, int]], addr: int) -> bool:
    return any(start <= addr < start + n for start, n in runs)


def run_bytes(runs: Iterable[tuple[int, int]]) -> set[int]:
    found: set[int] = set()
    for start, n in runs:
        found.update((start + i) & MASK64 for i in range(n))
    return found


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

        readonly = [
            (seg["p_vaddr"], seg["p_vaddr"] + seg["p_memsz"])
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and not seg["p_flags"] & P_FLAGS.PF_W
        ]
        word = functools.cache(lambda addr: code_at(elf, addr, INSTRUCTION))  # the padding is revisited
        replay = Replay(annotation_texts(elf), insns, elf_symbols(elf), word, readonly)
        return replay.run(Stream(trace.records))
