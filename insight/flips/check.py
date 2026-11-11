"""Flip tests of one instruction against its rule.

An input flows into an output if flipping it changes that output. Over two address layouts of
sixteen states each:
1. every observed flow, minus the policy's exclusions, is in the rule;
2. a location the rule keeps (its only source is itself) is not overwritten by the instruction;
3. a flow of the rule never observed is reported, not failed;
4. the rule's memory locations and new <SP>, evaluated on the state, match the run.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_MEM

from insight.dsl.locations import SP_INDEX, Mem, Reg, VByte
from insight.dsl.terms import MASK, Term
from insight.flips.forms import form_of
from insight.flips.machine import (
    DATA,
    EXCLUSIVE_OFFSET,
    LANDING,
    MEMORY_OFFSET,
    NZCV_OFFSET,
    PAGE,
    SENDS,
    SP_OFFSET,
    STATE_SIZE,
    TPIDR_OFFSET,
    V_OFFSET,
    Exclusive,
    Machine,
    RunError,
)
from insight.semantics.operands import GReg, UnsupportedFormError, VReg, address, gregs, regs
from insight.semantics.policy import NZCV, STM_REGISTER, TPIDR_EL0, Flag, inputs
from insight.semantics.rules import STORE_EXCLUSIVE_PAIRS, STORE_EXCLUSIVES, rule, size_of

if TYPE_CHECKING:
    from collections.abc import Iterable

    from capstone import CsInsn

    from insight.dsl.locations import Loc
    from insight.dsl.transfer import Transfer
    from insight.semantics.policy import Inputs

    Place = Loc | Flag

LAYOUTS = 2
STATES = 16
RANDOM_MASKS = 2  # per register and per memory byte, besides the single bits
WINDOW_SLACK = 16  # bytes flipped on each side of the access
GROUP_CHUNK = 64  # memory bytes per member of the group flips
EDGE_VALUES = (
    0, 1, MASK, 0x7FFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000,
    0xFFFF_FFFF, 0x7FFF_FFFF, 0x8000_0000, 0x1_0000_0000, 0xFF, 0x80,
)  # fmt: skip
NONZERO = re.compile(rb"[^\x00]")


# Locations and state offsets
# \____________________________


def place_at(offset: int) -> Place | None:  # noqa: PLR0911
    """The location a byte of the state belongs to."""
    if offset < SP_OFFSET:
        return Reg(offset // 8)
    if offset < NZCV_OFFSET:
        return Reg(SP_INDEX)
    if offset < TPIDR_OFFSET:
        return NZCV
    if offset < EXCLUSIVE_OFFSET:
        return TPIDR_EL0
    if offset < V_OFFSET:
        return None
    if offset < MEMORY_OFFSET:
        return VByte((offset - V_OFFSET) // 16, (offset - V_OFFSET) % 16)
    return Mem(Term.of(DATA + offset - MEMORY_OFFSET))


def reg_offset(n: int) -> int:
    return SP_OFFSET if n == SP_INDEX else 8 * n


def mem_offset(addr: int) -> int:
    return MEMORY_OFFSET + addr - DATA


def get64(state: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(state[offset : offset + 8], "little")


def put64(state: bytearray, offset: int, value: int) -> None:
    state[offset : offset + 8] = (value & MASK).to_bytes(8, "little")


# Layouts and states
# \___________________


@dataclass
class Layout:
    """The values of the address inputs, and the memory window around the access."""

    fixed: dict[int, int] = field(default_factory=dict)  # register number -> value
    window: range = range(0)  # addresses flipped bit by bit
    exclusive: int | None = None  # the access address, for arming the monitor


def access_size(insn: CsInsn) -> int:
    """Bytes accessed, for the window: from the rule's loads and stores, at most 32 (64 for the
    FP/SIMD registers: the bytes they name, an ld4 of four whole registers at most)."""
    v_data = [op for op in regs(insn) if isinstance(op, VReg)]
    if v_data:
        return min(64, sum(reg.width for reg in v_data))
    general = gregs(insn)
    width = max((reg.width for reg in general), default=8)
    pairs = 2 if any(m in insn.mnemonic for m in ("ldp", "stp", "ldnp", "stnp", "xp")) else 1
    return min(32, width * pairs)


def make_layout(insn: CsInsn, ins: Inputs, rng: random.Random) -> Layout:
    """The address inputs' values: the base and index put the access in the middle of the data
    page, an indirect branch's target register points to the landing page, x18 to its own."""
    layout = Layout()
    layout.fixed[STM_REGISTER.n] = SENDS + 0x100
    if insn.mnemonic in {"br", "blr", "ret"}:
        for reg in ins.address:
            layout.fixed[reg.n] = LANDING
        return layout
    if not any(op.type == ARM64_OP_MEM for op in insn.operands):
        return layout
    addr = address(insn)
    target = DATA + PAGE // 2 + 16 * rng.randint(-8, 8)
    index = 0
    if addr.index is not None and not addr.index.is_zero:
        if addr.index.n == addr.base.n:
            raise UnsupportedFormError(insn, "base and index are the same register")
        low = rng.randint(0, 32) if addr.ext == "uxtw" else rng.randint(-32, 32)
        value = (rng.getrandbits(32) << 32 | low & 0xFFFF_FFFF) if addr.ext in {"uxtw", "sxtw"} else low
        layout.fixed[addr.index.n] = value & MASK
        index = Term.sym("<X0>").ext(addr.ext or "uxtx", addr.shift).evaluate({"<X0>": value})
    if addr.base.n == STM_REGISTER.n:
        return layout  # a send: x18 stays on its page
    base = target if addr.mode == "post" else target - addr.disp - index
    if addr.base.kind == "sp":
        base &= ~15
        target = base if addr.mode == "post" else base + addr.disp + index
    layout.fixed[addr.base.n] = base & MASK
    target &= MASK
    size = access_size(insn)
    layout.window = range(target - WINDOW_SLACK, target + size + WINDOW_SLACK)
    if insn.mnemonic in STORE_EXCLUSIVES or insn.mnemonic in STORE_EXCLUSIVE_PAIRS:
        layout.exclusive = target
    return layout


def random_value(rng: random.Random) -> int:
    pick = rng.random()
    if pick < 0.5:
        return rng.getrandbits(64)
    if pick < 0.75:
        return rng.choice(EDGE_VALUES)
    return rng.randint(-64, 64) & MASK


def make_state(layout: Layout, k: int, rng: random.Random) -> bytes:
    state = bytearray(rng.randbytes(STATE_SIZE))
    for n in range(31):
        put64(state, reg_offset(n), random_value(rng))
    put64(state, SP_OFFSET, random_value(rng) & ~15)
    put64(state, NZCV_OFFSET, (k % 16) << 28)
    for n, value in layout.fixed.items():
        put64(state, reg_offset(n), value)
    armed = layout.exclusive is not None and k % 2 == 0
    put64(state, EXCLUSIVE_OFFSET, layout.exclusive if armed and layout.exclusive else DATA + PAGE - 64)
    state[EXCLUSIVE_OFFSET + 8 : V_OFFSET] = bytes(V_OFFSET - EXCLUSIVE_OFFSET - 8)
    return bytes(state)


# Flips
# \______


@dataclass(frozen=True)
class Flip:
    source: Place
    xor: tuple[tuple[int, int], ...]  # (state offset, byte mask)


def register_flips(n: int, rng: random.Random, bits: range | None = None) -> list[Flip]:
    offset = reg_offset(n)
    if bits is not None:  # a write-back base: only bits that keep the access in the page
        return [Flip(Reg(n), ((offset + bit // 8, 1 << (bit % 8)),)) for bit in bits]
    singles = [Flip(Reg(n), ((offset + bit // 8, 1 << (bit % 8)),)) for bit in range(64)]
    masks = [
        Flip(Reg(n), tuple((offset + i, rng.randint(1, 255)) for i in range(8))) for _ in range(RANDOM_MASKS)
    ]
    return singles + masks


def byte_flips(source: Place, offset: int, rng: random.Random) -> list[Flip]:
    singles = [Flip(source, ((offset, 1 << bit),)) for bit in range(8)]
    return singles + [Flip(source, ((offset, rng.randint(1, 255)),)) for _ in range(RANDOM_MASKS)]


@dataclass(frozen=True)
class Member:
    """One location (or a chunk of memory) flipped in the group run."""

    offsets: tuple[int, ...]

    def flips(self, rng: random.Random) -> list[Flip]:
        """Its own flips, when the group run singles it out: a register as a register, bytes
        one by one."""
        first = place_at(self.offsets[0])
        if isinstance(first, Reg) and len(self.offsets) == 8:
            return register_flips(first.n, rng)
        return [
            f for o in self.offsets if (place := place_at(o)) is not None for f in byte_flips(place, o, rng)
        ]


# Observation
# \____________


@dataclass
class Observation:
    """Over the states of one layout: who flowed into whom, what was flipped."""

    flows: dict[Place, set[Place]] = field(default_factory=dict)
    flipped: set[Place] = field(default_factory=set)
    nondeterministic: set[Place] = field(default_factory=set)
    runs: int = 0

    def add(self, source: Place, outputs: Iterable[Place]) -> None:
        for out in outputs:
            self.flows.setdefault(out, set()).add(source)


def changed(a: bytes, b: int, ignore: int) -> list[int]:
    """The offsets where a differs from b (a state as an integer), outside ignore."""
    diff = (int.from_bytes(a, "little") ^ b) & ~ignore
    if not diff:
        return []
    return [m.start() for m in NONZERO.finditer(diff.to_bytes(STATE_SIZE, "little"))]


def apply(state: bytes, xor: Iterable[tuple[int, int]]) -> bytes:
    flipped = bytearray(state)
    for offset, mask in xor:
        flipped[offset] ^= mask
    return bytes(flipped)


def outputs_of(offsets: Iterable[int]) -> set[Place]:
    return {place for o in offsets if (place := place_at(o)) is not None}


class Runner:
    def __init__(self, machine: Machine, rng: random.Random, obs: Observation) -> None:
        self.machine, self.rng, self.obs = machine, rng, obs

    def run(self, state: bytes) -> bytes:
        self.obs.runs += 1
        return self.machine.run(state)

    def flip(self, state: bytes, base: int, ignore: int, flip: Flip) -> None:
        out = self.run(apply(state, flip.xor))
        self.obs.flipped.add(flip.source)
        self.obs.add(flip.source, outputs_of(changed(out, base, ignore)))

    def group(self, state: bytes, base: int, ignore: int, members: list[Member]) -> None:
        """Flip the members together; if each only keeps its own flip, they are identities.
        Otherwise split, down to single members flipped bit by bit."""
        if not members:
            return
        xor = [(o, self.rng.randint(1, 255)) for m in members for o in m.offsets]
        expected = 0
        for offset, mask in xor:
            expected |= mask << (8 * offset)
        out = self.run(apply(state, xor))
        diff = (int.from_bytes(out, "little") ^ base) & ~ignore
        if diff == expected & ~ignore:
            for o, _ in xor:
                place = place_at(o)
                if place is not None:
                    self.obs.flipped.add(place)
                    self.obs.add(place, [place])
            return
        if len(members) == 1:
            for flip in members[0].flips(self.rng):
                self.flip(state, base, ignore, flip)
            return
        half = len(members) // 2
        self.group(state, base, ignore, members[:half])
        self.group(state, base, ignore, members[half:])


def observe(  # noqa: PLR0917 (the parts of one layout's run)
    insn: CsInsn,
    machine: Machine,
    layout: Layout,
    ins: Inputs,
    rng: random.Random,
    states_count: int = STATES,
) -> tuple[Observation, list[tuple[bytes, bytes]]]:
    """The observations over one layout's states, and each state with its output."""
    obs = Observation()
    runner = Runner(machine, rng, obs)
    operands = regs(insn)
    named = {op.n for op in operands if isinstance(op, GReg) and op.loc is not None} - set(layout.fixed)
    named_v = sorted({op.n for op in operands if isinstance(op, VReg)})
    named_tpidr = TPIDR_EL0.name.lower() in insn.op_str.lower()
    states: list[tuple[bytes, bytes]] = []
    for k in range(states_count):
        state = make_state(layout, k, rng)
        base = runner.run(state)
        states.append((state, base))
        again = runner.run(state)
        base_int = int.from_bytes(base, "little")
        varying = changed(again, base_int, 0)
        ignore = sum(0xFF << (8 * o) for o in varying)
        obs.nondeterministic |= outputs_of(varying)
        flips: list[Flip] = []
        for n in sorted(named):
            flips += register_flips(n, rng)
        if ins.writeback is not None:
            flips += register_flips(ins.writeback.n, rng, range(ins.lowest_bit, 8))
        flips += [Flip(NZCV, ((NZCV_OFFSET + 3, 1 << bit),)) for bit in range(4, 8)]
        if named_tpidr:
            flips += [Flip(TPIDR_EL0, ((TPIDR_OFFSET + bit // 8, 1 << bit % 8),)) for bit in range(64)]
        for n in named_v:  # whole registers, byte by byte: also the bytes a write clears
            flips += [f for b in range(16) for f in byte_flips(VByte(n, b), V_OFFSET + 16 * n + b, rng)]
        for addr in layout.window:
            flips += byte_flips(Mem(Term.of(addr)), mem_offset(addr), rng)
        for flip in flips:
            runner.flip(state, base_int, ignore, flip)
        members = [
            Member(tuple(range(reg_offset(n), reg_offset(n) + 8)))
            for n in [*range(31), SP_INDEX]
            if n not in named and n not in layout.fixed
        ]
        if not named_tpidr:
            members.append(Member(tuple(range(TPIDR_OFFSET, TPIDR_OFFSET + 8))))
        members += [
            Member(tuple(range(V_OFFSET + 16 * n, V_OFFSET + 16 * n + 16)))
            for n in range(32)
            if n not in named_v
        ]
        window = {mem_offset(a) for a in layout.window}
        page = [o for o in range(MEMORY_OFFSET, STATE_SIZE) if o not in window]
        members += [Member(tuple(page[i : i + GROUP_CHUNK])) for i in range(0, len(page), GROUP_CHUNK)]
        runner.group(state, base_int, ignore, members)
    return obs, states


# Checks
# \_______


@dataclass
class Report:
    encoding: str
    text: str
    form: str
    failures: list[str] = field(default_factory=list)
    precision: list[str] = field(default_factory=list)
    untestable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    runs: int = 0
    skipped: str | None = None

    @property
    def ok(self) -> bool:
        return not self.failures and self.skipped is None


def env_of(state: bytes, disp: int) -> dict[str, int]:
    env = {f"<X{n}>": get64(state, reg_offset(n)) for n in range(31)}
    env["<SP>"] = get64(state, SP_OFFSET)
    env["<FP>"] = env["<X29>"]
    env["LO12"] = disp
    return env


def concrete(loc: Loc, env: dict[str, int]) -> Loc:
    return Mem(Term.of(loc.addr.evaluate(env))) if isinstance(loc, Mem) else loc


def concrete_rule(transfer: Transfer, env: dict[str, int]) -> dict[Loc, tuple[Loc, dict[Loc, Loc]]]:
    """For each written location, concrete: its symbolic form, and its sources, concrete to
    symbolic."""
    return {
        concrete(loc, env): (loc, {concrete(s, env): s for s in dep.srcs})
        for loc, dep in transfer.tags.items()
    }


def show(place: Place) -> str:
    """Concrete memory bytes in hexadecimal."""
    if isinstance(place, Mem) and place.addr.is_const:
        return f"M[{place.addr.const:#x}]"
    return str(place)


def is_location(place: Place) -> bool:
    return not isinstance(place, Flag)


def encoded_disp(insn: CsInsn) -> int:
    return next((op.mem.disp for op in insn.operands if op.type == ARM64_OP_MEM), 0)


def check_layout(  # noqa: PLR0917 (the parts of one layout's check)
    transfer: Transfer,
    insn: CsInsn,
    ins: Inputs,
    obs: Observation,
    states: list[tuple[bytes, bytes]],
    report: Report,
) -> set[tuple[str, str]]:
    """Checks 1, 2 and 4 on one layout; the rule's flows observed, for check 3."""
    disp = encoded_disp(insn)
    envs = [env_of(state, disp) for state, _ in states]
    written = concrete_rule(transfer, envs[0])
    for env in envs[1:]:
        if concrete_rule(transfer, env).keys() != written.keys():
            report.failures.append("the rule's addresses depend on a register that is not an address input")
            return set()

    observed_pairs: set[tuple[str, str]] = set()
    # Every location flipped too: one the instruction clears and the rule leaves out (keeps) is
    # only seen there, nothing flowing into it.
    outs: set[Loc] = {out for out in obs.flows if not isinstance(out, Flag)} | set(written)
    outs |= {place for place in obs.flipped if not isinstance(place, Flag)}
    for out in sorted(outs, key=str):
        if out in obs.nondeterministic:
            continue
        excluded = ins.excluded_for(out)
        seen = {src for src in obs.flows.get(out, set()) if src not in excluded and is_location(src)}
        symbolic, srcs = written.get(out, (out, {out: out}))
        for src in sorted(seen - srcs.keys(), key=str):
            report.failures.append(
                f"soundness: {show(src)} flows into {show(out)}, not in the rule ({symbolic})"
            )
        if srcs.keys() == {out} and out in obs.flipped and out not in seen:
            report.failures.append(
                f"overwrite: the rule keeps {show(out)}'s tag, the instruction overwrites it"
            )
        for src in srcs.keys() & seen:
            observed_pairs.add((str(symbolic), str(srcs[src])))

    # 4: the new SP
    sp_term = transfer.values.get("SP")
    for (_, output), env in zip(states, envs, strict=True):
        after = get64(output, SP_OFFSET)
        expected = sp_term.evaluate(env) if sp_term is not None else env["<SP>"]
        if after != expected:
            report.failures.append(f"value: SP is {after:#x} after the run, the rule gives {expected:#x}")
            break
    return observed_pairs


def exclusive_of(insn: CsInsn) -> Exclusive | None:
    if insn.mnemonic in STORE_EXCLUSIVES:
        return Exclusive(size_of(STORE_EXCLUSIVES[insn.mnemonic], gregs(insn)[1]), pair=False)
    if insn.mnemonic in STORE_EXCLUSIVE_PAIRS:
        return Exclusive(size_of(None, gregs(insn)[1]), pair=True)
    return None


@dataclass
class Pairs:
    """The rule's flows (out, src) as text: all, observed, and those whose source was held fixed."""

    all: set[tuple[str, str]] = field(default_factory=set)
    seen: set[tuple[str, str]] = field(default_factory=set)
    fixed: set[str] = field(default_factory=set)


def decode_one(encoding: bytes) -> CsInsn:
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    (insn,) = decoder.disasm(encoding, Machine.address)
    return insn


def run_layouts(
    insn: CsInsn,
    transfer: Transfer,
    ins: Inputs,
    rng: random.Random,
    report: Report,
    *,
    layouts: int,
    states: int,
) -> Pairs:
    """Observe and check each layout; the rule's flows, for the precision report."""
    machine = Machine(bytes(insn.bytes), exclusive_of(insn))
    pairs = Pairs()
    for _ in range(layouts):
        layout = make_layout(insn, ins, rng)
        obs, runs = observe(insn, machine, layout, ins, rng, states)
        report.runs += obs.runs
        if obs.nondeterministic:
            report.notes.append("nondeterministic: " + ", ".join(sorted(map(str, obs.nondeterministic))))
        pairs.seen |= check_layout(transfer, insn, ins, obs, runs, report)
        env = env_of(runs[0][0], encoded_disp(insn))
        for loc, dep in transfer.tags.items():
            for src in dep.srcs:
                pairs.all.add((str(loc), str(src)))
                if concrete(src, env) not in obs.flipped:
                    pairs.fixed.add(str(src))
    return pairs


def flip_test(
    encoding: bytes,
    transfer: Transfer | None = None,
    *,
    seed: int | None = None,
    layouts: int = LAYOUTS,
    states: int = STATES,
) -> Report:
    """The flip test of one instruction against transfer, by default its rule in R. Fewer layouts
    or states are for quick tests only: fewer than 16 states leave NZCV values untried."""
    insn = decode_one(encoding)
    report = Report(encoding.hex(), f"{insn.mnemonic} {insn.op_str}", form_of(insn))
    if insn.mnemonic == "svc":
        report.skipped = "system call: the kernel's side (KSight events), not an instruction's"
        return report
    try:
        transfer = rule(insn) if transfer is None else transfer
        ins = inputs(insn)
    except UnsupportedFormError as error:
        report.skipped = f"R: {error.reason}"
        return report
    report.failures += [
        f"the rule excludes {src} from {written}, which the policy does not"
        for written, dep in sorted(transfer.tags.items(), key=lambda item: str(item[0]))
        for src in sorted(dep.excl - ins.untagged, key=str)
    ]
    rng = random.Random(seed if seed is not None else int.from_bytes(encoding, "little"))  # noqa: S311
    try:
        pairs = run_layouts(insn, transfer, ins, rng, report, layouts=layouts, states=states)
    except RunError as error:
        report.failures.append(f"run: {error}")
        return report
    except UnsupportedFormError as error:
        report.skipped = f"layout: {error.reason}"
        return report
    over = {(str(loc), str(s)) for loc, dep in transfer.tags.items() for s in dep.over}
    for out, src in sorted(pairs.all - pairs.seen - over):
        if src in pairs.fixed:
            report.untestable.append(f"{src} -> {out}: {src} is held fixed (an address input)")
        else:
            report.precision.append(f"{src} -> {out}: in the rule, never observed")
    report.failures = list(dict.fromkeys(report.failures))
    report.notes = list(dict.fromkeys(report.notes))
    return report
