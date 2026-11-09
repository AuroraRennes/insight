"""Printing a transfer in the DSL's text syntax, deterministic and regrouped.

Written locations are cut into runs, each printed as a union line, a byte map or runs of equal
dependencies.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

from insight.dsl.locations import Loc, Mem, Reg, VByte, loc_key
from insight.dsl.terms import Term

if TYPE_CHECKING:
    from insight.dsl.transfer import Dep, Transfer


def follows(prev: Loc, loc: Loc, direction: int = 1) -> bool:
    if isinstance(prev, VByte) and isinstance(loc, VByte):
        return prev.n == loc.n and loc.b == prev.b + direction
    if isinstance(prev, Mem) and isinstance(loc, Mem) and direction == 1:
        return (loc.addr - prev.addr) == Term.of(1)
    return False


def consecutive_runs(locs: list[Loc]) -> list[list[Loc]]:
    """Consecutive runs in the given order: ascending, or descending for V bytes."""
    runs: list[list[Loc]] = []
    for loc in locs:
        if runs:
            run = runs[-1]
            direction = -1 if len(run) > 1 and follows(run[0], run[1], -1) else 1
            if follows(run[-1], loc, direction) or (len(run) == 1 and follows(run[-1], loc, -1)):
                run.append(loc)
                continue
        runs.append([loc])
    return runs


def group_text(run: list[Loc]) -> str:
    first, last = run[0], run[-1]
    if len(run) == 1:
        return str(first)
    if isinstance(first, VByte) and isinstance(last, VByte):
        return f"V{first.n}[{first.b}:{last.b}]"
    if isinstance(first, Mem):
        return f"M[{first.addr} .. +{len(run)}]"
    msg = f"not a run: {', '.join(map(str, run))}"
    raise ValueError(msg)


def union_text(locs: frozenset[Loc]) -> str:
    if not locs:
        return "0"
    return " | ".join(group_text(run) for run in consecutive_runs(sorted(locs, key=loc_key)))


def written_runs(locs: list[Loc]) -> list[list[Loc]]:
    runs: list[list[Loc]] = []
    for loc in locs:
        if runs and follows(runs[-1][-1], loc):
            runs[-1].append(loc)
        else:
            runs.append([loc])
    return runs


def union_line(dsts: list[Loc], dep: Dep) -> str:
    line = f"{group_text(dsts)} <- {union_text(dep.srcs)}"
    if dep.excl:
        line += f" excl {union_text(dep.excl)}"
    if dep.over:
        line += " over " + " ".join(
            group_text(run) for run in consecutive_runs(sorted(dep.over, key=loc_key))
        )
    return line


def byte_map_line(dsts: list[Loc], deps: list[Dep]) -> str:
    items: list[str] = []
    pending: list[Loc] = []
    for dep in deps:
        if dep.srcs:
            pending += list(dep.srcs)
            continue
        items += [group_text(run) for run in consecutive_runs(pending)]
        pending = []
        items.append("0")
    items += [group_text(run) for run in consecutive_runs(pending)]
    return f"{group_text(dsts)} <- [{' '.join(items)}]"


def group_for(seq: list[Loc]) -> str | None:
    """The group that lists exactly seq, in order: a V range or a (strided) memory group."""
    if all(follows(a, b) for a, b in pairwise(seq)):
        return group_text(seq) if not isinstance(seq[0], Reg) or len(seq) == 1 else None
    mems = [loc for loc in seq if isinstance(loc, Mem)]
    return strided_mem_group(mems) if len(mems) == len(seq) else None


def strided_mem_group(seq: list[Mem]) -> str | None:
    size = 1
    while follows(seq[size - 1], seq[size]):
        size += 1
    distance = seq[size].addr - seq[0].addr
    if len(seq) % size or not distance.is_const or distance.const >= 1 << 32:
        return None
    step, times = distance.const, len(seq) // size
    if seq != [Mem(seq[0].addr + i * step + k) for i in range(times) for k in range(size)]:
        return None
    return f"M[{seq[0].addr} .. +{size} step {step} times {times}]"


def per_part(sets: list[frozenset[Loc]], e_out: int) -> str | None:
    """A part as text: the same locations for every element (a union), or element i made of the
    i-th element of each group (per e_in:e_out); None when it has neither shape."""
    if all(each == sets[0] for each in sets):
        return union_text(sets[0])
    runs = [consecutive_runs(sorted(each, key=loc_key)) for each in sets]
    if not runs[0]:
        return None
    e_in = len(runs[0][0])
    if any(len(element) != len(runs[0]) or any(len(run) != e_in for run in element) for element in runs):
        return None
    groups: list[str] = []
    for j in range(len(runs[0])):
        text = group_for([loc for element in runs for loc in element[j]])
        if text is None:
            return None
        groups.append(text)
    return " | ".join(groups) + f" per {e_in}" + ("" if e_out == e_in else f":{e_out}")


def per_line(run: list[Loc], deps: list[Dep]) -> str | None:
    if any(dep.over for dep in deps):
        return None
    for e_out in (1, 2, 4, 8):
        count = len(run) // e_out
        if len(run) % e_out or count < 2:
            continue
        chunks = [deps[i * e_out : (i + 1) * e_out] for i in range(count)]
        if any(dep != chunk[0] for chunk in chunks for dep in chunk):
            continue
        srcs = per_part([chunk[0].srcs for chunk in chunks], e_out)
        excl = per_part([chunk[0].excl for chunk in chunks], e_out)
        if srcs is not None and excl is not None:
            return f"{group_text(run)} <- {srcs}" + ("" if excl == "0" else f" excl {excl}")
    return None


def run_lines(run: list[Loc], tags: dict[Loc, Dep]) -> list[str]:
    deps = [tags[loc] for loc in run]
    if all(dep == deps[0] for dep in deps):
        return [union_line(run, deps[0])]
    per = per_line(run, deps)
    if per is not None:
        return [per]
    if all(len(dep.srcs) <= 1 and not dep.excl and not dep.over for dep in deps):
        return [byte_map_line(run, deps)]
    lines: list[str] = []
    start = 0
    for i in range(1, len(run) + 1):
        if i == len(run) or deps[i] != deps[start]:
            lines.append(union_line(run[start:i], deps[start]))
            start = i
    return lines


def dump(transfer: Transfer) -> str:
    """Deterministic, regrouped text; parse(dump(t)) == t."""
    lines = [f"send {reg}" for reg in transfer.sends]
    tags = dict(transfer.tags)
    for run in written_runs(sorted(tags, key=loc_key)):
        lines += run_lines(run, tags)
    lines += [f"<{reg}> <- {transfer.values[reg]}" for reg in ("SP", "FP") if reg in transfer.values]
    lines += [str(op) for op in transfer.opaque]
    return "\n".join(lines)
