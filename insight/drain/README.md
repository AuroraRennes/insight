# drain

A model of the compactor, the hardware block that turns a core's ETMv4 trace into a stream of 64-bit events for
the drain. The drain walks those events against the HBNG block table of the traced executable. The model serves as
the reference for the compactor's RTL and as the input of a model of the drain.

- `events.py`: the event format, encoded and decoded
- `compactor.py`: ETMv4 packets into events

```bash
uv run insight compact decode.opencsd --range <low> <high> [--base <bias>] [-o events.bin | -o events.hex --hex] [--print N]
```

The input is a `trc_pkt_lister` listing of one core (`--trace-id`, 0x10 by default). The output is one
little-endian 64-bit word per event, or with `--hex` one 16-digit hex word per line for a testbench. The command
fails when an `ERROR` or `OVERFLOW` event comes out.

## What the trace must look like

The core is traced with branch broadcast over the code the drain follows. The ETM then sends the target of every
taken branch, direct ones included, so an atom packet is a run of N atoms ending in at most one E, and the E's
target follows as an address packet. Captures of an A53 bear this out: no packet in the traced range has an E before
its last atom. Without branch broadcast, an atom packet holds several E atoms and their targets are missing, so the
compactor stops with an `ERROR`.

The compactor keeps the atoms while the last address seen is in `[low, high)` and drops the others (the loader, a
shared libc, the kernel). Addresses go out as 32 bits after subtracting the load bias `base`: 0 for a static
executable, the load address for a position-independent one.

## The event

Each event is one 64-bit AXI-Stream beat. Bits 63:61 hold the kind:

| kind | 63:61 | 60:56 | 55:32 | 31:0 |
|---|---|---|---|---|
| `BRANCH` | 000 | atom count | atoms | branch target |
| `ATOMS` | 001 | atom count | atoms | 0 |
| `EXCEPTION` | 010 | exception type | 0 | resume address |
| `OVERFLOW` | 011 | 0 | 0 | 0 |
| `LOST` | 100 | 0 | events dropped | 0 |
| `CONTEXT` | 101 | 0 | 0 | context ID |
| `ERROR` | 110 | error code | 0 | 0 |

The atoms are packed with the oldest one in bit 32; E is 1, N is 0. There are at most 24 of them, the most an
ETMv4 atom packet holds.

- **`BRANCH`**: atoms whose last one is an E, with that branch's target. The atoms before it are N. With no atoms,
  it says where execution now is without a traced branch: entering the range (back from a library or the kernel,
  or at the start), or at a periodic sync. The target `0xFFFFFFFF` means the branch left the range.
- **`ATOMS`**: atoms that are all N, the code running on without a taken branch.
- **`EXCEPTION`**: an exception taken in the range, with its ETMv4 type (`0x2` a system call, `0x3` a trap,
  `0xb` and `0xc` instruction and data faults, `0xe` an IRQ, ...) and the address execution would have resumed at.
  The kernel runs next; the trace comes back with a `BRANCH` without atoms, at the resume address or elsewhere (a
  trap may skip an instruction, a signal goes to its handler). When an E atom is pending, the exception's address
  is also its target: a `BRANCH` with that target comes first.
- **`OVERFLOW`**: the ETM lost trace. The position is unknown until the next `BRANCH` without atoms.
- **`LOST`**: the compactor dropped events because its output was full. The model has no timing and never sends it.
- **`CONTEXT`**: a new context ID. Not produced yet: the listings do not print the context ID.
- **`ERROR`**: the trace breaks an assumption above; the position is unknown until the next address. The codes are
  1, an E atom that is not the last of its packet; 2, an E atom with no address after it; 3, an address in the range
  that does not fit in 32 bits after the load bias.

For example, `0x02000002_00010034` is a `BRANCH` of two atoms, N then E, to `0x10034`.

## How the drain reads it

The drain holds the table entry of the block being executed. A block whose last instruction is a waypoint (a branch,
a call, a return or an `isb`) takes one atom: an N moves to the next entry of the table, which the post-link step guarantees starts right after the block;
an E moves to the entry at the target, found through the table's index. A block that ends without a waypoint takes
no atom and moves to the next entry. Each entry gives the number of sends to take from the send FIFO. A target that is
neither the start of an entry nor in an untracked range is reported.
