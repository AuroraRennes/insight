# Test files

The files present in this directory are the result of running `perf` on simple examples. All the source code is available in [`perfex`](https://github.com/QDucasse/perfex) along with scripts for regeneration.

To give a quick overview, programs are traced using `perf` on a ZCU-104 (Cortex-A53). To trace them, ASLR is disabled and the program is ran. `perf` records its execution using the address range associated with its placement in memory. Once traced, it is decoded using `perf report` (produces the `*.perf.dump` files) or extended and disassembled using `perf script` (produces `*.perf.disasm.log` files).

