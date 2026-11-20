#!/bin/sh
# Builds tiny.elf, forms.elf, signal.elf and fault.elf, runs them under flowsight-qemu and records
# their traces.
#   HBNG_BIN=<toolchain bin directory> MEASURE=<libmeasure.so> ./build.sh [outdir]
# outdir defaults to this directory; qemu-aarch64 must be on the PATH.
set -eu

dir=$(dirname "$0")
out=${1:-$dir}
chan=0x400000   # where __hbng_chan is linked

for prog in tiny forms signal fault; do
    "$HBNG_BIN/clang" --target=aarch64-linux -nostdlib -static -fuse-ld=lld -Wl,--no-relax \
        -Wl,--section-start=.hbngchan=$chan -o "$out/$prog.elf" "$dir/$prog.s"
    "$HBNG_BIN/llvm-hbng-postlink" "$out/$prog.elf"
done

for prog in tiny forms; do
    qemu-aarch64 -plugin "$MEASURE,out=/dev/null,taint=off,trace=$out/$prog.trace,chan=$chan" \
        "$out/$prog.elf" > /dev/null
done

# signal.elf reads its secret from the source file given as its argument
printf 'secret!\n' > "$out/secret.txt"
qemu-aarch64 -plugin "$MEASURE,out=/dev/null,taint=off,source=$out/secret.txt,trace=$out/signal.trace,chan=$chan" \
    "$out/signal.elf" "$out/secret.txt" > /dev/null

# fault.elf dies of SIGSEGV (no core file); its trace is complete up to the fault
(ulimit -c 0; qemu-aarch64 -plugin "$MEASURE,out=/dev/null,taint=off,trace=$out/fault.trace,chan=$chan" \
    "$out/fault.elf" > /dev/null 2>&1) || [ $? -eq 139 ]
