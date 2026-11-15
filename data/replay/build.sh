#!/bin/sh
# Builds tiny.elf from tiny.s, runs it under flowsight-qemu and records its trace.
#   HBNG_BIN=<toolchain bin directory> MEASURE=<libmeasure.so> ./build.sh [outdir]
# outdir defaults to this directory; qemu-aarch64 must be on the PATH.
set -eu

dir=$(dirname "$0")
out=${1:-$dir}
chan=0x400000   # where __hbng_chan is linked

"$HBNG_BIN/clang" --target=aarch64-linux -nostdlib -static -fuse-ld=lld -Wl,--no-relax \
    -Wl,--section-start=.hbngchan=$chan -o "$out/tiny.elf" "$dir/tiny.s"

qemu-aarch64 -plugin "$MEASURE,out=/dev/null,taint=off,trace=$out/tiny.trace,chan=$chan" \
    "$out/tiny.elf" > /dev/null
