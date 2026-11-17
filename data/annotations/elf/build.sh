#!/bin/sh
# Builds the test executables from their sources with the HBNG toolchain:
#   HBNG_BIN=<toolchain>/bin ./build.sh [outdir]
# outdir defaults to this directory.
set -eu
dir=$(dirname "$0")
out=${1:-$dir}
bin="${HBNG_BIN:?set HBNG_BIN to the HBNG toolchain bin directory}"
for name in good bad old; do
    "$bin/clang" --target=aarch64-linux-musl -nostdlib -static -fuse-ld=lld \
        -Wl,--build-id=none -Wl,-z,norelro -o "$out/$name.elf" "$dir/$name.s"
done
