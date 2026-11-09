#!/bin/sh
# Rebuilds the test executables from their sources with the HBNG toolchain:
#   HBNG_BIN=<toolchain>/bin ./build.sh
set -eu
cd "$(dirname "$0")"
bin="${HBNG_BIN:?set HBNG_BIN to the HBNG toolchain bin directory}"
for name in good bad old; do
    "$bin/clang" --target=aarch64-linux-musl -nostdlib -static -fuse-ld=lld \
        -Wl,--build-id=none -Wl,-z,norelro -o "$name.elf" "$name.s"
done
