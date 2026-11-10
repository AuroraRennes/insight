# Corpus of instruction forms

`corpus.json` maps each instruction form (`ldr x, [x, #]!`: a mnemonic and the shape of its
operands) to up to four encodings found in real AArch64 code. The flip tests (`insight fliptest`)
run R against these encodings, and the tests check that R fails closed on each of them. The
corpus is committed, so none of the binaries below is needed to run the tests.

`sources` in the JSON lists every file the corpus was built from, with its sha256 and origin.

| files | origin |
|---|---|
| `/usr/bin/gdb`, `/usr/bin/perf`, `/usr/lib/libpython3.12.so.1.0`, `/usr/lib/libgmp.so.10` | PetaLinux 2024.2+release-S11061705 (Yocto scarthgap, built with GCC) |
| `/usr/aarch64-linux-gnu/lib/libc.so.6`, `libm.so.6` | Debian package `libc6-arm64-cross` 2.41-11cross1 |
| `extra-forms.o` | `extra-forms.s`, assembled with GNU as 2.44 (Debian `binutils-aarch64-linux-gnu`) |

The binaries were chosen for the forms they add: `gdb` alone gives most forms R has a rule for, `perf` and `libm` add FP/SIMD forms, `libgmp` carry chains, glibc hand-written string routines. `extra-forms.s` holds the forms of the HBNG builds that none of them has: clang's uses of the zero register and their aliases, and musl's write of the thread pointer. Together they cover every general-register form of the HBNG nginx.
