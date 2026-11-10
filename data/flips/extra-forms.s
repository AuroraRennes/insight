// Forms of the HBNG binaries that the other sources of the corpus lack: clang's uses of the zero
// register and its aliases, musl's write of the thread pointer. Assembled with GNU as for aarch64.
    adcs xzr, x1, xzr
    clrex
    cmn x1, x2, lsl #3
    csinv w0, wzr, w1, ne
    csneg x0, xzr, x1, lt
    eon x0, x1, x2, lsl #4
    ldp w0, w1, [x2], #8
    ldpsw x0, x1, [x2]
    ldr xzr, [x1, #8]
    ldrh w0, [x1, w2, uxtw]
    ldrsh x0, [x1, w2, uxtw #1]
    mov w0, wzr
    mov x0, xzr
    msr tpidr_el0, x0
    mvn w0, w1, lsr #3
    ngc x0, x1
    orn w0, w1, w2
    orr x0, x1, xzr
    orr x0, x1, xzr, lsl #2
    sbcs xzr, x1, x2
    stlxr w0, wzr, [x1]
    stlxr w0, xzr, [x1]
    stp w0, w1, [x2], #8
    stp xzr, x1, [x2, #16]!
    sub sp, x1, #16
    tst w0, w1, lsl #2
