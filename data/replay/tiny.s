// A replay fixture: start code outside the block table (SP, then FP, to the
// channel page), then one annotated block: a send, a store and a load through
// the sent base, a pair on the stack, write(1, buf, 8) and exit_group(0).
	.text
	.globl	_start
_start:
	mov	x16, sp
	adrp	x17, __hbng_chan
	stp	x29, x16, [x17]
	b	main
.Lstart_end:
main:
	adrp	x9, __hbng_chan
	adrp	x0, buf
	add	x0, x0, :lo12:buf
	str	x0, [x9]
	mov	x1, #42
	str	x1, [x0]
	ldr	x2, [x0, #8]
	stp	x0, x1, [sp, #-16]!
	ldp	x0, x1, [sp], #16
	mov	x2, #8
	mov	x1, x0
	mov	x0, #1
	mov	x8, #64
	svc	#0
	mov	x0, #0
	mov	x8, #94
	svc	#0
	udf	#0	// exit_group does not return

	.data
	.p2align 3
buf:
	.quad	0, 7

	// The channel page, linked at a fixed address (build.sh: chan)
	.section .hbngchan,"aw",@nobits
	.globl	__hbng_chan
__hbng_chan:
	.zero	0x10000

	.section .hbngannot,"a",@progbits
HBNG_main_annot:
	.ascii	"@0\n" "X9 <- 0\n"
	.ascii	"@4\n" "X0 <- 0\n"
	.ascii	"@8\n" "X0 <- X0\n"
	.ascii	"@12\n" "send X0\n"
	.ascii	"@16\n" "X1 <- 0\n"
	.ascii	"@20\n" "M[<X0> .. +8] <- X1\n"
	.ascii	"@24\n" "X2 <- M[<X0> + 8 .. +8]\n"
	.ascii	"@28\n" "M[<SP> - 16 .. +8] <- X0\n" "M[<SP> - 8 .. +8] <- X1\n" "<SP> <- <SP> - 16\n"
	.ascii	"@32\n" "X0 <- M[<SP> .. +8]\n" "X1 <- M[<SP> + 8 .. +8]\n" "<SP> <- <SP> + 16\n"
	.ascii	"@36\n" "X2 <- 0\n"
	.ascii	"@40\n" "X1 <- X0\n"
	.ascii	"@44\n" "X0 <- 0\n"
	.ascii	"@48\n" "X8 <- 0\n"
	.ascii	"@52\n" "svc\n"
	.ascii	"@56\n" "X0 <- 0\n"
	.ascii	"@60\n" "X8 <- 0\n"
	.ascii	"@64\n" "svc\n"
	.ascii	"END\n"

	// Per block: its address and annotations, its instructions (0x8000: the last one is a branch,
	// call, return or isb), its sends and the index of each send's instruction
	.section .hbngbbt,"a",@progbits
	.word	main, HBNG_main_annot
	.hword	17, 1, 3
	.p2align 2

	// Code with no entry: the start code
	.section .hbngskip,"",@progbits
	.word	_start, .Lstart_end
