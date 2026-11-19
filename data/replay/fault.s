// A replay fixture: a load from an unmapped page (address 16, in the null
// page) kills the process. The trace ends at the load, which has no access:
// the replay ends there, on a fatal fault. Start code as in tiny.s.
	.text
	.globl	_start
_start:
	mov	x16, sp
	adrp	x17, __hbng_chan
	stp	x29, x16, [x17]
	b	main
main:
	adrp	x9, __hbng_chan
	mov	x0, #16
	str	x0, [x9]
	ldr	x1, [x0]
	mov	x0, #0
	mov	x8, #94
	svc	#0

	// The channel page, linked at a fixed address (build.sh: chan)
	.section .hbngchan,"aw",@nobits
	.globl	__hbng_chan
__hbng_chan:
	.zero	0x10000

	.section .hbngannot,"a",@progbits
HBNG_main_annot:
	.ascii	"@0\n" "X9 <- 0\n"
	.ascii	"@4\n" "X0 <- 0\n"
	.ascii	"@8\n" "send X0\n"
	.ascii	"@12\n" "X1 <- M[<X0> .. +8]\n"
	.ascii	"@16\n" "X0 <- 0\n"
	.ascii	"@20\n" "X8 <- 0\n"
	.ascii	"@24\n" "svc\n"
	.ascii	"END\n"

	// Per block: its address and annotations, its instructions, its sends and the index of each
	// send's instruction
	.section .hbngbbt,"a",@progbits
	.xword	main, HBNG_main_annot
	.hword	7, 1, 2
	.p2align 3
