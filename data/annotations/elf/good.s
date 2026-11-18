// Blocks whose annotations pass the check: sends to the channel page, through a register an
// adrp of the page sets in the block, or one set before the block.
	.text
	.globl	_start
_start:
HBNG_load:
	adrp	x16, __hbng_chan
	str	x0, [x16]
	ldr	x0, [x0]
	ret
HBNG_cas_n_2:
	stlxp	w9, x8, x1, [x0]
	stp	x0, x0, [x16]
	cbnz	w9, HBNG_cas_n_2
HBNG_frame:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	ldp	x29, x30, [sp], #16
	adrp	x9, __hbng_chan
	str	x29, [x9]
	ret

	.bss
	.p2align 12
	.globl	__hbng_chan
__hbng_chan:
	.zero	4096

	.section .hbngannot,"a",@progbits
HBNG_load_annot:
	.ascii	"@0\n" "X16 <- 0\n"
	.ascii	"@4\n" "send X0\n"
	.ascii	"@8\n" "X0 <- M[<X0> .. +8]\n"
	.ascii	"@12\n" "END\n"
HBNG_cas_n_2_annot:
	.ascii	"@0\n" "M[<X0> .. +8] <- X8\n" "M[<X0> + 8 .. +8] <- X1\n" "X9 <- 0\n"
	.ascii	"@4\n" "send X0\n" "send X0\n"
	.ascii	"@8\n" "END\n"
HBNG_frame_annot:
	.ascii	"@0\n" "M[<SP> - 16 .. +8] <- FP\n" "M[<SP> - 8 .. +8] <- LR\n" "<SP> <- <SP> - 16\n"
	.ascii	"@4\n" "FP <- SP\n" "<FP> <- <SP>\n"
	.ascii	"@8\n" "FP <- M[<SP> .. +8]\n" "LR <- M[<SP> + 8 .. +8]\n" "<SP> <- <SP> + 16\n"
	.ascii	"@12\n" "X9 <- 0\n"
	.ascii	"@16\n" "send X29\n" "<FP> <- <X29>\n"
	.ascii	"@20\n" "END\n"

	.section .hbngbbt,"a",@progbits
	.p2align 3
// Each entry: the block, its text, its instructions, its sends, then the instruction of each send.
	.xword	HBNG_load, HBNG_load_annot
	.hword	4, 1, 1
	.p2align 3
	.xword	HBNG_cas_n_2, HBNG_cas_n_2_annot
	.hword	3, 2, 1, 1
	.p2align 3
	.xword	HBNG_frame, HBNG_frame_annot
	.hword	6, 1, 4
	.p2align 3
