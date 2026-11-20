// One block per kind of issue the check reports.
	.text
	.globl	_start
_start:
HBNG_not_a_send:
	ldr	x0, [x0]
	ret
HBNG_wrong_page:
	adrp	x16, other
	str	x0, [x16]
	ldr	x0, [x0]
	ret
HBNG_unpaired:
	ldr	x0, [x1]
	ret
HBNG_gap:
	ldr	x0, [x1]
	ret
HBNG_syntax:
	ret

	.bss
	.p2align 12
	.globl	__hbng_chan
__hbng_chan:
	.zero	4096
other:
	.zero	4096

	.section .hbngannot,"a",@progbits
HBNG_not_a_send_annot:
	.ascii	"@0\n" "send X0\n" "X0 <- M[<X0> .. +8]\n"
	.ascii	"@4\n" "END\n"
HBNG_wrong_page_annot:
	.ascii	"@0\n" "X16 <- 0\n"
	.ascii	"@4\n" "send X0\n"
	.ascii	"@8\n" "X0 <- M[<X0> .. +8]\n"
	.ascii	"@12\n" "END\n"
HBNG_unpaired_annot:
	.ascii	"@0\n" "X0 <- M[<X1> .. +8]\n"
	.ascii	"@4\n" "END\n"
HBNG_gap_annot:
	.ascii	"@0\n"
	.ascii	"@8\n" "END\n"
HBNG_syntax_annot:
	.ascii	"@0\n" "X0 := 1\n" "END\n"

	.section .hbngbbt,"a",@progbits
	.p2align 2
// Each entry: the block, its text, its instructions (0x8000: the last one is a waypoint, a branch,
// call, return or isb), its sends, then the instruction of each send. llvm-hbng-postlink sorts
// them and adds the index and the format version.
	.word	HBNG_not_a_send, HBNG_not_a_send_annot
	.hword	0x8002, 1, 0
	.p2align 2
	.word	HBNG_wrong_page, HBNG_wrong_page_annot
	.hword	0x8004, 1, 1
	.p2align 2
	.word	HBNG_unpaired, HBNG_unpaired_annot
	.hword	0x8002, 0
	.p2align 2
	.word	HBNG_gap, HBNG_gap_annot
	.hword	0x8002, 0
	.p2align 2
	.word	HBNG_syntax, HBNG_syntax_annot
	.hword	0x8001, 0
	.p2align 2
