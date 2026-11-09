// One block per kind of issue the check reports.
	.text
	.globl	_start
_start:
HBNG_missing_send:
	str	x0, [x18]
	ldr	x0, [x0]
	ret
HBNG_unpaired:
	ldr	x0, [x1]
	ret
HBNG_gap:
	ldr	x0, [x1]
	ret
HBNG_x18:
	mov	x18, x0
	ret
HBNG_syntax:
	ret

	.section .hbngannot,"a",@progbits
HBNG_missing_send_annot:
	.ascii	"@0\n"
	.ascii	"@4\n" "X0 <- M[<X0> .. +8]\n"
	.ascii	"@8\n" "END\n"
HBNG_unpaired_annot:
	.ascii	"@0\n" "X0 <- M[<X1> .. +8]\n"
	.ascii	"@4\n" "END\n"
HBNG_gap_annot:
	.ascii	"@0\n"
	.ascii	"@8\n" "END\n"
HBNG_x18_annot:
	.ascii	"@0\n"
	.ascii	"@4\n" "END\n"
HBNG_syntax_annot:
	.ascii	"@0\n" "X0 := 1\n" "END\n"

	.section .hbngbbt,"a",@progbits
	.xword	HBNG_missing_send, HBNG_missing_send_annot
	.xword	HBNG_unpaired, HBNG_unpaired_annot
	.xword	HBNG_gap, HBNG_gap_annot
	.xword	HBNG_x18, HBNG_x18_annot
	.xword	HBNG_syntax, HBNG_syntax_annot
