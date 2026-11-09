// A block in the annotation format from before the DSL.
	.text
	.globl	_start
_start:
HBNG_load:
	str	x0, [x18]
	ldr	x0, [x0]
	ret

	.section .hbngannot,"a",@progbits
HBNG_load_annot:
	.ascii	"X0 <- [<X0> + 8*Imm(0)]_64\n"
	.ascii	"END\n"

	.section .hbngbbt,"a",@progbits
	.xword	HBNG_load, HBNG_load_annot
