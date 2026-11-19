// A replay fixture: a signal handler that stores the secret into the saved x19 of its ucontext.
// main reads the source file (argv[1]) into secret, installs the handler for SIGUSR1, clears
// x19 and sends itself the signal; once returned, it writes x19 to stdout. The kernel reloads x19
// from the frame, so the write leaks the secret.
	.text
	.globl	_start
_start:
	mov	x16, sp
	adrp	x17, __hbng_chan
	stp	x29, x16, [x17]
	b	main
main:
	ldr	x1, [sp, #16]
	mov	x0, #-100
	mov	x2, #0
	mov	x8, #56
	svc	#0
	adrp	x9, __hbng_chan
	adrp	x1, secret
	add	x1, x1, :lo12:secret
	str	x1, [x9]
	mov	x2, #8
	mov	x8, #63
	svc	#0
	adrp	x1, act
	add	x1, x1, :lo12:act
	mov	x0, #10
	mov	x2, #0
	mov	x3, #8
	mov	x8, #134
	svc	#0
	mov	x19, #0
	mov	x8, #172
	svc	#0
	mov	x1, #10
	mov	x8, #129
	svc	#0
	adrp	x1, out
	add	x1, x1, :lo12:out
	str	x1, [x9]
	str	x19, [x1]
	mov	x0, #1
	mov	x2, #8
	mov	x8, #64
	svc	#0
	mov	x0, #0
	mov	x8, #94
	svc	#0
handler:
	adrp	x9, __hbng_chan
	str	x2, [x9]
	adrp	x10, secret
	add	x10, x10, :lo12:secret
	str	x10, [x9]
	ldr	x11, [x10]
	str	x11, [x2, #336]
	ret
restorer:
	mov	x8, #139
	svc	#0

	.data
	.p2align 3
act:	// the kernel's struct sigaction: SA_SIGINFO | SA_RESTORER
	.quad	handler, 0x04000004, restorer, 0
secret:
	.quad	0
out:
	.quad	0

	// The channel page, linked at a fixed address (build.sh: chan)
	.section .hbngchan,"aw",@nobits
	.globl	__hbng_chan
__hbng_chan:
	.zero	0x10000

	.section .hbngannot,"a",@progbits
HBNG_main_annot:
	.ascii	"@0\n" "X1 <- M[<SP> + 16 .. +8]\n"
	.ascii	"@4\n" "X0 <- 0\n"
	.ascii	"@8\n" "X2 <- 0\n"
	.ascii	"@12\n" "X8 <- 0\n"
	.ascii	"@16\n" "svc\n"
	.ascii	"@20\n" "X9 <- 0\n"
	.ascii	"@24\n" "X1 <- 0\n"
	.ascii	"@28\n" "X1 <- X1\n"
	.ascii	"@32\n" "send X1\n"
	.ascii	"@36\n" "X2 <- 0\n"
	.ascii	"@40\n" "X8 <- 0\n"
	.ascii	"@44\n" "svc\n"
	.ascii	"@48\n" "X1 <- 0\n"
	.ascii	"@52\n" "X1 <- X1\n"
	.ascii	"@56\n" "X0 <- 0\n"
	.ascii	"@60\n" "X2 <- 0\n"
	.ascii	"@64\n" "X3 <- 0\n"
	.ascii	"@68\n" "X8 <- 0\n"
	.ascii	"@72\n" "svc\n"
	.ascii	"@76\n" "X19 <- 0\n"
	.ascii	"@80\n" "X8 <- 0\n"
	.ascii	"@84\n" "svc\n"
	.ascii	"@88\n" "X1 <- 0\n"
	.ascii	"@92\n" "X8 <- 0\n"
	.ascii	"@96\n" "svc\n"
	.ascii	"@100\n" "X1 <- 0\n"
	.ascii	"@104\n" "X1 <- X1\n"
	.ascii	"@108\n" "send X1\n"
	.ascii	"@112\n" "M[<X1> .. +8] <- X19\n"
	.ascii	"@116\n" "X0 <- 0\n"
	.ascii	"@120\n" "X2 <- 0\n"
	.ascii	"@124\n" "X8 <- 0\n"
	.ascii	"@128\n" "svc\n"
	.ascii	"@132\n" "X0 <- 0\n"
	.ascii	"@136\n" "X8 <- 0\n"
	.ascii	"@140\n" "svc\n"
	.ascii	"END\n"
HBNG_handler_annot:
	.ascii	"@0\n" "X9 <- 0\n"
	.ascii	"@4\n" "send X2\n"
	.ascii	"@8\n" "X10 <- 0\n"
	.ascii	"@12\n" "X10 <- X10\n"
	.ascii	"@16\n" "send X10\n"
	.ascii	"@20\n" "X11 <- M[<X10> .. +8]\n"
	.ascii	"@24\n" "M[<X2> + 336 .. +8] <- X11\n"
	.ascii	"@28\n"
	.ascii	"END\n"

	// Per block: its address and annotations, its instructions, its sends and the index of each
	// send's instruction
	.section .hbngbbt,"a",@progbits
	.xword	main, HBNG_main_annot
	.hword	36, 2, 8, 27
	.p2align 3
	.xword	handler, HBNG_handler_annot
	.hword	8, 2, 1, 4
	.p2align 3
