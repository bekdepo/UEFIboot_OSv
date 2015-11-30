	.globl boot_osv
boot_osv:
	/* mb_info */
	movq %rdx, %rbx
	/* target */
	movq %r8, %rbp
	/* stack */
	movq $0x1200, %rsp

	jmp *%rcx
