.globl boot_osv
boot_osv:
#	movq 0x28(%rsp), %r10
#	movq %r9, %r10
	movq %rdx, %rbx # mb_info
	movq %r8, %rbp # target
#	movq %r9, %rsp # stack
	movq $0x1200, %rsp # stack
	jmp *%rcx # jump to start64
