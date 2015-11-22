addr_entry = 0x000000000021022e

addr_cmdline = 0x7e00
addr_target = 0x200000
addr_mb_info = 0x1000
addr_e820data = 0x1100
addr_stack = 0x1200

.global boot_osv
boot_osv:
	; # set mb_info addr to rbx
	movq	$addr_mb_info, %rbx

	; # set addr_target to rbp
	movq	$addr_target, %rbp
	; # set addr_stack to rsp
	movq	$addr_stack, %rsp


jump_start64:
	; # set start64 to rip
	mov $addr_entry, %rcx
	jmp	*%rcx