addr_entry = 0x000000000021022e

addr_cmdline = 0x7e00
addr_target = 0x200000
addr_mb_info = 0x1000
addr_e820data = 0x1100
addr_stack = 0x1200

#define PG_V	0x001
#define PG_RW	0x002
#define PG_U	0x004
#define PG_PS	0x080
#define PG_VRWPSU (PG_V | PG_RW | PG_PS | PG_U)

#define ADDR_PT4 0x2000
#define ADDR_PT3 0x3000
#define ADDR_PT2 0x4000
#define ADDR_GDTR 0x5000

#define PT4 (ADDR_PT3 | PG_V | PG_RW | PG_U)
#define PT3 (ADDR_PT2 | PG_V | PG_RW | PG_U)

; # rcx: Kernel
; # rdx: e820data_entry
; # r8 : Cmdline

boot_uefi:
	; # kernel size(byte) to r13 
	movq	(%rcx), %r13
	; # e820data size to r14
	movq	(%rdx), %r14
	; # Cmdline size to r15
	movq	(%r8), %r15

	; # increment address(64bit) 
	addq	$8, %rcx
	addq	$8, %rdx
	addq	$8, %r8


	; # copy kernel to addr_target
	shrq	$3, %r13
	incq	%r13
	xorq	%r11, %r11	; # r11: loop counter
copy_kernel:
	; # r10 <- (rcx + r11 * 8)
	movq	(%rcx, %r11, 8), %r10
	movq	%r10, addr_target(, %r11, 8)
	incq	%r11
	cmpq	%r13, %r11
	jb	copy_kernel


	; # copy e820data to addr_e820data
	shrq	$3, %r14
	incq	%r14
	xorq	%r11, %r11	; # r11: loop counter
copy_e820data:
	; # r10 <- (rdx + r11 * 8)
	movq	(%rdx, %r11, 8), %r10
	movq	%r10, addr_e820data(, %r11, 8)
	incq	%r11
	cmpq	%r14, %r11
	jb	copy_e820data


	; # copy cmdline to addr_cmdline
	shrq	$3, %r15
	incq	%r15
	xorq	%r11, %r11	; # r11: loop counter
copy_cmdline:
	; # r10 <- (rdx + r11 * 8)
	movq	(%r8, %r11, 8), %r10
	movq	%r10, addr_cmdline(, %r11, 8)
	incq	%r11
	cmpq	%r15, %r11
	jb	copy_cmdline


	; # copy cmdline to addr_cmdline
 	;# r15 <- sizeof(multiboot_info)
	mov 	$88, %r15
	xorq	%r11, %r11	; # r11: loop counter
copy_mbinfo:
	; # r10 <- (rdx + r11 * 8)
	movq	(%r9, %r11, 8), %r10
	movq	%r10, addr_mb_info(, %r11, 8)
	incq	%r11
	cmpq	%r15, %r11
	jb	copy_mbinfo

	; # make mb_info
	; # zero clear 88byte(8 * 11byte)
# 	xorq	%r11, %r11
# clear_mbinfo:
# 	movq	$0, addr_mb_info(, %r11, 8)
# 	incq	%r11
# 	cmpq	$11, %r11
# 	jb clear_mbinfo

# 	; # set mb_info.cmdline(offset 16byte)
# 	movq	$addr_mb_info, %r10
# 	movq	$addr_cmdline, %rax
# 	movl	%eax, 16(,%r10,1)
# 	; # set mb_info.mmap_length(offset 48byte)
# 	movq 	%r14, %rax
# 	movl	%eax, 44(,%r10,1)
# 	; # set mb_info.mmap_addr(offset 48byte)
# 	movl	$addr_e820data, %eax
# 	movl	%eax, 48(,%r10,1)

# set_pt:
# 	// set counter
# 	xorq	%rcx, %rcx
# set_pt_loop:
# 	// set PT4
# 	movq $PT4, ADDR_PT4(,%rcx, 8)
# 	movq $PT3, ADDR_PT3(,%rcx, 8)
# 	movq $0x200000, %rax
# 	mul %rcx
# 	or $PG_VRWPSU, %rax
# 	movq %rax, ADDR_PT2(,%rcx, 8)
# 	incq %rcx
# 	cmpq	$512, %rcx
# 	jb set_pt_loop

# set_register:
# 	// # set descriptor
# 	// mov		$0x0000209B, %eax
# 	// mov 	%rax, %cs
# 	// mov		$0x00000093, %eax
# 	// mov 	%rax, %ds
# 	// mov 	%rax, %es
# 	// mov 	%rax, %fs
# 	// mov 	%rax, %gs
# 	// mov 	%rax, %ss
# 	// # set tr register
# 	// mov		$0x0000008b, %eax
# 	// mov 	%rax, %tr
# 	// mov		$0x00010000, %eax
# 	// mov 	%rax, %ldtr

	# // set c4,c3,c0
	# mov $0x000007b8, %rax
	# mov %rax, %cr4
	# mov $ADDR_PT4, %rax
	# mov %rax, %cr3
	# mov $0x80010001, %rax
	# mov %rax, %cr0

	# // set gdt
	# xorq %rcx, %rcx
	# movq $0x0, %rax
	# movq %rax, ADDR_GDTR(, %rcx, 8)
	# incq %rcx
	# movq $0x00af9b000000ffff, %rax
	# movq %rax, ADDR_GDTR(, %rcx, 8)
	# incq %rcx
	# movq $0x00cf93000000ffff, %rax
	# movq %rax, ADDR_GDTR(, %rcx, 8)
	# incq %rcx
	# movq $0x00cf9b000000ffff, %rax
	# movq %rax, ADDR_GDTR(, %rcx, 8)

	# // set gdt size
	# xorq %rcx, %rcx
	# mov  $(ADDR_GDTR-16*4), %rax
	# movw $(16*4), (ADDR_GDTR-16*4)(, %rcx, 1)
	# movl $(ADDR_GDTR), (ADDR_GDTR-16*4)(, %rcx, 1)
	# lgdt (ADDR_GDTR-16*4)

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