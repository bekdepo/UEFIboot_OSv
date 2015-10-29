#define ADDR_CMDLINE 0x7e00
#define ADDR_TARGET 0x200000
#define ADDR_MB_INFO 0x1000
#define ADDR_E820DATA 0x1100
#define ADDR_STACK 0x1200

#define ENTRY_ADDR 0x000000000021022e

# loader2((VOID *)Kernel, (VOID *)e820data_entry, (VOID *)Cmdline);


addr_entry = 0x000000000021022e

addr_cmdline = 0x7e00
addr_target = 0x200000
addr_mb_info = 0x1000
addr_e820data = 0x1100
addr_stack = 0x1200

# rcx: Kernel
# rdx: e820data_entry
# r8 : Cmdline

boot_uefi:
	# kernel size(byte) to r13 
	movq	(%rcx), %r13
	# e820data size to r14
	movq	(%rdx), %r14
	# Cmdline size to r15
	movq	(%r8), %r15

	# increment address(64bit) 
	addq	$8, %rcx
	addq	$8, %rdx
	addq	$8, %r8


	# copy kernel to addr_target
	shrq	$3, %r13
	incq	%r13
	xorq	%r11, %r11	# r11: loop counter
copy_kernel:
	# r10 <- (rcx + r11 * 8)
	movq	(%rcx, %r11, 8), %r10
	movq	%r10, addr_target(, %r11, 8)
	incq	%r11
	cmpq	%r13, %r11
	jb	copy_kernel


	# copy e820data to addr_e820data
	shrq	$3, %r14
	incq	%r14
	xorq	%r11, %r11	# r11: loop counter
copy_e820data:
	# r10 <- (rdx + r11 * 8)
	movq	(%rdx, %r11, 8), %r10
	movq	%r10, addr_e820data(, %r11, 8)
	incq	%r11
	cmpq	%r14, %r11
	jb	copy_e820data


	# copy cmdline to addr_cmdline
	shrq	$3, %r15
	incq	%r15
	xorq	%r11, %r11	# r11: loop counter
copy_cmdline:
	# r10 <- (rdx + r11 * 8)
	movq	(%r8, %r11, 8), %r10
	movq	%r10, addr_cmdline(, %r11, 8)
	incq	%r11
	cmpq	%r15, %r11
	jb	copy_cmdline

	# make mb_info
	# zero clear 88byte(8 * 11byte)
	xorq	%r11, %r11
clear_mbinfo:
	movq	$0, addr_mb_info(, %r11, 8)
	incq	%r11
	cmpq	$11, %r11
	jb clear_mbinfo

	# set mb_info.cmdline(offset 16byte)
	movq	$addr_mb_info, %r10
	movq	$addr_cmdline, %rax
	movl	%eax, 16(,%r10,1)
	# set mb_info.mmap_length(offset 48byte)
	movq 	%r14, %rax
	movl	%eax, 44(,%r10,1)
	# set mb_info.mmap_addr(offset 48byte)
	movl	$addr_e820data, %eax
	movl	%eax, 48(,%r10,1)


	# set mb_info addr to rbx
	movq	$addr_mb_info, %rbx

	# set addr_target_ to rax
	movq	$addr_target, %rax

	# set addr_target to rbp
	movq	$addr_target, %rbp
	# set addr_stack to rsp
	movq	$addr_stack,	%rsp

	# set start64 to rip
	mov $addr_entry, %rcx
	jmp	*%rcx