.intel_syntax noprefix

.macro pushall
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	pushfq
.endm

.macro popall
	popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
.endm

.global _start
.extern packer_main
.extern packer_begin

.section .packer.init

_start:
	mov rdi, rsp
	push 0 # ret placeholder
	pushall
	sub rsp, 8
	call packer_main
	add rsp, 8

	mov [rsp + 128], rax

	mov rax, 1
	mov rdi, 1
	lea rsi, [rip + msg]
	mov rdx, 14
	syscall

	popall
	ret

.section .rodata
msg:
	.ascii "....WOODY....\n"
