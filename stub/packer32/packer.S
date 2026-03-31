.intel_syntax noprefix

.global _start
.extern packer_main
.extern packer_begin

.section .packer.init

_start:
	mov eax, esp
	push 0 # ret placeholder
	pushad
	pushfd

	sub esp, 4
	push eax
	call packer_main
	add esp, 8
	mov [esp + 36], eax

	call .L_get_pc1
.L_get_pc1:
	pop ecx
	add ecx, (msg - .L_get_pc1)
	mov eax, 4 # SYS_WRITE
	mov ebx, 1 # fd stdout
	mov edx, 14 # size
	int 0x80

	popfd
	popad
	ret

.section .data
entry_point:
	.long 0

.section .rodata
msg:
	.ascii "....WOODY....\n"
