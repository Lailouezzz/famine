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

	popfd
	popad
	ret

.section .data
entry_point:
	.long 0
