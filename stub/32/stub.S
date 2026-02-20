.intel_syntax noprefix

.global _start
.extern stub_main
.extern stub_begin

.section .stub.init

_start:
	mov eax, esp
	push 0 # ret placeholder
	pushad
	pushfd

	sub esp, 4
	push eax
	call stub_main
	add esp, 8
	mov [esp + 36], eax

	popfd
	popad
	ret

.section .data
entry_point:
	.long 0
