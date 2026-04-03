// Test 64: Loop in assembly (64-bit)
.section .text
.globl _start

_start:
    mov     $5, %rcx        // counter

.loop:
    push    %rcx

    mov     $1, %rax
    mov     $1, %rdi
    lea     msg(%rip), %rsi
    mov     $6, %rdx
    syscall

    pop     %rcx
    dec     %rcx
    jnz     .loop

    // exit(0)
    mov     $60, %rax
    xor     %rdi, %rdi
    syscall

.section .rodata
msg:
    .ascii "Loop\n"
