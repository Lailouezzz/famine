// Test 65: Data section in assembly (64-bit)
.section .data
counter:
    .quad 0
buffer:
    .space 64

.section .text
.globl _start

_start:
    // Increment counter
    lea     counter(%rip), %rax
    incq    (%rax)

    // Write to buffer
    lea     buffer(%rip), %rdi
    movb    $'O', (%rdi)
    movb    $'K', 1(%rdi)
    movb    $'\n', 2(%rdi)

    // Print buffer
    mov     $1, %rax
    mov     $1, %rdi
    lea     buffer(%rip), %rsi
    mov     $3, %rdx
    syscall

    // exit(0)
    mov     $60, %rax
    xor     %rdi, %rdi
    syscall
