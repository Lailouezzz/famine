// Test 61: Minimal assembly program (64-bit)
.section .text
.globl _start

_start:
    // write(1, msg, 13)
    mov     $1, %rax        // syscall: write
    mov     $1, %rdi        // fd: stdout
    lea     msg(%rip), %rsi // buf
    mov     $13, %rdx       // count
    syscall

    // exit(0)
    mov     $60, %rax       // syscall: exit
    xor     %rdi, %rdi      // status: 0
    syscall

.section .rodata
msg:
    .ascii "Hello, ASM!\n"
