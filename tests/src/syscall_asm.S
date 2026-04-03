// Test 62: Direct syscalls (64-bit)
.section .text
.globl _start

_start:
    // getpid()
    mov     $39, %rax       // syscall: getpid
    syscall
    mov     %rax, %r12      // save pid

    // write pid info
    mov     $1, %rax
    mov     $1, %rdi
    lea     msg(%rip), %rsi
    mov     $5, %rdx
    syscall

    // exit(0)
    mov     $60, %rax
    xor     %rdi, %rdi
    syscall

.section .rodata
msg:
    .ascii "PID:\n"
