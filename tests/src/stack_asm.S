// Test 63: Stack operations (64-bit)
.section .text
.globl _start

_start:
    push    %rbp
    mov     %rsp, %rbp
    sub     $16, %rsp

    // Store value on stack
    movq    $42, -8(%rbp)

    // Call function
    call    print_hello

    add     $16, %rsp
    pop     %rbp

    // exit(0)
    mov     $60, %rax
    xor     %rdi, %rdi
    syscall

print_hello:
    push    %rbp
    mov     %rsp, %rbp

    mov     $1, %rax
    mov     $1, %rdi
    lea     msg(%rip), %rsi
    mov     $14, %rdx
    syscall

    pop     %rbp
    ret

.section .rodata
msg:
    .ascii "Stack works!\n"
