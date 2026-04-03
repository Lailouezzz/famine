// Test 28: Inline assembly
#include <stdio.h>

int main(void) {
    int result;

#ifdef __x86_64__
    __asm__ volatile (
        "mov $42, %%eax\n"
        "add $8, %%eax\n"
        : "=a" (result)
    );
#else
    __asm__ volatile (
        "mov $42, %%eax\n"
        "add $8, %%eax\n"
        : "=a" (result)
    );
#endif

    printf("Inline asm result: %d\n", result);
    return 0;
}
