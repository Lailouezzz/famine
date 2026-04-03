// Test 59: Large local arrays (stack probe)
#include <stdio.h>
#include <string.h>

int main(void) {
    char large_stack[65536];  // 64KB on stack
    memset(large_stack, 'A', sizeof(large_stack) - 1);
    large_stack[sizeof(large_stack) - 1] = '\0';

    printf("Stack array size: %zu\n", sizeof(large_stack));
    printf("First 10 chars: %.10s\n", large_stack);
    return 0;
}
