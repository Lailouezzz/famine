// Test 55: GCC builtins
#include <stdio.h>

int main(void) {
    unsigned int x = 0x12345678;

    printf("popcount(0x%X) = %d\n", x, __builtin_popcount(x));
    printf("clz(0x%X) = %d\n", x, __builtin_clz(x));
    printf("ctz(16) = %d\n", __builtin_ctz(16));
    printf("bswap32(0x%X) = 0x%X\n", x, __builtin_bswap32(x));

    if (__builtin_expect(x != 0, 1)) {
        printf("Expected branch\n");
    }

    return 0;
}
