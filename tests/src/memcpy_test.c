// Test 43: Memory functions
#include <stdio.h>
#include <string.h>

int main(void) {
    char src[50] = "Hello, memory!";
    char dst[50];

    memcpy(dst, src, strlen(src) + 1);
    printf("memcpy: %s\n", dst);

    memset(dst, 'X', 5);
    printf("memset: %s\n", dst);

    memmove(dst + 2, dst, 5);
    printf("memmove: %s\n", dst);

    printf("memcmp: %d\n", memcmp("abc", "abc", 3));
    printf("memcmp: %d\n", memcmp("abc", "abd", 3));

    return 0;
}
