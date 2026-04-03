// Test 56: SIMD vectors (GCC extension)
#include <stdio.h>

typedef int v4si __attribute__((vector_size(16)));

int main(void) {
    v4si a = {1, 2, 3, 4};
    v4si b = {10, 20, 30, 40};
    v4si c = a + b;

    printf("SIMD result: %d %d %d %d\n", c[0], c[1], c[2], c[3]);
    return 0;
}
