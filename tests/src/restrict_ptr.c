// Test 53: restrict pointers
#include <stdio.h>

void add_arrays(int * restrict dst, const int * restrict a,
                const int * restrict b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = a[i] + b[i];
    }
}

int main(void) {
    int a[] = {1, 2, 3, 4, 5};
    int b[] = {10, 20, 30, 40, 50};
    int c[5];

    add_arrays(c, a, b, 5);

    for (int i = 0; i < 5; i++) {
        printf("%d ", c[i]);
    }
    printf("\n");
    return 0;
}
