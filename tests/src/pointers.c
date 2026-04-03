// Test 12: Pointer operations
#include <stdio.h>

void swap(int *a, int *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int main(void) {
    int x = 10, y = 20;
    printf("Before: x=%d, y=%d\n", x, y);
    swap(&x, &y);
    printf("After: x=%d, y=%d\n", x, y);

    int arr[] = {1, 2, 3, 4, 5};
    int *p = arr;
    printf("Pointer arithmetic: %d %d %d\n", *p, *(p+2), *(p+4));
    return 0;
}
