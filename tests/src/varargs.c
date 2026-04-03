// Test 27: Variadic functions
#include <stdio.h>
#include <stdarg.h>

int sum(int count, ...) {
    va_list args;
    va_start(args, count);

    int total = 0;
    for (int i = 0; i < count; i++) {
        total += va_arg(args, int);
    }

    va_end(args);
    return total;
}

int main(void) {
    printf("sum(3, 1,2,3) = %d\n", sum(3, 1, 2, 3));
    printf("sum(5, 10,20,30,40,50) = %d\n", sum(5, 10, 20, 30, 40, 50));
    return 0;
}
