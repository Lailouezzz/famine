// Test 9: Recursive function (stack usage)
#include <stdio.h>

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main(void) {
    printf("fib(10) = %d\n", fibonacci(10));
    printf("fib(20) = %d\n", fibonacci(20));
    return 0;
}
