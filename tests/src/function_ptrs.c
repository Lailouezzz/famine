// Test 16: Function pointers
#include <stdio.h>

int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int mul(int a, int b) { return a * b; }

typedef int (*op_func)(int, int);

int main(void) {
    op_func ops[] = {add, sub, mul};
    const char *names[] = {"add", "sub", "mul"};

    for (int i = 0; i < 3; i++) {
        printf("%s(10, 3) = %d\n", names[i], ops[i](10, 3));
    }
    return 0;
}
