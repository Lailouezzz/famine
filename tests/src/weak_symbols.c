// Test 23: Weak symbols
#include <stdio.h>

__attribute__((weak))
int weak_func(void) {
    return 42;
}

int main(void) {
    if (weak_func) {
        printf("Weak func exists: %d\n", weak_func());
    } else {
        printf("Weak func not available\n");
    }
    return 0;
}
