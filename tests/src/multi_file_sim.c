// Test 20: Simulating multi-file with functions (not relying on global init values)
#include <stdio.h>

// Use functions instead of pre-initialized globals
int external_func(int x) { return x * x; }

int get_magic(void) {
    return 42;
}

int main(void) {
    int magic = get_magic();
    int squared = external_func(5);

    printf("Magic: %d\n", magic);
    printf("Squared(5): %d\n", squared);

    int ok = (magic == 42) && (squared == 25);
    if (ok) {
        printf("Multi-file simulation: OK\n");
    }
    return ok ? 0 : 1;
}
