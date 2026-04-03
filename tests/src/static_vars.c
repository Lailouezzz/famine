// Test 17: Static variables - test function static vars (more reliable)
#include <stdio.h>

int counter(void) {
    static int count = 0;
    return ++count;
}

int main(void) {
    // Test that static local variables work correctly
    int results[5];
    for (int i = 0; i < 5; i++) {
        results[i] = counter();
    }

    // Verify sequence is 1, 2, 3, 4, 5
    int ok = 1;
    for (int i = 0; i < 5; i++) {
        if (results[i] != i + 1) {
            printf("Counter mismatch at %d: got %d, expected %d\n", i, results[i], i + 1);
            ok = 0;
        }
    }

    if (ok) {
        printf("Static variables: OK\n");
        printf("Final counter: %d\n", results[4]);
    }
    return ok ? 0 : 1;
}
