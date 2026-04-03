// Test 22: Thread-local storage (single threaded test)
#include <stdio.h>

__thread int tls_counter = 0;

void increment(void) {
    tls_counter++;
}

int main(void) {
    printf("Initial: %d\n", tls_counter);
    for (int i = 0; i < 5; i++) {
        increment();
    }
    printf("Final: %d\n", tls_counter);
    return 0;
}
