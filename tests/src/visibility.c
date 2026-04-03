// Test 24: Symbol visibility
#include <stdio.h>

__attribute__((visibility("default")))
int public_func(void) { return 1; }

__attribute__((visibility("hidden")))
int hidden_func(void) { return 2; }

int main(void) {
    printf("Public: %d\n", public_func());
    printf("Hidden: %d\n", hidden_func());
    return 0;
}
