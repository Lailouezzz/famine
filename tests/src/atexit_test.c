// Test 40: atexit handlers
#include <stdio.h>
#include <stdlib.h>

void cleanup1(void) { printf("Cleanup 1\n"); }
void cleanup2(void) { printf("Cleanup 2\n"); }
void cleanup3(void) { printf("Cleanup 3\n"); }

int main(void) {
    atexit(cleanup1);
    atexit(cleanup2);
    atexit(cleanup3);
    printf("Main done, exiting...\n");
    return 0;
}
