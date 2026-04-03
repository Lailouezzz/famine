// Test 7: Command line arguments - don't print argv[0] as it varies
#include <stdio.h>

int main(int argc, char **argv) {
    printf("argc: %d\n", argc);
    // Skip argv[0] as it changes between original and packed binary
    for (int i = 1; i < argc; i++) {
        printf("argv[%d]: %s\n", i, argv[i]);
    }
    // Return based on argc to test exit codes still work
    return (argc >= 1) ? 0 : 1;
}
