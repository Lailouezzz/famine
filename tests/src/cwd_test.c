// Test 35: Working directory - just verify getcwd works
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd))) {
        // Don't print the actual path as it varies
        // Just verify we got a valid path (starts with /)
        if (cwd[0] == '/') {
            printf("getcwd: OK (got valid path)\n");
            return 0;
        }
    }
    printf("getcwd: FAIL\n");
    return 1;
}
