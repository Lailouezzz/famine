// Test 8: Environment variables
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *home = getenv("HOME");
    char *user = getenv("USER");
    printf("HOME: %s\n", home ? home : "(null)");
    printf("USER: %s\n", user ? user : "(null)");
    return 0;
}
