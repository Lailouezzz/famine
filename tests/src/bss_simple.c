// Test 3: Simple BSS usage
#include <stdio.h>

char buffer[1024];  // BSS - uninitialized

int main(void) {
    buffer[0] = 'H';
    buffer[1] = 'i';
    buffer[2] = '\n';
    buffer[3] = '\0';
    printf("%s", buffer);
    return 0;
}
