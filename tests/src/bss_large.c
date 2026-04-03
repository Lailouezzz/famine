// Test 4: Large BSS section
#include <stdio.h>
#include <string.h>

char large_buffer[1024 * 1024];  // 1MB BSS

int main(void) {
    memset(large_buffer, 'A', 100);
    large_buffer[100] = '\0';
    printf("Large BSS test: %s\n", large_buffer);
    return 0;
}
