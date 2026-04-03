// Test 6: Read-only data section
#include <stdio.h>

const char rodata_msg[] = "This is in .rodata\n";
const int ro_numbers[] = {100, 200, 300};

int main(void) {
    printf("%s", rodata_msg);
    printf("First: %d, Last: %d\n", ro_numbers[0], ro_numbers[2]);
    return 0;
}
