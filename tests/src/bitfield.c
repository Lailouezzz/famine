// Test 49: Bit fields
#include <stdio.h>

struct Flags {
    unsigned int read : 1;
    unsigned int write : 1;
    unsigned int exec : 1;
    unsigned int reserved : 5;
    unsigned int value : 8;
};

int main(void) {
    struct Flags f = {0};
    f.read = 1;
    f.write = 1;
    f.exec = 0;
    f.value = 42;

    printf("read: %u, write: %u, exec: %u\n", f.read, f.write, f.exec);
    printf("value: %u\n", f.value);
    printf("sizeof: %zu\n", sizeof(f));
    return 0;
}
