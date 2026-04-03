// Test 48: Unions
#include <stdio.h>
#include <stdint.h>

union Number {
    uint32_t i;
    float f;
    uint8_t bytes[4];
};

int main(void) {
    union Number n;
    n.i = 0x40490FDB;  // float representation of pi

    printf("As int: 0x%X\n", n.i);
    printf("As float: %f\n", n.f);
    printf("Bytes: %02X %02X %02X %02X\n",
           n.bytes[0], n.bytes[1], n.bytes[2], n.bytes[3]);
    return 0;
}
