// Test 26: Packed structures
#include <stdio.h>
#include <stdint.h>

struct __attribute__((packed)) PackedStruct {
    uint8_t a;
    uint32_t b;
    uint16_t c;
    uint8_t d;
};

struct NormalStruct {
    uint8_t a;
    uint32_t b;
    uint16_t c;
    uint8_t d;
};

int main(void) {
    printf("Packed size: %zu\n", sizeof(struct PackedStruct));
    printf("Normal size: %zu\n", sizeof(struct NormalStruct));

    struct PackedStruct p = {1, 0x12345678, 0xABCD, 2};
    printf("Values: %u %u %u %u\n", p.a, p.b, p.c, p.d);
    return 0;
}
