// Test 25: Aligned data - only check alignment, not addresses
#include <stdio.h>
#include <stdint.h>

__attribute__((aligned(64)))
int aligned_array[16];

__attribute__((aligned(4096)))
char page_aligned[4096];

int main(void) {
    // Only check that alignment is correct, not the actual addresses
    int align64_ok = ((uintptr_t)aligned_array % 64) == 0;
    int align4096_ok = ((uintptr_t)page_aligned % 4096) == 0;

    printf("64-byte alignment: %s\n", align64_ok ? "OK" : "FAIL");
    printf("4096-byte alignment: %s\n", align4096_ok ? "OK" : "FAIL");

    return (align64_ok && align4096_ok) ? 0 : 1;
}
