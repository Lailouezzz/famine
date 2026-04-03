// Test 46: Computed goto (GCC extension)
#include <stdio.h>

int main(void) {
    void *labels[] = {&&L1, &&L2, &&L3, &&L4, &&END};
    int idx = 0;

L1: printf("Label 1\n"); idx++; goto *labels[idx];
L2: printf("Label 2\n"); idx++; goto *labels[idx];
L3: printf("Label 3\n"); idx++; goto *labels[idx];
L4: printf("Label 4\n"); idx++; goto *labels[idx];
END:
    printf("Done\n");
    return 0;
}
