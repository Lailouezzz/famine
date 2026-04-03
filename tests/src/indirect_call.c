// Test 57: Indirect function calls through GOT/PLT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    // These will go through PLT
    void *p = malloc(100);
    memset(p, 0, 100);
    sprintf(p, "Indirect call test: %d\n", 42);
    printf("%s", (char*)p);
    free(p);
    return 0;
}
