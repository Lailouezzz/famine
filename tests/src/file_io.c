// Test 31: File I/O
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/woody_test.txt", "w");
    if (!f) return 1;

    fprintf(f, "Test content\n");
    fclose(f);

    f = fopen("/tmp/woody_test.txt", "r");
    if (!f) return 1;

    char buf[100];
    if (fgets(buf, sizeof(buf), f)) {
        printf("Read: %s", buf);
    }
    fclose(f);

    remove("/tmp/woody_test.txt");
    return 0;
}
