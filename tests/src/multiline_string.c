// Test 60: Multiline strings
#include <stdio.h>

const char *poem =
    "Roses are red,\n"
    "Violets are blue,\n"
    "Testing this packer,\n"
    "Is what I do!\n";

int main(void) {
    printf("%s", poem);
    return 0;
}
