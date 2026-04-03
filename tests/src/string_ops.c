// Test 15: String operations
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[100];
    const char *s1 = "Hello";
    const char *s2 = "World";

    strcpy(buf, s1);
    strcat(buf, " ");
    strcat(buf, s2);
    printf("Concat: %s\n", buf);
    printf("Length: %zu\n", strlen(buf));
    printf("Compare: %d\n", strcmp(s1, s2));

    char *found = strstr(buf, "Wor");
    printf("Found: %s\n", found ? found : "(null)");

    return 0;
}
