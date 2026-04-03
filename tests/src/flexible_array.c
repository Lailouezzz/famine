// Test 52: Flexible array member
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct String {
    size_t len;
    char data[];
};

int main(void) {
    const char *text = "Flexible array!";
    size_t len = strlen(text);

    struct String *s = malloc(sizeof(struct String) + len + 1);
    s->len = len;
    strcpy(s->data, text);

    printf("len: %zu, data: %s\n", s->len, s->data);
    free(s);
    return 0;
}
