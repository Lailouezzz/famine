// Test 58: Various relocations - don't print addresses
#include <stdio.h>

int global_var = 100;
static int static_var = 200;
extern int printf(const char *, ...);

int get_global(void) { return global_var; }
int get_static(void) { return static_var; }

int main(void) {
    printf("global: %d\n", get_global());
    printf("static: %d\n", get_static());

    int *p = &global_var;
    *p = 999;
    printf("modified global: %d\n", global_var);

    // Verify values are correct
    int ok = (get_static() == 200) && (global_var == 999);
    return ok ? 0 : 1;
}
