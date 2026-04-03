// Test 29: setjmp/longjmp
#include <stdio.h>
#include <setjmp.h>

jmp_buf env;

void do_jump(int val) {
    printf("About to longjmp with %d\n", val);
    longjmp(env, val);
}

int main(void) {
    int ret = setjmp(env);
    if (ret == 0) {
        printf("Initial setjmp\n");
        do_jump(42);
    } else {
        printf("Returned from longjmp with %d\n", ret);
    }
    return 0;
}
