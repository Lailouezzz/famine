// Test 21: Constructor and destructor attributes
#include <stdio.h>

__attribute__((constructor))
void init_func(void) {
    printf("Constructor called\n");
}

__attribute__((destructor))
void fini_func(void) {
    printf("Destructor called\n");
}

int main(void) {
    printf("Main function\n");
    return 0;
}
