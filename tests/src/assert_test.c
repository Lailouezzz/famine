// Test 44: Assert (should pass)
#include <stdio.h>
#include <assert.h>

int main(void) {
    int x = 5;
    assert(x == 5);
    assert(x > 0);
    assert(x < 10);
    printf("All assertions passed\n");
    return 0;
}
