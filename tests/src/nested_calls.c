// Test 19: Nested function calls
#include <stdio.h>

int level4(int x) { return x * 2; }
int level3(int x) { return level4(x) + 1; }
int level2(int x) { return level3(x) * 3; }
int level1(int x) { return level2(x) - 5; }

int main(void) {
    int result = level1(10);
    printf("Result: %d\n", result);
    // 10 -> 20 -> 21 -> 63 -> 58
    return 0;
}
