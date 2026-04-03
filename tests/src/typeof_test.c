// Test 54: typeof (GCC extension)
#include <stdio.h>

#define max(a, b) ({ \
    typeof(a) _a = (a); \
    typeof(b) _b = (b); \
    _a > _b ? _a : _b; \
})

int main(void) {
    int x = 5, y = 10;
    printf("max(%d, %d) = %d\n", x, y, max(x, y));

    double a = 3.14, b = 2.71;
    printf("max(%.2f, %.2f) = %.2f\n", a, b, max(a, b));

    return 0;
}
