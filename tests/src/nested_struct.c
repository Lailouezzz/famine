// Test 47: Nested structures
#include <stdio.h>

struct Inner {
    int x;
    int y;
};

struct Outer {
    struct Inner a;
    struct Inner b;
    int z;
};

int main(void) {
    struct Outer o = {
        .a = {1, 2},
        .b = {3, 4},
        .z = 5
    };

    printf("a: (%d, %d)\n", o.a.x, o.a.y);
    printf("b: (%d, %d)\n", o.b.x, o.b.y);
    printf("z: %d\n", o.z);
    return 0;
}
