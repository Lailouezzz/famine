// Test 45: Large code section
#include <stdio.h>

#define FUNC(n) int func##n(int x) { return x + n; }
#define CALL(n) sum += func##n(i);

FUNC(1) FUNC(2) FUNC(3) FUNC(4) FUNC(5)
FUNC(6) FUNC(7) FUNC(8) FUNC(9) FUNC(10)
FUNC(11) FUNC(12) FUNC(13) FUNC(14) FUNC(15)
FUNC(16) FUNC(17) FUNC(18) FUNC(19) FUNC(20)
FUNC(21) FUNC(22) FUNC(23) FUNC(24) FUNC(25)
FUNC(26) FUNC(27) FUNC(28) FUNC(29) FUNC(30)
FUNC(31) FUNC(32) FUNC(33) FUNC(34) FUNC(35)
FUNC(36) FUNC(37) FUNC(38) FUNC(39) FUNC(40)

int main(void) {
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        CALL(1) CALL(2) CALL(3) CALL(4) CALL(5)
        CALL(6) CALL(7) CALL(8) CALL(9) CALL(10)
        CALL(11) CALL(12) CALL(13) CALL(14) CALL(15)
        CALL(16) CALL(17) CALL(18) CALL(19) CALL(20)
        CALL(21) CALL(22) CALL(23) CALL(24) CALL(25)
        CALL(26) CALL(27) CALL(28) CALL(29) CALL(30)
        CALL(31) CALL(32) CALL(33) CALL(34) CALL(35)
        CALL(36) CALL(37) CALL(38) CALL(39) CALL(40)
    }
    printf("Sum: %d\n", sum);
    return 0;
}
