// Test 10: Various loop constructs
#include <stdio.h>

int main(void) {
    int sum = 0;

    // for loop
    for (int i = 0; i < 10; i++) {
        sum += i;
    }

    // while loop
    int j = 0;
    while (j < 5) {
        sum += j;
        j++;
    }

    // do-while
    int k = 0;
    do {
        sum += k;
        k++;
    } while (k < 3);

    printf("Sum: %d\n", sum);
    return 0;
}
