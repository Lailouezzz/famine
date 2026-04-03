// Test 5: Initialized data section
#include <stdio.h>

char message[] = "This is in .data section\n";
int numbers[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

int main(void) {
    printf("%s", message);
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += numbers[i];
    }
    printf("Sum: %d\n", sum);
    return 0;
}
