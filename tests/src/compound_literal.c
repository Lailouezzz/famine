// Test 51: Compound literals
#include <stdio.h>

struct Point { int x, y; };

void print_point(struct Point p) {
    printf("(%d, %d)\n", p.x, p.y);
}

int main(void) {
    print_point((struct Point){10, 20});
    print_point((struct Point){.y = 5, .x = 3});

    int *arr = (int[]){1, 2, 3, 4, 5};
    for (int i = 0; i < 5; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
    return 0;
}
