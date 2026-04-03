// Test 14: Dynamic memory allocation
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *str = malloc(100);
    if (!str) return 1;

    strcpy(str, "Dynamic allocation works!\n");
    printf("%s", str);

    int *arr = calloc(10, sizeof(int));
    if (!arr) { free(str); return 1; }

    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    printf("Squares: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");

    free(str);
    free(arr);
    return 0;
}
