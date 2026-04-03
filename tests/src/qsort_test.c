// Test 41: qsort with callback
#include <stdio.h>
#include <stdlib.h>

int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

int main(void) {
    int arr[] = {64, 25, 12, 22, 11, 90, 42};
    size_t n = sizeof(arr) / sizeof(arr[0]);

    printf("Before: ");
    for (size_t i = 0; i < n; i++) printf("%d ", arr[i]);
    printf("\n");

    qsort(arr, n, sizeof(int), compare);

    printf("After: ");
    for (size_t i = 0; i < n; i++) printf("%d ", arr[i]);
    printf("\n");

    return 0;
}
