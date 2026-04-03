// Test 42: bsearch
#include <stdio.h>
#include <stdlib.h>

int compare(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

int main(void) {
    int arr[] = {1, 3, 5, 7, 9, 11, 13, 15};
    size_t n = sizeof(arr) / sizeof(arr[0]);

    int key = 7;
    int *result = bsearch(&key, arr, n, sizeof(int), compare);

    if (result) {
        printf("Found %d at index %ld\n", *result, result - arr);
    } else {
        printf("Not found\n");
    }
    return 0;
}
