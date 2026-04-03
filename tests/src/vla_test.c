// Test 50: Variable length arrays
#include <stdio.h>

void print_array(int n, int arr[n]) {
    for (int i = 0; i < n; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main(void) {
    int n = 5;
    int vla[n];

    for (int i = 0; i < n; i++) {
        vla[i] = i * i;
    }

    printf("VLA contents: ");
    print_array(n, vla);
    return 0;
}
