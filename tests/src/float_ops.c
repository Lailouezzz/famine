// Test 33: Floating point operations
#include <stdio.h>
#include <math.h>

int main(void) {
    double a = 3.14159;
    double b = 2.71828;

    printf("a + b = %.5f\n", a + b);
    printf("a * b = %.5f\n", a * b);
    printf("a / b = %.5f\n", a / b);
    printf("sqrt(a) = %.5f\n", sqrt(a));
    printf("sin(a) = %.5f\n", sin(a));
    printf("cos(a) = %.5f\n", cos(a));
    printf("pow(a, 2) = %.5f\n", pow(a, 2));

    return 0;
}
