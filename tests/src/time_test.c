// Test 32: Time functions - verify they work without comparing exact values
#include <stdio.h>
#include <time.h>

int main(void) {
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        printf("time() FAIL\n");
        return 1;
    }

    struct tm *tm_info = localtime(&now);
    if (!tm_info) {
        printf("localtime() FAIL\n");
        return 1;
    }

    // Verify year is reasonable (2020-2100)
    int year = tm_info->tm_year + 1900;
    if (year < 2020 || year > 2100) {
        printf("Year out of range: %d\n", year);
        return 1;
    }

    printf("Time functions: OK\n");
    printf("Year: %d\n", year);
    return 0;
}
