// Test 18: Switch statement (jump table)
#include <stdio.h>

const char *day_name(int day) {
    switch (day) {
        case 0: return "Sunday";
        case 1: return "Monday";
        case 2: return "Tuesday";
        case 3: return "Wednesday";
        case 4: return "Thursday";
        case 5: return "Friday";
        case 6: return "Saturday";
        default: return "Unknown";
    }
}

int main(void) {
    for (int i = 0; i <= 7; i++) {
        printf("Day %d: %s\n", i, day_name(i));
    }
    return 0;
}
