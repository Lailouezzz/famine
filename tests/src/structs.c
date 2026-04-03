// Test 13: Structures
#include <stdio.h>
#include <string.h>

typedef struct {
    char name[32];
    int age;
    float height;
} Person;

Person people[3] = {
    {"Alice", 25, 1.65f},
    {"Bob", 30, 1.80f},
    {"Charlie", 35, 1.75f}
};

int main(void) {
    for (int i = 0; i < 3; i++) {
        printf("%s: age=%d, height=%.2f\n",
               people[i].name, people[i].age, people[i].height);
    }
    return 0;
}
