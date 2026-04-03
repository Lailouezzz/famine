// Test 2: Various exit codes
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        return atoi(argv[1]);
    }
    return 42;
}
