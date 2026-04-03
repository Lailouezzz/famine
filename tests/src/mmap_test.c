// Test 36: Memory mapping
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

int main(void) {
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    strcpy(ptr, "mmap works!\n");
    printf("%s", (char*)ptr);

    munmap(ptr, 4096);
    return 0;
}
