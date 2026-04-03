// Test 39: errno handling
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/nonexistent/path/file", O_RDONLY);
    if (fd < 0) {
        printf("errno: %d\n", errno);
        printf("strerror: %s\n", strerror(errno));
        perror("open");
    }
    return 0;
}
