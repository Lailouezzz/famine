// Test 38: Pipe
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return 1;
    }

    const char *msg = "Hello through pipe!";
    write(pipefd[1], msg, strlen(msg) + 1);
    close(pipefd[1]);

    char buf[100];
    read(pipefd[0], buf, sizeof(buf));
    close(pipefd[0]);

    printf("Received: %s\n", buf);
    return 0;
}
