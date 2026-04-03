// Test 37: Fork (simple)
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        printf("Child process (pid=%d)\n", getpid());
        _exit(42);
    } else {
        int status;
        waitpid(pid, &status, 0);
        printf("Parent: child exited with %d\n", WEXITSTATUS(status));
    }
    return 0;
}
