// Test 34: Process info - verify calls work, don't print actual values
#include <stdio.h>
#include <unistd.h>

int main(void) {
    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    gid_t gid = getgid();

    // Just verify they return reasonable values
    int ok = 1;
    if (pid <= 0) { printf("getpid FAIL\n"); ok = 0; }
    if (ppid <= 0) { printf("getppid FAIL\n"); ok = 0; }
    // uid and gid can be 0 (root), so just check they were called

    if (ok) {
        printf("Process info: OK\n");
        printf("UID: %d, GID: %d\n", uid, gid);  // These are stable
    }
    return ok ? 0 : 1;
}
