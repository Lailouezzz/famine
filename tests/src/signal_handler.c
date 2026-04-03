// Test 30: Signal handling
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

volatile sig_atomic_t got_signal = 0;

void handler(int sig) {
    (void)sig;
    got_signal = 1;
}

int main(void) {
    signal(SIGUSR1, handler);
    printf("Sending SIGUSR1 to self\n");
    kill(getpid(), SIGUSR1);
    if (got_signal) {
        printf("Signal received!\n");
    }
    return 0;
}
