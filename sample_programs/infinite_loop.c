#include <stdio.h>
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
}

int main() {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    printf("Infinite loop test program\n");
    printf("Process ID: %d\n", getpid());
    printf("This program will run until terminated\n");
    printf("Use Stop Process button to terminate\n");
    
    int counter = 0;
    while (keep_running) {
        counter++;
        if (counter % 1000000 == 0) {
            printf("Running... iteration %d\n", counter);
        }
        usleep(1000); /* Small delay to prevent 100% CPU */
    }
    
    printf("Program terminated after %d iterations\n", counter);
    return 0;
}

