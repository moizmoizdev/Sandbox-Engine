#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Fork bomb simulation - creates many child processes rapidly */
int main() {
    printf("Fork bomb simulation started\n");
    printf("Process ID: %d\n", getpid());
    printf("Warning: This will create many processes!\n");
    
    pid_t pid;
    int count = 0;
    int max_forks = 50; /* Limited to prevent system crash */
    
    for (int i = 0; i < max_forks; i++) {
        pid = fork();
        
        if (pid < 0) {
            perror("fork failed");
            break;
        } else if (pid == 0) {
            /* Child process - do some work */
            printf("Child process %d created (PID: %d)\n", i, getpid());
            sleep(2);
            exit(0);
        } else {
            /* Parent process */
            count++;
        }
    }
    
    printf("Created %d child processes, waiting for them...\n", count);
    
    /* Wait for all children */
    while (wait(NULL) > 0) {
        /* Wait for all children to finish */
    }
    
    printf("Fork bomb simulation completed\n");
    return 0;
}

