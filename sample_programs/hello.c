#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Hello from sandboxed process!\n");
    printf("Process ID: %d\n", getpid());
    printf("Parent Process ID: %d\n", getppid());
    
    /* Run for a few seconds to test monitoring */
    for (int i = 0; i < 5; i++) {
        printf("Running... %d/5\n", i + 1);
        sleep(1);
    }
    
    printf("Program completed successfully!\n");
    return 0;
}

