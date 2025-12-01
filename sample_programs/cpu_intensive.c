#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main() {
    printf("CPU-intensive test program started\n");
    printf("Process ID: %d\n", getpid());
    
    clock_t start = clock();
    volatile long long count = 0;
    
    /* Run for approximately 10 seconds */
    while ((clock() - start) / CLOCKS_PER_SEC < 10) {
        count++;
        if (count % 10000000 == 0) {
            printf("Iterations: %lld\n", count);
        }
    }
    
    printf("CPU-intensive test completed. Total iterations: %lld\n", count);
    return 0;
}

