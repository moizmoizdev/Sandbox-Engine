#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>

volatile int keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
    printf("\nReceived signal %d, stopping resource exhaustion...\n", sig);
}

/* Resource exhaustion - combines CPU, memory, and file descriptors */
int main() {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    printf("Resource exhaustion attack started\n");
    printf("Process ID: %d\n", getpid());
    
    /* Allocate memory */
    printf("Allocating memory...\n");
    void *mem_blocks[100];
    int mem_count = 0;
    
    for (int i = 0; i < 100 && keep_running; i++) {
        mem_blocks[i] = malloc(5 * 1024 * 1024); /* 5 MB each */
        if (mem_blocks[i]) {
            memset(mem_blocks[i], 0xCC, 5 * 1024 * 1024);
            mem_count++;
        } else {
            break;
        }
    }
    
    printf("Allocated %d memory blocks\n", mem_count);
    
    /* Open file descriptors */
    printf("Opening file descriptors...\n");
    FILE *files[50];
    int file_count = 0;
    char filename[256];
    
    for (int i = 0; i < 50 && keep_running; i++) {
        snprintf(filename, sizeof(filename), "exhaust_fd_%d_%d.tmp", getpid(), i);
        files[i] = fopen(filename, "w");
        if (files[i]) {
            file_count++;
        } else {
            break;
        }
    }
    
    printf("Opened %d file descriptors\n", file_count);
    
    /* CPU intensive loop */
    printf("Starting CPU-intensive loop...\n");
    volatile long long iterations = 0;
    
    while (keep_running) {
        iterations++;
        
        /* Periodically report */
        if (iterations % 100000000 == 0) {
            printf("Running... %lld iterations\n", iterations);
        }
        
        /* Try to open more files periodically */
        if (iterations % 50000000 == 0 && file_count < 50) {
            snprintf(filename, sizeof(filename), "exhaust_fd_%d_%d.tmp", getpid(), file_count);
            FILE *f = fopen(filename, "w");
            if (f) {
                files[file_count++] = f;
            }
        }
    }
    
    printf("Completed %lld iterations\n", iterations);
    
    /* Cleanup */
    printf("Cleaning up...\n");
    
    for (int i = 0; i < file_count; i++) {
        if (files[i]) {
            fclose(files[i]);
            snprintf(filename, sizeof(filename), "exhaust_fd_%d_%d.tmp", getpid(), i);
            unlink(filename);
        }
    }
    
    for (int i = 0; i < mem_count; i++) {
        if (mem_blocks[i]) {
            free(mem_blocks[i]);
        }
    }
    
    printf("Resource exhaustion attack completed\n");
    return 0;
}

