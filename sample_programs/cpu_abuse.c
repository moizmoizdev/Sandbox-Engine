#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

volatile int keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
    printf("\nReceived signal %d, stopping CPU abuse...\n", sig);
}

/* CPU abuse - spawns multiple threads to max out CPU cores */
void* cpu_thread(void* arg) {
    int thread_id = *(int*)arg;
    volatile long long count = 0;
    
    printf("CPU thread %d started\n", thread_id);
    
    while (keep_running) {
        count++;
        /* Prevent compiler optimization */
        if (count % 100000000 == 0) {
            printf("Thread %d: %lld iterations\n", thread_id, count);
        }
    }
    
    printf("Thread %d completed with %lld iterations\n", thread_id, count);
    return NULL;
}

int main() {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    printf("CPU abuse program started\n");
    printf("Process ID: %d\n", getpid());
    
    int num_threads = 4; /* Number of CPU-intensive threads */
    pthread_t threads[num_threads];
    int thread_ids[num_threads];
    
    printf("Spawning %d CPU-intensive threads...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, cpu_thread, &thread_ids[i]) != 0) {
            perror("pthread_create");
            break;
        }
    }
    
    printf("All threads running. Press Ctrl+C or use Stop Process to terminate.\n");
    
    /* Wait for all threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("CPU abuse completed\n");
    return 0;
}

