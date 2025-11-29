/*
 * Ultimate Stress Test
 * 
 * This program aggressively consumes system resources to test sandbox limits:
 * - Allocates 2GB of RAM
 * - Creates 100 threads doing CPU-intensive work
 * - Forks 10 child processes
 * - Each process/thread maxes out CPU cores
 * 
 * This is designed to test cgroup limits (CPU, memory, PIDs, threads)
 * 
 * Compile: gcc -o ultimate_stress ultimate_stress.c -pthread
 * Run: ./ultimate_stress
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#define TARGET_MEMORY_MB    2048      /* 2 GB target */
#define NUM_THREADS         100       /* 100 threads */
#define NUM_PROCESSES       10        /* 10 child processes */
#define STRESS_DURATION_SEC 30        /* Run for 30 seconds */

/* Global flag to control threads */
volatile int running = 1;

/* Thread counter */
volatile int threads_created = 0;
pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * CPU-intensive calculation (calculate prime numbers)
 */
unsigned long calculate_primes(unsigned long limit) {
    unsigned long count = 0;
    for (unsigned long n = 2; n < limit; n++) {
        int is_prime = 1;
        for (unsigned long i = 2; i * i <= n; i++) {
            if (n % i == 0) {
                is_prime = 0;
                break;
            }
        }
        if (is_prime) count++;
    }
    return count;
}

/**
 * Thread function - performs CPU-intensive work
 */
void* thread_worker(void* arg) {
    int thread_id = *(int*)arg;
    free(arg);
    
    pthread_mutex_lock(&counter_mutex);
    threads_created++;
    printf("[Thread %d] Started (total: %d)\n", thread_id, threads_created);
    pthread_mutex_unlock(&counter_mutex);
    
    /* CPU-intensive loop */
    while (running) {
        /* Calculate primes (CPU intensive) */
        volatile unsigned long primes = calculate_primes(10000);
        
        /* Allocate and touch some memory */
        char* buf = malloc(1024 * 1024); /* 1 MB */
        if (buf) {
            memset(buf, 0xAA, 1024 * 1024);
            free(buf);
        }
        
        /* Prevent compiler optimization */
        (void)primes;
    }
    
    pthread_mutex_lock(&counter_mutex);
    threads_created--;
    pthread_mutex_unlock(&counter_mutex);
    
    printf("[Thread %d] Exiting\n", thread_id);
    return NULL;
}

/**
 * Allocate large chunk of memory and keep it allocated
 */
void* memory_allocator_thread(void* arg) {
    size_t mb_to_allocate = *(size_t*)arg;
    free(arg);
    
    printf("[Memory Allocator] Attempting to allocate %zu MB...\n", mb_to_allocate);
    
    /* Allocate in chunks to avoid single large allocation failure */
    size_t chunk_size = 64 * 1024 * 1024; /* 64 MB chunks */
    size_t num_chunks = (mb_to_allocate * 1024 * 1024) / chunk_size;
    
    char** chunks = malloc(num_chunks * sizeof(char*));
    if (!chunks) {
        fprintf(stderr, "[Memory Allocator] Failed to allocate chunk array\n");
        return NULL;
    }
    
    size_t allocated = 0;
    for (size_t i = 0; i < num_chunks && running; i++) {
        chunks[i] = malloc(chunk_size);
        if (!chunks[i]) {
            fprintf(stderr, "[Memory Allocator] Failed to allocate chunk %zu (allocated %zu MB so far)\n", 
                    i, allocated / (1024 * 1024));
            break;
        }
        
        /* Touch every page to ensure physical allocation */
        for (size_t j = 0; j < chunk_size; j += 4096) {
            chunks[i][j] = (char)(i & 0xFF);
        }
        
        allocated += chunk_size;
        
        if ((i + 1) % 10 == 0) {
            printf("[Memory Allocator] Allocated %zu MB / %zu MB\n", 
                   allocated / (1024 * 1024), mb_to_allocate);
        }
    }
    
    printf("[Memory Allocator] Successfully allocated %zu MB, holding...\n", 
           allocated / (1024 * 1024));
    
    /* Keep memory allocated while running */
    while (running) {
        /* Touch memory periodically to prevent swapping */
        for (size_t i = 0; i < num_chunks && chunks[i]; i++) {
            chunks[i][0] = (char)(i & 0xFF);
        }
        sleep(1);
    }
    
    /* Cleanup */
    printf("[Memory Allocator] Freeing memory...\n");
    for (size_t i = 0; i < num_chunks && chunks[i]; i++) {
        free(chunks[i]);
    }
    free(chunks);
    
    return NULL;
}

/**
 * Child process worker - also spawns threads
 */
void child_process_worker(int process_id) {
    printf("[Process %d] PID %d started\n", process_id, getpid());
    
    /* Each child process creates some threads */
    int threads_per_child = 5;
    pthread_t threads[threads_per_child];
    
    for (int i = 0; i < threads_per_child; i++) {
        int* tid = malloc(sizeof(int));
        *tid = process_id * 100 + i;
        
        if (pthread_create(&threads[i], NULL, thread_worker, tid) != 0) {
            fprintf(stderr, "[Process %d] Failed to create thread %d: %s\n", 
                    process_id, i, strerror(errno));
            free(tid);
            break;
        }
    }
    
    /* CPU-intensive work */
    time_t start = time(NULL);
    while (running && (time(NULL) - start) < STRESS_DURATION_SEC) {
        calculate_primes(50000);
        usleep(10000); /* Brief pause */
    }
    
    printf("[Process %d] Signaling threads to stop...\n", process_id);
    
    /* Wait for threads to finish */
    for (int i = 0; i < threads_per_child; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("[Process %d] Exiting\n", process_id);
    exit(0);
}

/**
 * Signal handler for graceful shutdown
 */
void signal_handler(int sig) {
    printf("\n[Main] Caught signal %d, shutting down...\n", sig);
    running = 0;
}

/**
 * Print current resource usage
 */
void print_stats() {
    char stat_path[256];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/status", getpid());
    
    FILE* f = fopen(stat_path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmRSS:", 6) == 0 || 
                strncmp(line, "VmSize:", 7) == 0 ||
                strncmp(line, "Threads:", 8) == 0) {
                printf("[Stats] %s", line);
            }
        }
        fclose(f);
    }
}

int main() {
    printf("═══════════════════════════════════════════════════════\n");
    printf("   ULTIMATE STRESS TEST - Resource Exhaustion\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("Target: %d MB RAM, %d threads, %d processes\n", 
           TARGET_MEMORY_MB, NUM_THREADS, NUM_PROCESSES);
    printf("Duration: %d seconds\n", STRESS_DURATION_SEC);
    printf("PID: %d\n", getpid());
    printf("═══════════════════════════════════════════════════════\n\n");
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Start time */
    time_t start_time = time(NULL);
    
    /* Phase 1: Allocate large memory block */
    printf("\n[Phase 1] Allocating %d MB of RAM...\n", TARGET_MEMORY_MB);
    pthread_t memory_thread;
    size_t* mem_size = malloc(sizeof(size_t));
    *mem_size = TARGET_MEMORY_MB;
    
    if (pthread_create(&memory_thread, NULL, memory_allocator_thread, mem_size) != 0) {
        fprintf(stderr, "Failed to create memory allocator thread: %s\n", strerror(errno));
        free(mem_size);
    }
    
    sleep(2); /* Give memory allocator time */
    
    /* Phase 2: Create CPU-intensive threads */
    printf("\n[Phase 2] Creating %d CPU-intensive threads...\n", NUM_THREADS);
    pthread_t threads[NUM_THREADS];
    int thread_count = 0;
    
    for (int i = 0; i < NUM_THREADS && running; i++) {
        int* tid = malloc(sizeof(int));
        if (!tid) break;
        *tid = i;
        
        if (pthread_create(&threads[i], NULL, thread_worker, tid) != 0) {
            fprintf(stderr, "Failed to create thread %d: %s\n", i, strerror(errno));
            free(tid);
            break;
        }
        thread_count++;
        
        /* Small delay to avoid overwhelming the system instantly */
        if (i % 10 == 0) {
            usleep(50000); /* 50ms */
            printf("[Phase 2] Created %d threads so far...\n", i + 1);
        }
    }
    
    printf("[Phase 2] Successfully created %d threads\n", thread_count);
    sleep(1);
    
    /* Phase 3: Fork child processes */
    printf("\n[Phase 3] Forking %d child processes...\n", NUM_PROCESSES);
    pid_t children[NUM_PROCESSES];
    int process_count = 0;
    
    for (int i = 0; i < NUM_PROCESSES && running; i++) {
        pid_t pid = fork();
        
        if (pid < 0) {
            fprintf(stderr, "Failed to fork process %d: %s\n", i, strerror(errno));
            break;
        } else if (pid == 0) {
            /* Child process */
            child_process_worker(i);
            exit(0); /* Should not reach here */
        } else {
            /* Parent */
            children[process_count++] = pid;
            printf("[Phase 3] Forked process %d (PID %d)\n", i, pid);
            usleep(100000); /* 100ms delay between forks */
        }
    }
    
    printf("[Phase 3] Successfully forked %d processes\n", process_count);
    
    /* Phase 4: Run stress test */
    printf("\n[Phase 4] Running stress test...\n");
    printf("Press Ctrl+C to stop early\n\n");
    
    while (running && (time(NULL) - start_time) < STRESS_DURATION_SEC) {
        /* Print stats every 5 seconds */
        static time_t last_stats = 0;
        if (time(NULL) - last_stats >= 5) {
            printf("\n─── Resource Usage (elapsed: %ld sec) ───\n", 
                   time(NULL) - start_time);
            print_stats();
            printf("Active threads: %d\n", threads_created);
            printf("─────────────────────────────────────────\n\n");
            last_stats = time(NULL);
        }
        
        /* Parent also does CPU work */
        calculate_primes(20000);
        sleep(1);
    }
    
    /* Shutdown */
    printf("\n[Shutdown] Stopping all threads and processes...\n");
    running = 0;
    
    /* Wait for child processes */
    printf("[Shutdown] Waiting for child processes...\n");
    for (int i = 0; i < process_count; i++) {
        int status;
        waitpid(children[i], &status, 0);
        printf("[Shutdown] Process %d (PID %d) exited\n", i, children[i]);
    }
    
    /* Wait for threads */
    printf("[Shutdown] Waiting for threads...\n");
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Wait for memory thread */
    pthread_join(memory_thread, NULL);
    
    printf("\n═══════════════════════════════════════════════════════\n");
    printf("   Stress test completed\n");
    printf("   Total runtime: %ld seconds\n", time(NULL) - start_time);
    printf("═══════════════════════════════════════════════════════\n");
    
    return 0;
}

