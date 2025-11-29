/*
 * Stress Test Master Controller
 * 
 * Interactive menu system to test sandbox resource limits:
 * - Memory allocation (configurable size)
 * - Thread creation (configurable count)
 * - Process forking (configurable count)
 * - CPU usage (configurable intensity)
 * - Combined stress tests
 * 
 * User can configure parameters and confirm before execution
 * 
 * Compile: gcc -o stress_master stress_master.c -pthread
 * Run: ./stress_master
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
#include <ctype.h>

/* Configuration structure */
typedef struct {
    int test_memory;
    size_t memory_mb;
    
    int test_threads;
    int num_threads;
    
    int test_processes;
    int num_processes;
    
    int test_cpu;
    int cpu_intensity;  /* 1-10 scale */
    
    int duration_sec;
    int verbose;
} StressConfig;

/* Global control */
volatile int running = 1;
volatile int threads_active = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
void print_banner(void);
void print_menu(void);
void configure_test(StressConfig *config);
void show_configuration(const StressConfig *config);
int confirm_execution(void);
void execute_stress_test(const StressConfig *config);
void signal_handler(int sig);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ========================================================================== */

void clear_screen(void) {
    printf("\033[2J\033[H");
}

void print_separator(void) {
    printf("═══════════════════════════════════════════════════════════════════════\n");
}

void print_line(void) {
    printf("───────────────────────────────────────────────────────────────────────\n");
}

int read_int(const char *prompt, int min, int max, int default_val) {
    char input[100];
    int value;
    
    while (1) {
        printf("%s [%d-%d, default=%d]: ", prompt, min, max, default_val);
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            return default_val;
        }
        
        /* Remove newline */
        input[strcspn(input, "\n")] = 0;
        
        /* Empty input = default */
        if (strlen(input) == 0) {
            return default_val;
        }
        
        /* Parse integer */
        if (sscanf(input, "%d", &value) == 1) {
            if (value >= min && value <= max) {
                return value;
            } else {
                printf("  ⚠️  Value must be between %d and %d\n", min, max);
            }
        } else {
            printf("  ⚠️  Invalid input. Please enter a number.\n");
        }
    }
}

int read_yes_no(const char *prompt, int default_yes) {
    char input[100];
    
    printf("%s [%s]: ", prompt, default_yes ? "Y/n" : "y/N");
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return default_yes;
    }
    
    /* Remove newline */
    input[strcspn(input, "\n")] = 0;
    
    /* Empty input = default */
    if (strlen(input) == 0) {
        return default_yes;
    }
    
    /* Check first character */
    char c = tolower(input[0]);
    return (c == 'y');
}

/* ============================================================================
 * STRESS TEST WORKERS
 * ========================================================================== */

/**
 * CPU-intensive calculation
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
 * Thread worker function
 */
void* thread_worker(void* arg) {
    int thread_id = *(int*)arg;
    int intensity = *((int*)arg + 1);
    free(arg);
    
    pthread_mutex_lock(&mutex);
    threads_active++;
    printf("  [Thread %d] Started (active: %d)\n", thread_id, threads_active);
    pthread_mutex_unlock(&mutex);
    
    /* CPU work based on intensity */
    unsigned long work_size = 5000 * intensity;
    
    while (running) {
        calculate_primes(work_size);
        
        /* Brief pause at lower intensities */
        if (intensity < 8) {
            usleep(10000 * (10 - intensity));
        }
    }
    
    pthread_mutex_lock(&mutex);
    threads_active--;
    pthread_mutex_unlock(&mutex);
    
    return NULL;
}

/**
 * Memory allocator thread
 */
void* memory_worker(void* arg) {
    size_t mb_to_allocate = *(size_t*)arg;
    free(arg);
    
    printf("\n  [Memory] Allocating %zu MB...\n", mb_to_allocate);
    
    size_t chunk_size = 64 * 1024 * 1024; /* 64 MB chunks */
    size_t num_chunks = (mb_to_allocate * 1024 * 1024) / chunk_size;
    if (num_chunks == 0) num_chunks = 1;
    
    char** chunks = malloc(num_chunks * sizeof(char*));
    if (!chunks) {
        fprintf(stderr, "  [Memory] ❌ Failed to allocate chunk array\n");
        return NULL;
    }
    
    size_t allocated = 0;
    for (size_t i = 0; i < num_chunks && running; i++) {
        size_t alloc_size = (i == num_chunks - 1) ? 
            (mb_to_allocate * 1024 * 1024 - allocated) : chunk_size;
        
        chunks[i] = malloc(alloc_size);
        if (!chunks[i]) {
            fprintf(stderr, "  [Memory] ⚠️  Failed after allocating %zu MB\n", 
                    allocated / (1024 * 1024));
            break;
        }
        
        /* Touch memory to force physical allocation */
        memset(chunks[i], 0xAA, alloc_size);
        allocated += alloc_size;
        
        printf("  [Memory] Allocated %zu / %zu MB\n", 
               allocated / (1024 * 1024), mb_to_allocate);
    }
    
    if (allocated >= mb_to_allocate * 1024 * 1024 * 0.9) {
        printf("  [Memory] ✅ Successfully allocated %zu MB\n", 
               allocated / (1024 * 1024));
    }
    
    /* Hold memory while running */
    while (running) {
        sleep(1);
    }
    
    /* Cleanup */
    for (size_t i = 0; i < num_chunks && chunks[i]; i++) {
        free(chunks[i]);
    }
    free(chunks);
    
    return NULL;
}

/**
 * Child process worker
 */
void child_process_worker(int process_id, int intensity, int duration) {
    printf("  [Process %d] PID %d started\n", process_id, getpid());
    
    time_t start = time(NULL);
    unsigned long work_size = 10000 * intensity;
    
    while (running && (time(NULL) - start) < duration) {
        calculate_primes(work_size);
        usleep(50000);
    }
    
    printf("  [Process %d] Exiting\n", process_id);
    exit(0);
}

/**
 * Print current resource stats
 */
void print_resource_stats(void) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    
    FILE* f = fopen(path, "r");
    if (!f) return;
    
    char line[256];
    printf("\n  📊 Resource Usage:\n");
    print_line();
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            printf("  %s", line);
        } else if (strncmp(line, "VmSize:", 7) == 0) {
            printf("  %s", line);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            printf("  %s", line);
        }
    }
    printf("  Active stress threads: %d\n", threads_active);
    print_line();
    
    fclose(f);
}

/* ============================================================================
 * MENU & CONFIGURATION
 * ========================================================================== */

void print_banner(void) {
    clear_screen();
    print_separator();
    printf("               🔥 STRESS TEST MASTER CONTROLLER 🔥\n");
    printf("           Interactive Sandbox Resource Testing Tool\n");
    print_separator();
    printf("\n");
}

void print_menu(void) {
    printf("  📋 MAIN MENU:\n");
    print_line();
    printf("  1. Configure Memory Stress Test\n");
    printf("  2. Configure Thread Stress Test\n");
    printf("  3. Configure Process Stress Test\n");
    printf("  4. Configure CPU Stress Test\n");
    printf("  5. Configure Combined Stress Test\n");
    printf("  6. Quick Presets\n");
    print_line();
    printf("  7. Show Current Configuration\n");
    printf("  8. Run Stress Test\n");
    printf("  9. Reset Configuration\n");
    printf("  0. Exit\n");
    print_separator();
}

void configure_memory_test(StressConfig *config) {
    clear_screen();
    printf("  🧠 MEMORY STRESS TEST CONFIGURATION\n");
    print_separator();
    
    config->test_memory = read_yes_no("Enable memory stress test?", 1);
    
    if (config->test_memory) {
        printf("\n  Memory allocation options:\n");
        printf("  • 512 MB   - Light test\n");
        printf("  • 1024 MB  - Moderate test (1 GB)\n");
        printf("  • 2048 MB  - Heavy test (2 GB)\n");
        printf("  • 4096 MB  - Extreme test (4 GB)\n\n");
        
        config->memory_mb = read_int("Enter memory to allocate (MB)", 64, 8192, 1024);
        printf("\n  ✅ Memory test configured: %zu MB\n", config->memory_mb);
    }
    
    printf("\n  Press Enter to continue...");
    getchar();
}

void configure_thread_test(StressConfig *config) {
    clear_screen();
    printf("  🧵 THREAD STRESS TEST CONFIGURATION\n");
    print_separator();
    
    config->test_threads = read_yes_no("Enable thread stress test?", 1);
    
    if (config->test_threads) {
        printf("\n  Thread count options:\n");
        printf("  • 10    - Light test\n");
        printf("  • 50    - Moderate test\n");
        printf("  • 100   - Heavy test\n");
        printf("  • 200   - Extreme test\n\n");
        
        config->num_threads = read_int("Enter number of threads", 1, 500, 50);
        printf("\n  ✅ Thread test configured: %d threads\n", config->num_threads);
    }
    
    printf("\n  Press Enter to continue...");
    getchar();
}

void configure_process_test(StressConfig *config) {
    clear_screen();
    printf("  🔀 PROCESS STRESS TEST CONFIGURATION\n");
    print_separator();
    
    config->test_processes = read_yes_no("Enable process fork stress test?", 1);
    
    if (config->test_processes) {
        printf("\n  Process count options:\n");
        printf("  • 5     - Light test\n");
        printf("  • 10    - Moderate test\n");
        printf("  • 20    - Heavy test\n");
        printf("  • 50    - Extreme test\n\n");
        
        config->num_processes = read_int("Enter number of processes", 1, 100, 10);
        printf("\n  ✅ Process test configured: %d processes\n", config->num_processes);
    }
    
    printf("\n  Press Enter to continue...");
    getchar();
}

void configure_cpu_test(StressConfig *config) {
    clear_screen();
    printf("  ⚡ CPU STRESS TEST CONFIGURATION\n");
    print_separator();
    
    config->test_cpu = read_yes_no("Enable CPU stress test?", 1);
    
    if (config->test_cpu) {
        printf("\n  CPU intensity scale (1-10):\n");
        printf("  • 1-3   - Light load (< 25%% CPU)\n");
        printf("  • 4-6   - Moderate load (25-50%% CPU)\n");
        printf("  • 7-8   - Heavy load (50-75%% CPU)\n");
        printf("  • 9-10  - Maximum load (100%% CPU)\n\n");
        
        config->cpu_intensity = read_int("Enter CPU intensity", 1, 10, 7);
        printf("\n  ✅ CPU test configured: intensity %d/10\n", config->cpu_intensity);
    }
    
    printf("\n  Press Enter to continue...");
    getchar();
}

void configure_combined_test(StressConfig *config) {
    clear_screen();
    printf("  🌪️  COMBINED STRESS TEST CONFIGURATION\n");
    print_separator();
    printf("\n  This will enable ALL stress tests simultaneously!\n\n");
    
    if (!read_yes_no("Enable combined stress test?", 1)) {
        return;
    }
    
    config->test_memory = 1;
    config->memory_mb = read_int("Memory (MB)", 64, 8192, 2048);
    
    config->test_threads = 1;
    config->num_threads = read_int("Threads", 1, 500, 100);
    
    config->test_processes = 1;
    config->num_processes = read_int("Processes", 1, 100, 10);
    
    config->test_cpu = 1;
    config->cpu_intensity = read_int("CPU Intensity (1-10)", 1, 10, 8);
    
    printf("\n  ✅ Combined test configured!\n");
    printf("\n  Press Enter to continue...");
    getchar();
}

void apply_preset(StressConfig *config, int preset) {
    switch (preset) {
        case 1: /* Light */
            config->test_memory = 1;
            config->memory_mb = 256;
            config->test_threads = 1;
            config->num_threads = 10;
            config->test_processes = 1;
            config->num_processes = 3;
            config->test_cpu = 1;
            config->cpu_intensity = 3;
            config->duration_sec = 15;
            break;
            
        case 2: /* Moderate */
            config->test_memory = 1;
            config->memory_mb = 1024;
            config->test_threads = 1;
            config->num_threads = 50;
            config->test_processes = 1;
            config->num_processes = 10;
            config->test_cpu = 1;
            config->cpu_intensity = 6;
            config->duration_sec = 30;
            break;
            
        case 3: /* Heavy */
            config->test_memory = 1;
            config->memory_mb = 2048;
            config->test_threads = 1;
            config->num_threads = 100;
            config->test_processes = 1;
            config->num_processes = 20;
            config->test_cpu = 1;
            config->cpu_intensity = 9;
            config->duration_sec = 45;
            break;
            
        case 4: /* Extreme */
            config->test_memory = 1;
            config->memory_mb = 4096;
            config->test_threads = 1;
            config->num_threads = 200;
            config->test_processes = 1;
            config->num_processes = 50;
            config->test_cpu = 1;
            config->cpu_intensity = 10;
            config->duration_sec = 60;
            break;
    }
}

void quick_presets(StressConfig *config) {
    clear_screen();
    printf("  ⚡ QUICK PRESETS\n");
    print_separator();
    printf("\n");
    printf("  1. Light     - 256MB, 10 threads, 3 processes, 15 sec\n");
    printf("  2. Moderate  - 1GB, 50 threads, 10 processes, 30 sec\n");
    printf("  3. Heavy     - 2GB, 100 threads, 20 processes, 45 sec\n");
    printf("  4. Extreme   - 4GB, 200 threads, 50 processes, 60 sec\n");
    printf("  0. Cancel\n");
    print_separator();
    
    int choice = read_int("Select preset", 0, 4, 0);
    
    if (choice > 0) {
        apply_preset(config, choice);
        printf("\n  ✅ Preset applied!\n");
    }
    
    printf("\n  Press Enter to continue...");
    getchar();
}

void show_configuration(const StressConfig *config) {
    clear_screen();
    printf("  📋 CURRENT CONFIGURATION\n");
    print_separator();
    printf("\n");
    
    printf("  Memory Test:   %s", config->test_memory ? "✅ ENABLED" : "❌ DISABLED");
    if (config->test_memory) {
        printf(" - %zu MB\n", config->memory_mb);
    } else {
        printf("\n");
    }
    
    printf("  Thread Test:   %s", config->test_threads ? "✅ ENABLED" : "❌ DISABLED");
    if (config->test_threads) {
        printf(" - %d threads\n", config->num_threads);
    } else {
        printf("\n");
    }
    
    printf("  Process Test:  %s", config->test_processes ? "✅ ENABLED" : "❌ DISABLED");
    if (config->test_processes) {
        printf(" - %d processes\n", config->num_processes);
    } else {
        printf("\n");
    }
    
    printf("  CPU Test:      %s", config->test_cpu ? "✅ ENABLED" : "❌ DISABLED");
    if (config->test_cpu) {
        printf(" - intensity %d/10\n", config->cpu_intensity);
    } else {
        printf("\n");
    }
    
    printf("\n");
    printf("  Duration:      %d seconds\n", config->duration_sec);
    printf("  Verbose:       %s\n", config->verbose ? "Yes" : "No");
    
    print_separator();
    printf("\n  Press Enter to continue...");
    getchar();
}

int confirm_execution(void) {
    printf("\n");
    print_separator();
    printf("  ⚠️  WARNING: This will stress your system resources!\n");
    printf("  Make sure you're running in the sandbox.\n");
    print_separator();
    
    return read_yes_no("  🚀 Start stress test?", 0);
}

/* ============================================================================
 * STRESS TEST EXECUTION
 * ========================================================================== */

void execute_stress_test(const StressConfig *config) {
    clear_screen();
    print_separator();
    printf("  🔥 EXECUTING STRESS TEST\n");
    print_separator();
    printf("\n  PID: %d\n", getpid());
    printf("  Duration: %d seconds\n", config->duration_sec);
    printf("  Press Ctrl+C to stop early\n\n");
    
    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    time_t start_time = time(NULL);
    pthread_t memory_thread = 0;
    pthread_t *threads = NULL;
    pid_t *children = NULL;
    int thread_count = 0;
    int process_count = 0;
    
    /* Phase 1: Memory */
    if (config->test_memory) {
        printf("  [Phase 1] Starting memory allocation...\n");
        size_t *mem_size = malloc(sizeof(size_t));
        *mem_size = config->memory_mb;
        pthread_create(&memory_thread, NULL, memory_worker, mem_size);
        sleep(2);
    }
    
    /* Phase 2: Threads */
    if (config->test_threads) {
        printf("\n  [Phase 2] Creating %d threads...\n", config->num_threads);
        threads = malloc(config->num_threads * sizeof(pthread_t));
        
        for (int i = 0; i < config->num_threads && running; i++) {
            int *params = malloc(2 * sizeof(int));
            params[0] = i;
            params[1] = config->cpu_intensity;
            
            if (pthread_create(&threads[i], NULL, thread_worker, params) == 0) {
                thread_count++;
                if ((i + 1) % 20 == 0) {
                    printf("    Created %d/%d threads...\n", i + 1, config->num_threads);
                }
            } else {
                free(params);
                break;
            }
            usleep(10000);
        }
        printf("    ✅ Created %d threads\n", thread_count);
    }
    
    /* Phase 3: Processes */
    if (config->test_processes) {
        printf("\n  [Phase 3] Forking %d processes...\n", config->num_processes);
        children = malloc(config->num_processes * sizeof(pid_t));
        
        for (int i = 0; i < config->num_processes && running; i++) {
            pid_t pid = fork();
            
            if (pid < 0) {
                fprintf(stderr, "    Fork failed: %s\n", strerror(errno));
                break;
            } else if (pid == 0) {
                child_process_worker(i, config->cpu_intensity, config->duration_sec);
                exit(0);
            } else {
                children[process_count++] = pid;
            }
            usleep(50000);
        }
        printf("    ✅ Forked %d processes\n", process_count);
    }
    
    /* Phase 4: Run */
    printf("\n  [Phase 4] Running stress test...\n");
    print_line();
    
    while (running && (time(NULL) - start_time) < config->duration_sec) {
        if ((time(NULL) - start_time) % 5 == 0) {
            print_resource_stats();
        }
        
        /* Parent CPU work if enabled */
        if (config->test_cpu) {
            calculate_primes(10000 * config->cpu_intensity);
        }
        
        sleep(1);
    }
    
    /* Shutdown */
    printf("\n  [Shutdown] Stopping stress test...\n");
    running = 0;
    
    if (children) {
        for (int i = 0; i < process_count; i++) {
            waitpid(children[i], NULL, 0);
        }
        free(children);
    }
    
    if (threads) {
        for (int i = 0; i < thread_count; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
    }
    
    if (memory_thread) {
        pthread_join(memory_thread, NULL);
    }
    
    printf("\n");
    print_separator();
    printf("  ✅ Stress test completed\n");
    printf("  Runtime: %ld seconds\n", time(NULL) - start_time);
    print_separator();
    printf("\n  Press Enter to return to menu...");
    getchar();
}

void signal_handler(int sig) {
    printf("\n\n  ⚠️  Caught signal %d, shutting down...\n", sig);
    running = 0;
}

/* ============================================================================
 * MAIN
 * ========================================================================== */

int main() {
    StressConfig config = {0};
    
    /* Default configuration */
    config.duration_sec = 30;
    config.verbose = 0;
    config.cpu_intensity = 5;
    
    int choice;
    
    while (1) {
        print_banner();
        print_menu();
        
        choice = read_int("Enter choice", 0, 9, 0);
        
        switch (choice) {
            case 1:
                configure_memory_test(&config);
                break;
            case 2:
                configure_thread_test(&config);
                break;
            case 3:
                configure_process_test(&config);
                break;
            case 4:
                configure_cpu_test(&config);
                break;
            case 5:
                configure_combined_test(&config);
                break;
            case 6:
                quick_presets(&config);
                break;
            case 7:
                show_configuration(&config);
                break;
            case 8:
                show_configuration(&config);
                if (confirm_execution()) {
                    execute_stress_test(&config);
                    running = 1; /* Reset for next run */
                }
                break;
            case 9:
                memset(&config, 0, sizeof(config));
                config.duration_sec = 30;
                config.cpu_intensity = 5;
                printf("\n  ✅ Configuration reset\n");
                sleep(1);
                break;
            case 0:
                printf("\n  👋 Goodbye!\n\n");
                return 0;
            default:
                printf("\n  ⚠️  Invalid choice\n");
                sleep(1);
        }
    }
    
    return 0;
}

