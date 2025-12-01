#define _GNU_SOURCE
#include "monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

/* Static variables for CPU calculation */
static pid_t prev_pid = 0;
static unsigned long long prev_utime = 0;
static unsigned long long prev_stime = 0;
static double prev_uptime = 0.0;

/**
 * Get memory usage from /proc/[pid]/status
 */
static int get_memory_usage(pid_t pid, long *rss_kb, long *vms_kb) {
    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    
    FILE *f = fopen(status_path, "r");
    if (!f) {
        return -1;
    }
    
    *rss_kb = 0;
    *vms_kb = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld", rss_kb);
        } else if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line, "VmSize: %ld", vms_kb);
        }
    }
    
    fclose(f);
    return 0;
}

/**
 * Get thread count from /proc/[pid]/status
 */
static int get_thread_count(pid_t pid) {
    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    
    FILE *f = fopen(status_path, "r");
    if (!f) {
        return -1;
    }
    
    int threads = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Threads:", 8) == 0) {
            sscanf(line, "Threads: %d", &threads);
            break;
        }
    }
    
    fclose(f);
    return threads;
}

/**
 * Get file descriptor count
 */
static int get_fd_count(pid_t pid) {
    char fd_dir[256];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    
    DIR *dir = opendir(fd_dir);
    if (!dir) {
        return -1;
    }
    
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

/**
 * Get CPU usage percentage
 */
static double get_cpu_usage(pid_t pid) {
    char stat_path[256];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    
    FILE *f = fopen(stat_path, "r");
    if (!f) {
        return -1.0;
    }
    
    unsigned long long utime = 0, stime = 0;
    char line[512];
    if (fgets(line, sizeof(line), f)) {
        /* Parse stat file - format: pid comm state ppid ... utime stime ... */
        char *token = strtok(line, " ");
        int field = 0;
        while (token != NULL) {
            field++;
            if (field == 14) {
                utime = strtoull(token, NULL, 10);
            } else if (field == 15) {
                stime = strtoull(token, NULL, 10);
                break;
            }
            token = strtok(NULL, " ");
        }
    }
    fclose(f);
    
    /* Get system uptime */
    FILE *uptime_file = fopen("/proc/uptime", "r");
    double uptime = 0.0;
    if (uptime_file) {
        fscanf(uptime_file, "%lf", &uptime);
        fclose(uptime_file);
    }
    
    double cpu_percent = 0.0;
    
    /* Calculate CPU percentage */
    if (prev_pid == pid && prev_uptime > 0 && prev_utime > 0) {
        long time_diff = (utime + stime) - (prev_utime + prev_stime);
        double uptime_diff = uptime - prev_uptime;
        
        if (uptime_diff > 0 && time_diff >= 0) {
            /* CPU percentage = (process_time / elapsed_time) * 100 */
            cpu_percent = ((double)time_diff / (uptime_diff * sysconf(_SC_CLK_TCK))) * 100.0;
            if (cpu_percent < 0) cpu_percent = 0;
            if (cpu_percent > 100) cpu_percent = 100;
        }
    }
    
    prev_utime = utime;
    prev_stime = stime;
    prev_uptime = uptime;
    
    return cpu_percent;
}

void init_monitoring(pid_t pid) {
    prev_pid = pid;
    prev_utime = 0;
    prev_stime = 0;
    prev_uptime = 0.0;
}

int collect_process_stats(pid_t pid, ProcessStats *stats) {
    if (!stats || pid <= 0) {
        return -1;
    }
    
    stats->pid = pid;
    stats->exit_status = 0;
    stats->signal_number = 0;
    
    /* Check if process is running using kill(0) - non-destructive check */
    if (kill(pid, 0) != 0) {
        /* Process doesn't exist */
        stats->is_running = 0;
        
        /* Try waitpid with WNOHANG to get status if process already exited */
        /* Note: This may fail with ECHILD if PID namespace is used, which is OK */
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (WIFEXITED(status)) {
                stats->exit_status = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                stats->signal_number = WTERMSIG(status);
            }
        } else if (result == -1 && errno == ECHILD) {
            /* Process doesn't exist or is in a different PID namespace */
            /* This is normal when PID namespace is used - the process might have exited */
            stats->exit_status = -1; /* Unknown exit status */
        }
        
        return 0; /* Process not running, but not an error */
    }
    
    stats->is_running = 1;
    
    /* Get CPU usage */
    stats->cpu_percent = get_cpu_usage(pid);
    if (stats->cpu_percent < 0) {
        stats->cpu_percent = 0.0;
    }
    
    /* Get memory usage */
    if (get_memory_usage(pid, &stats->memory_rss_kb, &stats->memory_vms_kb) < 0) {
        stats->memory_rss_kb = 0;
        stats->memory_vms_kb = 0;
    }
    
    /* Get thread count */
    stats->num_threads = get_thread_count(pid);
    if (stats->num_threads < 0) {
        stats->num_threads = 0;
    }
    
    /* Get file descriptor count */
    stats->num_fds = get_fd_count(pid);
    if (stats->num_fds < 0) {
        stats->num_fds = 0;
    }
    
    return 0;
}

