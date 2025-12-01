#ifndef MONITOR_H
#define MONITOR_H

#include <sys/types.h>

/**
 * Process statistics structure
 */
typedef struct {
    pid_t pid;
    double cpu_percent;         /* CPU usage percentage */
    long memory_rss_kb;          /* Resident Set Size in KB */
    long memory_vms_kb;          /* Virtual Memory Size in KB */
    int num_threads;             /* Number of threads */
    int num_fds;                 /* Number of file descriptors */
    int is_running;              /* 1 if running, 0 if stopped */
    int exit_status;             /* Exit status if stopped */
    int signal_number;           /* Signal number if killed */
} ProcessStats;

/**
 * Initialize monitoring (reset internal state)
 * @param pid Process ID to monitor
 */
void init_monitoring(pid_t pid);

/**
 * Collect process statistics
 * @param pid Process ID to monitor
 * @param stats Pointer to ProcessStats structure to fill
 * @return 0 on success, -1 on error
 */
int collect_process_stats(pid_t pid, ProcessStats *stats);

#endif /* MONITOR_H */

