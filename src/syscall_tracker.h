#ifndef SYSCALL_TRACKER_H
#define SYSCALL_TRACKER_H

#include <sys/types.h>
#include <time.h>

/* Maximum syscall name length */
#define MAX_SYSCALL_NAME 64
#define MAX_SYSCALL_LOG_ENTRIES 10000

/* Syscall log entry */
typedef struct {
    unsigned long syscall_number;
    char syscall_name[MAX_SYSCALL_NAME];
    long arg1, arg2, arg3, arg4, arg5, arg6;
    long return_value;
    int error_code;  /* errno if return_value < 0 */
    time_t timestamp;
    pid_t pid;
    pid_t tid;  /* Thread ID */
} SyscallLogEntry;

/* Syscall statistics */
typedef struct {
    unsigned long syscall_number;
    char syscall_name[MAX_SYSCALL_NAME];
    unsigned long count;
    unsigned long error_count;
    unsigned long total_time_ns;  /* Total execution time in nanoseconds */
} SyscallStats;

/* Syscall tracker context */
typedef struct {
    pid_t target_pid;
    SyscallLogEntry *log_entries;
    int log_count;
    int log_capacity;
    int log_index;  /* Circular buffer index */
    
    SyscallStats *stats;
    int stats_count;
    int stats_capacity;
    
    int enabled;
    int log_to_file;
    char log_file_path[256];
    
    /* Filtering */
    int filter_enabled;
    unsigned long *filtered_syscalls;  /* Array of syscall numbers to filter */
    int filter_count;
    
    /* Entry/Exit tracking */
    int in_syscall;  /* Toggle: 0=entry, 1=exit */
} SyscallTracker;

/**
 * Initialize syscall tracker
 * @param tracker Pointer to tracker structure
 * @param target_pid Process ID to track
 * @param log_file_path Path to log file (NULL to disable file logging)
 * @return 0 on success, -1 on error
 */
int syscall_tracker_init(SyscallTracker *tracker, pid_t target_pid, const char *log_file_path);

/**
 * Start tracking syscalls (attach ptrace)
 * @param tracker Tracker context
 * @return 0 on success, -1 on error
 */
int syscall_tracker_start(SyscallTracker *tracker);

/**
 * Stop tracking syscalls (detach ptrace)
 * @param tracker Tracker context
 * @return 0 on success, -1 on error
 */
int syscall_tracker_stop(SyscallTracker *tracker);

/**
 * Process a syscall event (called from monitoring loop)
 * @param tracker Tracker context
 * @return 0 on success, -1 on error
 */
int syscall_tracker_process_event(SyscallTracker *tracker);

/**
 * Get syscall log entries
 * @param tracker Tracker context
 * @param entries Output array
 * @param max_entries Maximum entries to return
 * @return Number of entries returned
 */
int syscall_tracker_get_logs(SyscallTracker *tracker, SyscallLogEntry *entries, int max_entries);

/**
 * Get syscall statistics
 * @param tracker Tracker context
 * @param stats Output array
 * @param max_stats Maximum stats to return
 * @return Number of stats returned
 */
int syscall_tracker_get_stats(SyscallTracker *tracker, SyscallStats *stats, int max_stats);

/**
 * Set syscall filter (only track these syscalls)
 * @param tracker Tracker context
 * @param syscall_numbers Array of syscall numbers
 * @param count Number of syscalls in array
 * @return 0 on success, -1 on error
 */
int syscall_tracker_set_filter(SyscallTracker *tracker, unsigned long *syscall_numbers, int count);

/**
 * Clear syscall filter (track all syscalls)
 * @param tracker Tracker context
 */
void syscall_tracker_clear_filter(SyscallTracker *tracker);

/**
 * Get syscall name from number
 * @param syscall_number Syscall number
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Pointer to buffer
 */
const char* syscall_number_to_name(unsigned long syscall_number, char *buffer, size_t buffer_size);

/**
 * Cleanup tracker resources
 * @param tracker Tracker context
 */
void syscall_tracker_cleanup(SyscallTracker *tracker);

/**
 * Format syscall log entry as string
 * @param entry Log entry
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Number of characters written
 */
int syscall_format_entry(const SyscallLogEntry *entry, char *buffer, size_t buffer_size);

#endif /* SYSCALL_TRACKER_H */

