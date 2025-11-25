#ifndef CGROUPS_H
#define CGROUPS_H

#include <sys/types.h>

/**
 * Cgroup configuration structure
 */
typedef struct {
    int cpu_limit_percent;      /* CPU limit as percentage (0-100, 0 = unlimited) */
    int memory_limit_mb;        /* Memory limit in MB (0 = unlimited) */
    int pids_limit;             /* Maximum number of processes (0 = unlimited) */
    int max_threads;            /* Maximum number of CPU cores/threads (0 = unlimited) */
    char *cgroup_path;          /* Path to cgroup directory */
} CgroupConfig;

/**
 * Initialize a cgroup configuration
 * @param config Pointer to CgroupConfig structure to initialize
 * @param cpu_limit CPU limit percentage (0-100, 0 = unlimited)
 * @param memory_limit_mb Memory limit in MB (0 = unlimited)
 * @param pids_limit Maximum number of processes (0 = unlimited)
 * @param max_threads Maximum number of CPU cores/threads (0 = unlimited)
 * @return 0 on success, -1 on error
 */
int init_cgroup_config(CgroupConfig *config, int cpu_limit, int memory_limit_mb, 
                       int pids_limit, int max_threads);

/**
 * Free cgroup configuration resources
 * @param config Pointer to CgroupConfig structure to free
 */
void free_cgroup_config(CgroupConfig *config);

/**
 * Setup cgroup for a process
 * @param config Cgroup configuration
 * @param pid Process ID to add to cgroup
 * @return 0 on success, -1 on error
 */
int setup_cgroup(const CgroupConfig *config, pid_t pid);

/**
 * Cleanup cgroup directory
 * @param config Cgroup configuration
 * @return 0 on success, -1 on error
 */
int cleanup_cgroup(const CgroupConfig *config);

#endif /* CGROUPS_H */

