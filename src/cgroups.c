#define _GNU_SOURCE
#include "cgroups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* Cgroup v2 path */
#define CGROUP_V2_PATH "/sys/fs/cgroup"
/* Cgroup v1 paths */
#define CGROUP_V1_CPU_PATH "/sys/fs/cgroup/cpu"
#define CGROUP_V1_MEMORY_PATH "/sys/fs/cgroup/memory"
#define CGROUP_V1_PIDS_PATH "/sys/fs/cgroup/pids"
#define CGROUP_V1_CPUSET_PATH "/sys/fs/cgroup/cpuset"

/* Our cgroup name */
#define CGROUP_NAME "sandbox_engine"

static int cgroup_version = 0; /* 0 = unknown, 1 = v1, 2 = v2 */

/**
 * Detect cgroup version
 */
static int read_cgroup_version(void) {
    struct stat st;
    
    /* Check for cgroup v2 */
    if (stat(CGROUP_V2_PATH, &st) == 0 && S_ISDIR(st.st_mode)) {
        /* Check if it's actually v2 by looking for cgroup.controllers */
        char controllers_path[256];
        snprintf(controllers_path, sizeof(controllers_path), "%s/cgroup.controllers", CGROUP_V2_PATH);
        if (access(controllers_path, F_OK) == 0) {
            return 2;
        }
    }
    
    /* Check for cgroup v1 */
    if (stat(CGROUP_V1_CPU_PATH, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    
    return 0; /* Unknown */
}

/**
 * Write string to file
 */
static int write_to_file(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (!f) {
        return -1;
    }
    
    int ret = fprintf(f, "%s", value);
    fclose(f);
    
    return (ret < 0) ? -1 : 0;
}

/**
 * Create cgroup directory
 */
static int create_cgroup(char *cgroup_path, size_t path_size) {
    if (cgroup_version == 0) {
        cgroup_version = read_cgroup_version();
    }
    
    if (cgroup_version == 2) {
        /* Cgroup v2 */
        snprintf(cgroup_path, path_size, "%s/%s", CGROUP_V2_PATH, CGROUP_NAME);
    } else if (cgroup_version == 1) {
        /* Cgroup v1 - use memory controller as base */
        snprintf(cgroup_path, path_size, "%s/%s", CGROUP_V1_MEMORY_PATH, CGROUP_NAME);
    } else {
        fprintf(stderr, "Error: Cannot detect cgroup version\n");
        return -1;
    }
    
    /* Create directory */
    if (mkdir(cgroup_path, 0755) != 0 && errno != EEXIST) {
        perror("mkdir cgroup");
        return -1;
    }
    
    return 0;
}

/**
 * Add process to cgroup
 */
static int add_process_to_cgroup(const char *cgroup_path, pid_t pid) {
    char procs_path[512];
    
    if (cgroup_version == 2) {
        snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
    } else {
        snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
    }
    
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    
    return write_to_file(procs_path, pid_str);
}

/**
 * Set CPU limit
 */
static int set_cpu_limit(const char *cgroup_path, int cpu_percent) {
    if (cpu_percent <= 0 || cpu_percent > 100) {
        return 0; /* No limit */
    }
    
    char cpu_path[512];
    
    if (cgroup_version == 2) {
        snprintf(cpu_path, sizeof(cpu_path), "%s/cpu.max", cgroup_path);
        /* Format: "quota period" in microseconds
         * Period is standard 100000us (100ms)
         * Quota = (percent * 100000) / 100
         * Example: 5% = 5000us out of 100000us */
        char cpu_value[64];
        int quota = (cpu_percent * 100000) / 100;
        snprintf(cpu_value, sizeof(cpu_value), "%d 100000", quota);
        return write_to_file(cpu_path, cpu_value);
    } else {
        /* Cgroup v1 */
        snprintf(cpu_path, sizeof(cpu_path), "%s/cpu.cfs_quota_us", cgroup_path);
        /* Calculate quota: period is 100000us, quota = percent * period / 100 */
        int quota = (cpu_percent * 100000) / 100;
        char cpu_value[32];
        snprintf(cpu_value, sizeof(cpu_value), "%d", quota);
        return write_to_file(cpu_path, cpu_value);
    }
}

/**
 * Set memory limit
 */
static int set_memory_limit(const char *cgroup_path, int memory_mb) {
    if (memory_mb <= 0) {
        return 0; /* No limit */
    }
    
    char mem_path[512];
    snprintf(mem_path, sizeof(mem_path), "%s/memory.max", cgroup_path);
    
    /* Convert MB to bytes */
    long long memory_bytes = (long long)memory_mb * 1024 * 1024;
    char mem_value[64];
    snprintf(mem_value, sizeof(mem_value), "%lld", memory_bytes);
    
    return write_to_file(mem_path, mem_value);
}

/**
 * Set process count limit
 */
static int set_pids_limit(const char *cgroup_path, int pids_limit) {
    if (pids_limit <= 0) {
        return 0; /* No limit */
    }
    
    char pids_path[512];
    snprintf(pids_path, sizeof(pids_path), "%s/pids.max", cgroup_path);
    
    char pids_value[32];
    snprintf(pids_value, sizeof(pids_value), "%d", pids_limit);
    
    return write_to_file(pids_path, pids_value);
}

/**
 * Set maximum CPU cores/threads
 */
static int set_max_threads(const char *cgroup_path, int max_threads) {
    if (max_threads <= 0) {
        return 0; /* No limit */
    }
    
    /* Get number of available CPUs */
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) {
        num_cpus = 1;
    }
    
    /* Limit to available CPUs */
    if (max_threads > num_cpus) {
        max_threads = num_cpus;
    }
    
    char cpuset_path[512];
    
    if (cgroup_version == 2) {
        snprintf(cpuset_path, sizeof(cpuset_path), "%s/cpuset.cpus", cgroup_path);
    } else {
        snprintf(cpuset_path, sizeof(cpuset_path), "%s/%s/cpuset.cpus", CGROUP_V1_CPUSET_PATH, CGROUP_NAME);
        /* Create cpuset cgroup if v1 */
        char cpuset_cgroup[256];
        snprintf(cpuset_cgroup, sizeof(cpuset_cgroup), "%s/%s", CGROUP_V1_CPUSET_PATH, CGROUP_NAME);
        mkdir(cpuset_cgroup, 0755);
        
        /* Set cpuset.mems for v1 */
        char mems_path[256];
        snprintf(mems_path, sizeof(mems_path), "%s/cpuset.mems", cpuset_cgroup);
        write_to_file(mems_path, "0");
    }
    
    /* Format: "0-3" for CPUs 0-3, or "0,1,2,3" */
    char cpus_value[32];
    if (max_threads == 1) {
        snprintf(cpus_value, sizeof(cpus_value), "0");
    } else {
        snprintf(cpus_value, sizeof(cpus_value), "0-%d", max_threads - 1);
    }
    
    return write_to_file(cpuset_path, cpus_value);
}

int init_cgroup_config(CgroupConfig *config, int cpu_limit, int memory_limit_mb, 
                       int pids_limit, int max_threads) {
    if (!config) {
        return -1;
    }
    
    config->cpu_limit_percent = cpu_limit;
    config->memory_limit_mb = memory_limit_mb;
    config->pids_limit = pids_limit;
    config->max_threads = max_threads;
    config->cgroup_path = NULL;
    
    return 0;
}

void free_cgroup_config(CgroupConfig *config) {
    if (config && config->cgroup_path) {
        free(config->cgroup_path);
        config->cgroup_path = NULL;
    }
}

int setup_cgroup(const CgroupConfig *config, pid_t pid) {
    if (!config || pid <= 0) {
        return -1;
    }
    
    /* Detect cgroup version */
    if (cgroup_version == 0) {
        cgroup_version = read_cgroup_version();
        if (cgroup_version == 0) {
            fprintf(stderr, "Error: Cannot detect cgroup version\n");
            return -1;
        }
    }
    
    /* For cgroup v2, enable CPU and memory controllers in parent cgroup */
    if (cgroup_version == 2) {
        /* Try to enable controllers - may fail without root, that's OK */
        write_to_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids");
    }
    
    /* Create cgroup */
    char cgroup_path[512];
    if (create_cgroup(cgroup_path, sizeof(cgroup_path)) < 0) {
        return -1;
    }
    
    /* Store path in config (allocate memory) */
    if (config->cgroup_path) {
        free((void*)config->cgroup_path);
    }
    ((CgroupConfig*)config)->cgroup_path = strdup(cgroup_path);
    
    /* Add process to cgroup */
    if (add_process_to_cgroup(cgroup_path, pid) < 0) {
        perror("add_process_to_cgroup");
        return -1;
    }
    
    /* Apply limits */
    if (config->cpu_limit_percent > 0) {
        if (set_cpu_limit(cgroup_path, config->cpu_limit_percent) < 0) {
            fprintf(stderr, "Warning: Failed to set CPU limit\n");
        }
    }
    
    if (config->memory_limit_mb > 0) {
        if (set_memory_limit(cgroup_path, config->memory_limit_mb) < 0) {
            fprintf(stderr, "Warning: Failed to set memory limit\n");
        }
    }
    
    if (config->pids_limit > 0) {
        if (set_pids_limit(cgroup_path, config->pids_limit) < 0) {
            fprintf(stderr, "Warning: Failed to set PIDs limit\n");
        }
    }
    
    if (config->max_threads > 0) {
        if (set_max_threads(cgroup_path, config->max_threads) < 0) {
            fprintf(stderr, "Warning: Failed to set max threads\n");
        }
    }
    
    return 0;
}

int cleanup_cgroup(const CgroupConfig *config) {
    if (!config || !config->cgroup_path) {
        return 0;
    }
    
    /* Remove cgroup directory */
    if (rmdir(config->cgroup_path) != 0 && errno != ENOENT) {
        perror("rmdir cgroup");
        return -1;
    }
    
    return 0;
}

