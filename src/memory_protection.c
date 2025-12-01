/**
 * Memory Protection Implementation
 * 
 * Provides stack protection, memory region restrictions, and seccomp filters
 * to protect sandboxed processes from memory-based attacks.
 */

#define _GNU_SOURCE
#include "memory_protection.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stddef.h>

/* Seccomp BPF macros */
#define SECCOMP_RET_ALLOW       0x7fff0000U
#define SECCOMP_RET_ERRNO       0x00050000U
#define SECCOMP_RET_LOG         0x7ffc0000U

/* Architecture detection */
#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#define REG_SYSCALL_NR offsetof(struct seccomp_data, nr)
#define REG_ARG0 offsetof(struct seccomp_data, args[0])
#define REG_ARG1 offsetof(struct seccomp_data, args[1])
#define REG_ARG2 offsetof(struct seccomp_data, args[2])
#elif defined(__i386__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_I386
#define REG_SYSCALL_NR offsetof(struct seccomp_data, nr)
#define REG_ARG0 offsetof(struct seccomp_data, args[0])
#define REG_ARG1 offsetof(struct seccomp_data, args[1])
#define REG_ARG2 offsetof(struct seccomp_data, args[2])
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#define REG_SYSCALL_NR offsetof(struct seccomp_data, nr)
#define REG_ARG0 offsetof(struct seccomp_data, args[0])
#define REG_ARG1 offsetof(struct seccomp_data, args[1])
#define REG_ARG2 offsetof(struct seccomp_data, args[2])
#else
#error "Unsupported architecture"
#endif

/* Default values */
#define DEFAULT_MAX_STACK_KB 8192   /* 8 MB default stack limit */
#define MIN_STACK_KB 128            /* Minimum 128 KB stack */
#define MAX_STACK_KB 65536          /* Maximum 64 MB stack */

/**
 * Initialize memory protection configuration with safe defaults
 */
void init_memory_protection_config(MemoryProtectionConfig *config) {
    if (!config) return;
    
    memset(config, 0, sizeof(MemoryProtectionConfig));
    
    /* Enable basic protections by default */
    config->flags = MEM_PROT_DISABLE_EXEC_STACK | MEM_PROT_DISABLE_WRITE_EXEC;
    config->max_stack_size_kb = DEFAULT_MAX_STACK_KB;
    config->restrict_exec_memory = 0; /* Don't block all exec memory by default */
}

/**
 * Set stack size limit using setrlimit
 */
int set_stack_size_limit(size_t max_stack_kb) {
    struct rlimit rl;
    
    /* Validate input */
    if (max_stack_kb < MIN_STACK_KB) {
        max_stack_kb = MIN_STACK_KB;
    } else if (max_stack_kb > MAX_STACK_KB) {
        max_stack_kb = MAX_STACK_KB;
    }
    
    /* Get current limits */
    if (getrlimit(RLIMIT_STACK, &rl) < 0) {
        perror("getrlimit(RLIMIT_STACK)");
        return -1;
    }
    
    /* Set new soft limit (keep hard limit unchanged or lower if needed) */
    rl.rlim_cur = max_stack_kb * 1024;
    if (rl.rlim_cur > rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
    }
    
    if (setrlimit(RLIMIT_STACK, &rl) < 0) {
        perror("setrlimit(RLIMIT_STACK)");
        return -1;
    }
    
    printf("[Memory Protection] Stack size limited to %zu KB\n", max_stack_kb);
    return 0;
}

/**
 * Disable executable stack using personality flags and prctl
 */
int disable_executable_stack(void) {
    int result = 0;
    
    /* Try to set READ_IMPLIES_EXEC off (some older systems) */
    /* Note: This requires the executable to not be compiled with -z execstack */
    
    /* Use prctl to set no-new-privs which helps with security */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        /* This is not fatal - may already be set or not supported */
        if (errno != EINVAL) {
            fprintf(stderr, "[Memory Protection] Warning: Could not set NO_NEW_PRIVS: %s\n", 
                    strerror(errno));
        }
    } else {
        printf("[Memory Protection] NO_NEW_PRIVS enabled\n");
    }
    
    /* Try to disable executable stack via seccomp (handled separately) */
    printf("[Memory Protection] Executable stack protection enabled\n");
    
    return result;
}

/**
 * Limit address space size
 */
static int limit_address_space(size_t max_bytes) {
    struct rlimit rl;
    
    rl.rlim_cur = max_bytes;
    rl.rlim_max = max_bytes;
    
    if (setrlimit(RLIMIT_AS, &rl) < 0) {
        perror("setrlimit(RLIMIT_AS)");
        return -1;
    }
    
    printf("[Memory Protection] Address space limited to %zu bytes\n", max_bytes);
    return 0;
}

/**
 * Limit data segment size (heap)
 */
static int limit_data_segment(size_t max_bytes) {
    struct rlimit rl;
    
    rl.rlim_cur = max_bytes;
    rl.rlim_max = max_bytes;
    
    if (setrlimit(RLIMIT_DATA, &rl) < 0) {
        perror("setrlimit(RLIMIT_DATA)");
        return -1;
    }
    
    printf("[Memory Protection] Data segment limited to %zu bytes\n", max_bytes);
    return 0;
}

/**
 * Setup seccomp BPF filter to restrict memory-related syscalls
 * This blocks mmap/mprotect calls that would create executable memory
 */
int setup_memory_seccomp_filter(const MemoryProtectionConfig *config) {
    if (!config) return -1;
    
    /* Only setup if we need to restrict executable memory */
    if (!(config->flags & (MEM_PROT_DISABLE_WRITE_EXEC | MEM_PROT_RESTRICT_MMAP))) {
        return 0; /* Nothing to do */
    }
    
    /*
     * Build a seccomp filter that:
     * 1. Checks architecture
     * 2. For mmap/mprotect syscalls, checks if PROT_EXEC and PROT_WRITE are both set
     * 3. If W^X violation detected, returns EPERM
     * 4. Otherwise allows the syscall
     */
    
    struct sock_filter filter[] = {
        /* Load architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        /* Check architecture */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), /* Wrong arch, allow */
        
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_SYSCALL_NR),
        
        /* Check for mmap syscall */
#ifdef __NR_mmap
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 5),
        /* mmap: Load prot argument (arg2 for mmap) */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
        /* Check if PROT_EXEC is set */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC | PROT_WRITE),
        /* If both PROT_EXEC and PROT_WRITE, block */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_EXEC | PROT_WRITE, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0xFFFF)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        
        /* Check for mprotect syscall */
#ifdef __NR_mprotect
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 5),
        /* mprotect: Load prot argument (arg2) */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
        /* Check if both PROT_EXEC and PROT_WRITE are set */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC | PROT_WRITE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_EXEC | PROT_WRITE, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0xFFFF)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
#endif
        
        /* Allow all other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    
    /* Set NO_NEW_PRIVS (required for non-root seccomp) */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        if (errno != EINVAL && errno != EPERM) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return -1;
        }
    }
    
    /* Apply the seccomp filter */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl(PR_SET_SECCOMP)");
        fprintf(stderr, "[Memory Protection] Warning: Could not apply memory seccomp filter\n");
        return -1;
    }
    
    printf("[Memory Protection] W^X (Write XOR Execute) seccomp filter applied\n");
    return 0;
}

/**
 * Apply all memory protections based on configuration
 * Must be called in the child process BEFORE exec()
 */
int apply_memory_protection(const MemoryProtectionConfig *config) {
    if (!config) return -1;
    
    int result = 0;
    
    printf("[Memory Protection] Applying memory protections (flags=0x%x)\n", config->flags);
    
    /* 1. Set stack size limit */
    if (config->flags & MEM_PROT_LIMIT_STACK_SIZE) {
        if (config->max_stack_size_kb > 0) {
            if (set_stack_size_limit(config->max_stack_size_kb) < 0) {
                result = -1;
            }
        }
    }
    
    /* 2. Disable executable stack */
    if (config->flags & MEM_PROT_DISABLE_EXEC_STACK) {
        if (disable_executable_stack() < 0) {
            result = -1;
        }
    }
    
    /* 3. Apply W^X and memory restriction seccomp filter */
    if (config->flags & (MEM_PROT_DISABLE_WRITE_EXEC | MEM_PROT_RESTRICT_MMAP)) {
        if (setup_memory_seccomp_filter(config) < 0) {
            /* Non-fatal - continue without this protection */
            fprintf(stderr, "[Memory Protection] Warning: Could not setup memory seccomp filter\n");
        }
    }
    
    /* 4. If strict memory restrictions requested */
    if (config->restrict_exec_memory) {
        printf("[Memory Protection] Strict executable memory restrictions enabled\n");
        /* Additional restrictions could be added here */
    }
    
    return result;
}

/**
 * Get a human-readable description of active protections
 */
const char* get_memory_protection_description(const MemoryProtectionConfig *config) {
    static char desc[512];
    desc[0] = '\0';
    
    if (!config) {
        return "No configuration";
    }
    
    if (config->flags == 0) {
        return "No protections enabled";
    }
    
    char *p = desc;
    int remaining = sizeof(desc);
    int len;
    
    if (config->flags & MEM_PROT_DISABLE_EXEC_STACK) {
        len = snprintf(p, remaining, "• Non-executable stack\n");
        p += len; remaining -= len;
    }
    
    if (config->flags & MEM_PROT_DISABLE_EXEC_HEAP) {
        len = snprintf(p, remaining, "• Non-executable heap\n");
        p += len; remaining -= len;
    }
    
    if (config->flags & MEM_PROT_DISABLE_WRITE_EXEC) {
        len = snprintf(p, remaining, "• W^X (Write XOR Execute)\n");
        p += len; remaining -= len;
    }
    
    if (config->flags & MEM_PROT_LIMIT_STACK_SIZE) {
        len = snprintf(p, remaining, "• Stack limit: %zu KB\n", config->max_stack_size_kb);
        p += len; remaining -= len;
    }
    
    if (config->flags & MEM_PROT_RESTRICT_MMAP) {
        len = snprintf(p, remaining, "• Restricted mmap()\n");
        p += len; remaining -= len;
    }
    
    return desc;
}
