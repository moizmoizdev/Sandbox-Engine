#ifndef MEMORY_PROTECTION_H
#define MEMORY_PROTECTION_H

#include <sys/types.h>

/* Memory protection flags */
#define MEM_PROT_DISABLE_EXEC_STACK    (1 << 0)  /* Prevent executable stack */
#define MEM_PROT_DISABLE_EXEC_HEAP     (1 << 1)  /* Prevent executable heap */
#define MEM_PROT_DISABLE_EXEC_ANON      (1 << 2)  /* Prevent anonymous executable mappings */
#define MEM_PROT_DISABLE_WRITE_EXEC     (1 << 3)  /* Prevent writable+executable memory */
#define MEM_PROT_LIMIT_STACK_SIZE       (1 << 4)  /* Limit stack size */
#define MEM_PROT_RESTRICT_MMAP          (1 << 5)  /* Restrict mmap() calls */

/* Memory protection configuration */
typedef struct {
    int flags;                    /* Bitmask of protection flags */
    size_t max_stack_size_kb;     /* Maximum stack size in KB (0 = use default) */
    int restrict_exec_memory;     /* 1 = block all executable memory, 0 = allow */
} MemoryProtectionConfig;

/**
 * Initialize memory protection configuration
 * @param config Configuration structure to initialize
 */
void init_memory_protection_config(MemoryProtectionConfig *config);

/**
 * Apply memory protection to current process
 * This must be called BEFORE exec() in the child process
 * @param config Memory protection configuration
 * @return 0 on success, -1 on error
 */
int apply_memory_protection(const MemoryProtectionConfig *config);

/**
 * Setup seccomp filter to restrict memory syscalls
 * Blocks mmap/mprotect calls that create executable memory
 * @param config Memory protection configuration
 * @return 0 on success, -1 on error
 */
int setup_memory_seccomp_filter(const MemoryProtectionConfig *config);

/**
 * Set stack size limit
 * @param max_stack_kb Maximum stack size in KB
 * @return 0 on success, -1 on error
 */
int set_stack_size_limit(size_t max_stack_kb);

/**
 * Disable executable stack via prctl
 * @return 0 on success, -1 on error
 */
int disable_executable_stack(void);

/**
 * Get human-readable description of active memory protections
 * @param config Memory protection configuration
 * @return Static string with description (do not free)
 */
const char* get_memory_protection_description(const MemoryProtectionConfig *config);

#endif /* MEMORY_PROTECTION_H */

