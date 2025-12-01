#ifndef SANDBOX_H
#define SANDBOX_H

#include <sys/types.h>

/**
 * Initialize sandboxing features
 * This will be expanded to include namespaces, cgroups, seccomp, etc.
 * @return 0 on success, -1 on error
 */
int init_sandbox(void);

/**
 * Apply sandboxing restrictions to current process
 * @return 0 on success, -1 on error
 */
int apply_sandbox_restrictions(void);

#endif /* SANDBOX_H */

