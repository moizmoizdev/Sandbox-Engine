#ifndef NAMESPACES_H
#define NAMESPACES_H

#include <sys/types.h>

/* Namespace configuration flags */
#define NS_PID    (1 << 0)  /* PID namespace */
#define NS_MOUNT  (1 << 1)  /* Mount namespace */
#define NS_NET    (1 << 2)  /* Network namespace */
#define NS_UTS    (1 << 3)  /* UTS namespace */
#define NS_ALL    (NS_PID | NS_MOUNT | NS_NET | NS_UTS)

/**
 * Setup namespaces for the current process
 * @param flags Bitmask of namespaces to create (NS_PID, NS_MOUNT, NS_NET, NS_UTS)
 * @return 0 on success, -1 on error
 */
int setup_namespaces(int flags);

/**
 * Setup PID namespace isolation
 * @return 0 on success, -1 on error
 */
int setup_pid_namespace(void);

/**
 * Setup mount namespace isolation
 * @return 0 on success, -1 on error
 */
int setup_mount_namespace(void);

/**
 * Setup network namespace isolation
 * @return 0 on success, -1 on error
 */
int setup_network_namespace(void);

/**
 * Setup UTS namespace isolation (hostname isolation)
 * @param hostname Hostname to set in the new namespace
 * @return 0 on success, -1 on error
 */
int setup_uts_namespace(const char *hostname);

#endif /* NAMESPACES_H */

