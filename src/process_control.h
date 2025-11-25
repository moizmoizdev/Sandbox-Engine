#ifndef PROCESS_CONTROL_H
#define PROCESS_CONTROL_H

#include <sys/types.h>
#include "firewall.h"
#include "cgroups.h"

/**
 * Create a sandboxed subprocess with control over it
 * @param file_path Path to the executable file to run
 * @param ns_flags Bitmask of namespaces to enable (NS_PID, NS_MOUNT, NS_NET, NS_UTS)
 * @param uts_hostname Hostname to set in UTS namespace (NULL for default "sandbox")
 * @param firewall_policy Firewall policy to apply
 * @param policy_file Custom policy file path (NULL for built-in policies)
 * @param cgroup_config Cgroup configuration (NULL to skip cgroups)
 * @return Process ID of the created subprocess, or -1 on error
 */
pid_t create_sandboxed_process(const char *file_path, int ns_flags, const char *uts_hostname,
                                 FirewallPolicy firewall_policy, const char *policy_file,
                                 const CgroupConfig *cgroup_config);

/**
 * Terminate a running process
 * @param pid Process ID to terminate
 * @return 0 on success, -1 on error
 */
int terminate_process(pid_t pid);

/**
 * Check if a process is still running
 * @param pid Process ID to check
 * @return 1 if running, 0 if not running, -1 on error
 */
int is_process_running(pid_t pid);

/**
 * Wait for a process to complete
 * @param pid Process ID to wait for
 * @param status Pointer to store exit status
 * @return Process ID on success, -1 on error
 */
pid_t wait_for_process(pid_t pid, int *status);

#endif /* PROCESS_CONTROL_H */

