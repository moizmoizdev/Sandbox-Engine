#define _GNU_SOURCE
#include "process_control.h"
#include "namespaces.h"
#include "firewall.h"
#include "cgroups.h"
#include "memory_protection.h"
#include "landlock.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

/* Log file path for capturing sandboxed process output */
#define SANDBOX_LOG_FILE "/tmp/sandbox_firewall.log"

/**
 * Create a sandboxed subprocess with control over it
 * Sets up namespace isolation, firewall, memory protection, and cgroups before executing the target program
 */
pid_t create_sandboxed_process(const char *file_path, int ns_flags, const char *uts_hostname,
                                 FirewallPolicy firewall_policy, const char *policy_file,
                                 const CgroupConfig *cgroup_config,
                                 const MemoryProtectionConfig *mem_prot_config,
                                 const LandlockConfig *landlock_config) {
    pid_t pid;
    
    if (!file_path) {
        return -1;
    }
    
    /* Fork a new process */
    pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        /* Child process - setup namespaces */
        
        /* Setup namespaces before executing the target program */
        /* Note: PID namespace requires special handling with double-fork */
        int remaining_ns_flags = ns_flags & ~NS_PID; /* All except PID */
        
        /* Try to setup PID namespace if requested (may require root or capabilities) */
        if ((ns_flags & NS_PID) && setup_pid_namespace() == 0) {
            /* If PID namespace was created, we need to fork again
             * because the first process in PID namespace becomes init (PID 1) */
            pid_t inner_pid = fork();
            
            if (inner_pid < 0) {
                perror("fork (inner)");
                exit(EXIT_FAILURE);
            }
            
            if (inner_pid > 0) {
                /* Parent in PID namespace - wait for child and exit */
                int status;
                waitpid(inner_pid, &status, 0);
                exit(EXIT_SUCCESS);
            }
            
            /* Inner child - this is the actual sandboxed process */
            /* This process will be PID 1 in the namespace */
            
            /* Setup signal handling for PID 1 */
            /* Ignore SIGCHLD to prevent zombies (we're not the real init) */
            signal(SIGCHLD, SIG_IGN);
            
            /* Continue to setup remaining namespaces */
        } else if (ns_flags & NS_PID) {
            /* PID namespace was requested but failed, continue with other namespaces */
            fprintf(stderr, "Warning: PID namespace setup failed, continuing without it\n");
        }
        
        /* Setup remaining namespaces (mount, network) */
        int mount_net_flags = remaining_ns_flags & ~NS_UTS;
        if (mount_net_flags != 0 && setup_namespaces(mount_net_flags) < 0) {
            fprintf(stderr, "Warning: Some namespace setups failed\n");
            /* Continue anyway - partial isolation is better than none */
        }
        
        /* Setup UTS namespace separately with custom hostname */
        if ((ns_flags & NS_UTS)) {
            if (setup_uts_namespace(uts_hostname ? uts_hostname : "sandbox") < 0) {
                fprintf(stderr, "Warning: UTS namespace setup failed\n");
            }
        }
        
        /* Apply Landlock file access restrictions */
        if (landlock_config && landlock_config->enabled) {
            printf("Applying Landlock file access restrictions (policy: %s)\n",
                   landlock_policy_name(landlock_config->policy));
            
            /* Add current working directory to allow program execution */
            char cwd[512];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                /* Add the current directory with read+write+execute access */
                landlock_add_rule((LandlockConfig*)landlock_config, cwd,
                                 LANDLOCK_ACCESS_FS_READ | 
                                 LANDLOCK_ACCESS_FS_WRITE_FILE |
                                 LANDLOCK_ACCESS_FS_EXECUTE);
                printf("Added current directory to Landlock rules: %s\n", cwd);
            }
            
            /* Also add /dev for device access */
            landlock_add_rule((LandlockConfig*)landlock_config, "/dev",
                             LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR);
            
            /* Also add /proc for process info */
            landlock_add_rule((LandlockConfig*)landlock_config, "/proc",
                             LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_READ_DIR);
            
            if (landlock_apply(landlock_config) < 0) {
                fprintf(stderr, "ERROR: Failed to apply Landlock ruleset - file access restrictions NOT active\n");
                /* Continue anyway - partial sandboxing is better than none */
            } else {
                printf("Landlock ruleset successfully applied - file access restrictions are active\n");
            }
        } else {
            printf("Landlock disabled - full file system access\n");
        }
        
        /* Setup firewall */
        if (firewall_policy != FIREWALL_DISABLED) {
            printf("Initializing firewall with policy: %s\n", firewall_policy_name(firewall_policy));
            
            FirewallConfig *fw_config = firewall_init(firewall_policy);
            if (!fw_config) {
                fprintf(stderr, "Warning: Failed to initialize firewall\n");
            } else {
                /* Load policy file if provided (for STRICT, MODERATE, or CUSTOM modes) */
                if (policy_file && (firewall_policy == FIREWALL_CUSTOM || 
                                    firewall_policy == FIREWALL_STRICT ||
                                    firewall_policy == FIREWALL_MODERATE)) {
                    if (firewall_load_policy(fw_config, policy_file) < 0) {
                        fprintf(stderr, "Warning: Failed to load policy from %s\n", policy_file);
                    } else {
                        printf("Loaded %d firewall rules from %s\n", 
                               fw_config->rule_count, policy_file);
                    }
                }
                
                /* Apply firewall rules */
                if (firewall_apply(fw_config) < 0) {
                    fprintf(stderr, "Warning: Failed to apply firewall rules\n");
                }
                
                /* Note: We don't cleanup fw_config here as it needs to stay active
                 * for the sandboxed process. It will be cleaned up when process exits */
            }
        } else {
            printf("Firewall disabled - full network access granted\n");
        }
        
        /* Apply memory protection if configured */
        if (mem_prot_config && mem_prot_config->flags != 0) {
            printf("Applying memory protection (flags=0x%x)\n", mem_prot_config->flags);
            if (apply_memory_protection(mem_prot_config) < 0) {
                fprintf(stderr, "Warning: Some memory protections failed to apply\n");
                /* Continue anyway - partial protection is better than none */
            }
        } else {
            printf("Memory protection disabled\n");
        }
        
        /* Redirect stdout and stderr to log file so GUI can display it */
        int log_fd = open(SANDBOX_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            /* Write separator to log */
            const char *sep = "\n=== Sandbox Process Output ===\n";
            write(log_fd, sep, strlen(sep));
            
            /* Redirect stdout and stderr */
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        
        /* Execute the selected file */
        execl(file_path, file_path, (char *)NULL);
        
        /* If execl fails */
        perror("execl");
        exit(EXIT_FAILURE);
    }
    
    /* Parent process - setup cgroups if configured */
    if (cgroup_config && (cgroup_config->cpu_limit_percent > 0 || 
                          cgroup_config->memory_limit_mb > 0 ||
                          cgroup_config->pids_limit > 0 ||
                          cgroup_config->max_threads > 0)) {
        /* Wait a moment for process to start and namespaces to be set up */
        usleep(200000); /* 200ms - give more time for PID namespace setup */
        
        /* Verify process is still running before adding to cgroup */
        if (kill(pid, 0) == 0) {
            if (setup_cgroup(cgroup_config, pid) < 0) {
                fprintf(stderr, "Warning: Failed to setup cgroup, continuing without resource limits\n");
            }
        } else {
            fprintf(stderr, "Warning: Process exited before cgroup setup\n");
        }
    }
    
    return pid;
}

/**
 * Terminate a running process and its entire process tree
 * Handles PID namespace correctly by killing all descendant processes
 */
int terminate_process(pid_t pid) {
    if (pid <= 0) {
        return -1;
    }
    
    /* First, try to kill the entire process group */
    /* Use negative PID to kill process group (if process is group leader) */
    pid_t pgid = getpgid(pid);
    if (pgid > 0 && pgid != getpid()) {
        /* Kill the process group */
        kill(-pgid, SIGTERM);
    }
    
    /* Also kill the process directly */
    if (kill(pid, SIGTERM) == 0) {
        /* Wait a bit for graceful shutdown */
        int waited = 0;
        for (int i = 0; i < 10; i++) { /* Wait up to 1 second */
            usleep(100000); /* 100ms */
            if (kill(pid, 0) != 0) {
                if (errno == ESRCH) {
                    /* Process is dead */
                    return 0;
                }
            }
        }
        
        /* Check if still running */
        if (kill(pid, 0) == 0) {
            /* Process still running, force kill */
            /* Kill process group first */
            if (pgid > 0 && pgid != getpid()) {
                kill(-pgid, SIGKILL);
            }
            /* Then kill the process directly */
            if (kill(pid, SIGKILL) != 0) {
                if (errno != ESRCH) { /* Ignore if already dead */
                    perror("kill SIGKILL");
                    return -1;
                }
            }
            /* Wait a moment for SIGKILL to take effect */
            usleep(200000); /* 200ms */
        }
        return 0;
    } else {
        /* Process might already be dead */
        if (errno == ESRCH) {
            return 0; /* Process doesn't exist, consider it terminated */
        }
        /* Try SIGKILL anyway */
        kill(pid, SIGKILL);
        return 0; /* Return success even if kill failed (process might be dead) */
    }
}

/**
 * Check if a process is still running
 */
int is_process_running(pid_t pid) {
    if (pid <= 0) {
        return -1;
    }
    
    /* Use kill(pid, 0) to check if process exists */
    if (kill(pid, 0) == 0) {
        return 1; /* Process is running */
    } else {
        if (errno == ESRCH) {
            return 0; /* Process does not exist */
        }
        return -1; /* Error checking process */
    }
}

/**
 * Wait for a process to complete
 */
pid_t wait_for_process(pid_t pid, int *status) {
    pid_t waited_pid;
    
    if (pid <= 0) {
        return -1;
    }
    
    waited_pid = waitpid(pid, status, 0);
    
    if (waited_pid < 0) {
        perror("waitpid");
        return -1;
    }
    
    return waited_pid;
}

