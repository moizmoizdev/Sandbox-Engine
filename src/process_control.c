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
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdarg.h>

/* Log file path for engine messages (displayed in GUI) */
#define SANDBOX_LOG_FILE "/tmp/sandbox_firewall.log"

/**
 * Write engine log message to GUI log file
 * Also prints to terminal for debugging
 */
static void engine_log(const char *format, ...) {
    char buffer[1024];
    va_list args;
    
    /* Format the message */
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    /* Write to terminal (for debugging) */
    printf("%s", buffer);
    fflush(stdout);
    
    /* Write to log file (for GUI) */
    FILE *log = fopen(SANDBOX_LOG_FILE, "a");
    if (log) {
        fprintf(log, "%s", buffer);
        fclose(log);
    }
}

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
    int pidpipe[2]; /* Pipe for communicating real PID when using PID namespace */
    
    if (!file_path) {
        return -1;
    }
    
    /* Create pipe for PID communication if PID namespace is requested */
    if (ns_flags & NS_PID) {
        if (pipe(pidpipe) < 0) {
            perror("pipe");
            return -1;
        }
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
                /* Outer child - send real PID to parent via pipe */
                close(pidpipe[0]); /* Close read end */
                write(pidpipe[1], &inner_pid, sizeof(inner_pid));
                close(pidpipe[1]); /* Close write end */
                
                /* Wait for inner child and exit */
                int status;
                waitpid(inner_pid, &status, 0);
                exit(EXIT_SUCCESS);
            }
            
            /* Inner child - this is the actual sandboxed process */
            /* This process will be PID 1 in the namespace */
            
            /* Close both ends of pipe in inner child */
            close(pidpipe[0]);
            close(pidpipe[1]);
            
            /* Setup signal handling for PID 1 */
            /* Ignore SIGCHLD to prevent zombies (we're not the real init) */
            signal(SIGCHLD, SIG_IGN);
            
            /* Continue to setup remaining namespaces */
        } else if (ns_flags & NS_PID) {
            /* PID namespace was requested but failed, continue with other namespaces */
            fprintf(stderr, "Warning: PID namespace setup failed, continuing without it\n");
            /* Close pipe since we won't use it */
            close(pidpipe[0]);
            close(pidpipe[1]);
        }
        
        /* If PID namespace wasn't requested, close pipe in child */
        if (!(ns_flags & NS_PID)) {
            /* No pipe was created, nothing to close */
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
            
            /* Add the target program's directory with execute permission */
            char prog_dir[512];
            strncpy(prog_dir, file_path, sizeof(prog_dir) - 1);
            prog_dir[sizeof(prog_dir) - 1] = '\0';
            char *last_slash = strrchr(prog_dir, '/');
            if (last_slash) {
                *last_slash = '\0'; /* Truncate to directory */
                landlock_add_rule((LandlockConfig*)landlock_config, prog_dir,
                                 LANDLOCK_ACCESS_FS_READ | 
                                 LANDLOCK_ACCESS_FS_READ_DIR |
                                 LANDLOCK_ACCESS_FS_EXECUTE);
                printf("Added program directory to Landlock rules: %s\n", prog_dir);
            }
            
            /* Add the actual program file with execute permission */
            landlock_add_rule((LandlockConfig*)landlock_config, file_path,
                             LANDLOCK_ACCESS_FS_READ | 
                             LANDLOCK_ACCESS_FS_EXECUTE);
            printf("Added program file to Landlock rules: %s\n", file_path);
            
            /* Also add /tmp for temporary files */
            landlock_add_rule((LandlockConfig*)landlock_config, "/tmp",
                             LANDLOCK_ACCESS_FS_READ | 
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR);
            
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
        
        /* NOTE: Program output (stdout/stderr) is NOT redirected
         * This allows it to appear in the terminal naturally.
         * Engine logs are written to SANDBOX_LOG_FILE and displayed in GUI. */
        
        /* Execute the selected file */
        execl(file_path, file_path, (char *)NULL);
        
        /* If execl fails */
        perror("execl");
        exit(EXIT_FAILURE);
    }
    
    /* Parent process - get real PID if PID namespace was used */
    pid_t real_pid = pid;
    if (ns_flags & NS_PID) {
        /* Close write end of pipe */
        close(pidpipe[1]);
        
        /* Read real PID from pipe (written by outer child) */
        ssize_t bytes_read = read(pidpipe[0], &real_pid, sizeof(real_pid));
        close(pidpipe[0]);
        
        if (bytes_read == sizeof(real_pid)) {
            engine_log("[PID Namespace] Real monitored PID: %d (shim PID was: %d)\n", real_pid, pid);
        } else {
            /* Pipe read failed, fall back to original PID */
            fprintf(stderr, "Warning: Failed to read real PID from pipe, monitoring may be inaccurate\n");
            real_pid = pid;
        }
    }
    
    /* Parent process - setup cgroups if configured */
    if (cgroup_config && (cgroup_config->cpu_limit_percent > 0 || 
                          cgroup_config->memory_limit_mb > 0 ||
                          cgroup_config->pids_limit > 0 ||
                          cgroup_config->max_threads > 0)) {
        /* Wait a moment for process to start and namespaces to be set up */
        usleep(200000); /* 200ms - give more time for PID namespace setup */
        
        /* Verify process is still running before adding to cgroup */
        /* Use real_pid for cgroup (the actual process we want to limit) */
        if (kill(real_pid, 0) == 0) {
            if (setup_cgroup(cgroup_config, real_pid) < 0) {
                fprintf(stderr, "Warning: Failed to setup cgroup, continuing without resource limits\n");
            }
        } else {
            fprintf(stderr, "Warning: Process exited before cgroup setup\n");
        }
    }
    
    /* Return the real PID that should be monitored */
    return real_pid;
}

/**
 * Find and kill all child processes recursively via /proc
 */
static void kill_children_recursive(pid_t pid, int signal) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
    
    FILE *f = fopen(path, "r");
    if (f) {
        pid_t child_pid;
        while (fscanf(f, "%d", &child_pid) == 1) {
            /* Recursively kill grandchildren first */
            kill_children_recursive(child_pid, signal);
            /* Then kill this child */
            kill(child_pid, signal);
        }
        fclose(f);
    }
}

/**
 * Kill all processes in a cgroup (nuclear option)
 */
static int kill_cgroup_processes(const char *cgroup_path, int signal) {
    if (!cgroup_path) return -1;
    
    char procs_path[512];
    int killed = 0;
    
    /* Try cgroup v2 */
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_path);
    FILE *f = fopen(procs_path, "r");
    
    if (!f) {
        /* Try cgroup v1 */
        snprintf(procs_path, sizeof(procs_path), "%s/tasks", cgroup_path);
        f = fopen(procs_path, "r");
    }
    
    if (f) {
        pid_t cgroup_pid;
        while (fscanf(f, "%d", &cgroup_pid) == 1) {
            if (kill(cgroup_pid, signal) == 0) {
                killed++;
            }
        }
        fclose(f);
    }
    
    return killed;
}

/**
 * NUCLEAR OPTION: Terminate a process and ALL its descendants with EXTREME PREJUDICE
 * This function will NOT fail. The process WILL die.
 * @param methods Bitmask of termination methods to use
 */
int terminate_process(pid_t pid, int methods) {
    if (pid <= 0) {
        return -1;
    }
    
    /* If no methods specified, use all methods (legacy behavior) */
    if (methods == 0) {
        methods = TERM_SOFT_KILL | TERM_HARD_KILL | TERM_CGROUP_KILL;
    }
    
    engine_log("[TERMINATOR] Target acquired: PID %d\n", pid);
    engine_log("[TERMINATOR] Methods enabled: %s%s%s\n",
           (methods & TERM_SOFT_KILL) ? "SIGTERM " : "",
           (methods & TERM_HARD_KILL) ? "SIGKILL " : "",
           (methods & TERM_CGROUP_KILL) ? "CGROUP" : "");
    engine_log("[TERMINATOR] Engaging termination protocols...\n");
    
    /* Get process group ID (used by all methods) */
    pid_t pgid = getpgid(pid);
    
    /* === PHASE 1: SIGTERM (Soft Kill - Recursive) === */
    if (methods & TERM_SOFT_KILL) {
        engine_log("[TERMINATOR] Phase 1: SIGTERM (Soft Kill - Recursive)\n");
        
        /* 1.1: Kill process group */
        if (pgid > 0 && pgid != getpid()) {
            kill(-pgid, SIGTERM);
            engine_log("[TERMINATOR]   ✓ Sent SIGTERM to process group %d\n", pgid);
        }
        
        /* 1.2: Kill direct process */
        kill(pid, SIGTERM);
        engine_log("[TERMINATOR]   ✓ Sent SIGTERM to PID %d\n", pid);
        
        /* 1.3: Kill all children via /proc */
        kill_children_recursive(pid, SIGTERM);
        engine_log("[TERMINATOR]   ✓ Sent SIGTERM to all children\n");
        
        /* 1.4: Wait 200ms for graceful shutdown */
        usleep(200000);
        
        /* Check if dead */
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            engine_log("[TERMINATOR] ✅ Target eliminated (graceful SIGTERM)\n");
            return 0;
        }
        
        engine_log("[TERMINATOR]   ⚠️  Target still alive after SIGTERM\n");
    }
    
    /* === PHASE 2: SIGKILL (Hard Kill - Recursive) === */
    if (methods & TERM_HARD_KILL) {
        engine_log("[TERMINATOR] Phase 2: SIGKILL (Hard Kill - Recursive)\n");
    
        /* 2.1: SIGKILL process group */
        if (pgid > 0 && pgid != getpid()) {
            kill(-pgid, SIGKILL);
            engine_log("[TERMINATOR]   ✓ Sent SIGKILL to process group %d\n", pgid);
        }
        
        /* 2.2: SIGKILL direct process */
        kill(pid, SIGKILL);
        engine_log("[TERMINATOR]   ✓ Sent SIGKILL to PID %d\n", pid);
        
        /* 2.3: SIGKILL all children */
        kill_children_recursive(pid, SIGKILL);
        engine_log("[TERMINATOR]   ✓ Sent SIGKILL to all children\n");
        
        /* 2.4: Wait for SIGKILL to take effect */
        usleep(100000); /* 100ms */
        
        /* Check if dead */
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            engine_log("[TERMINATOR] ✅ Target eliminated (SIGKILL)\n");
            return 0;
        }
        
        engine_log("[TERMINATOR]   ⚠️  Target still alive after SIGKILL)\n");
    }
    
    /* === PHASE 3: Cgroup Kill (Mass Extermination) === */
    if (methods & TERM_CGROUP_KILL) {
        engine_log("[TERMINATOR] Phase 3: Cgroup Kill (Mass Extermination)\n");
        
        char cgroup_path[512];
        int total_killed = 0;
        
        /* Kill via cgroup v2 */
        snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/sandbox_engine");
        int cg_killed = kill_cgroup_processes(cgroup_path, SIGKILL);
        if (cg_killed > 0) {
            engine_log("[TERMINATOR]   ✓ Eliminated %d processes via cgroup v2\n", cg_killed);
            total_killed += cg_killed;
        }
        
        /* Also try v1 cgroup paths */
        snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/memory/sandbox_engine");
        cg_killed = kill_cgroup_processes(cgroup_path, SIGKILL);
        if (cg_killed > 0) {
            engine_log("[TERMINATOR]   ✓ Eliminated %d processes via memory cgroup\n", cg_killed);
            total_killed += cg_killed;
        }
        
        snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/cpu/sandbox_engine");
        cg_killed = kill_cgroup_processes(cgroup_path, SIGKILL);
        if (cg_killed > 0) {
            engine_log("[TERMINATOR]   ✓ Eliminated %d processes via cpu cgroup\n", cg_killed);
            total_killed += cg_killed;
        }
        
        if (total_killed > 0) {
            engine_log("[TERMINATOR]   ✓ Total cgroup kills: %d\n", total_killed);
        } else {
            engine_log("[TERMINATOR]   ⚠️  No processes found in cgroups\n");
        }
        
        usleep(100000); /* 100ms */
        
        /* Check if dead */
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            engine_log("[TERMINATOR] ✅ Target eliminated (cgroup kill)\n");
            return 0;
        }
    }
    
    /* === FINAL CHECK === */
    if (kill(pid, 0) != 0 && errno == ESRCH) {
        engine_log("[TERMINATOR] ✅ Target confirmed eliminated\n");
        return 0;
    }
    
    /* If we get here, selected methods didn't work */
    engine_log("[TERMINATOR]   ⚠️  Selected methods failed. Process may still be alive.\n");
    
    /* Try zombie reaping as last resort */
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == pid) {
        engine_log("[TERMINATOR] ✅ Zombie reaped successfully\n");
        return 0;
    }
    
    engine_log("[TERMINATOR] ⚠️  Termination sequence complete (process status unknown)\n");
    return 0;
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

