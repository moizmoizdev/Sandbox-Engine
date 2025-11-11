#include "process_control.h"
#include "namespaces.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Create a sandboxed subprocess with control over it
 * Sets up namespace isolation before executing the target program
 */
pid_t create_sandboxed_process(const char *file_path, int ns_flags, const char *uts_hostname) {
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
        
        /* Execute the selected file */
        execl(file_path, file_path, (char *)NULL);
        
        /* If execl fails */
        perror("execl");
        exit(EXIT_FAILURE);
    }
    
    /* Parent process - return child PID */
    return pid;
}

/**
 * Terminate a running process
 */
int terminate_process(pid_t pid) {
    if (pid <= 0) {
        return -1;
    }
    
    /* First try SIGTERM (graceful termination) */
    if (kill(pid, SIGTERM) == 0) {
        /* Wait a bit for graceful shutdown */
        sleep(1);
        
        /* Check if still running */
        if (kill(pid, 0) == 0) {
            /* Process still running, force kill */
            if (kill(pid, SIGKILL) != 0) {
                perror("kill SIGKILL");
                return -1;
            }
        }
        return 0;
    } else {
        /* Process might already be dead */
        if (errno == ESRCH) {
            return 0; /* Process doesn't exist, consider it terminated */
        }
        perror("kill SIGTERM");
        return -1;
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

