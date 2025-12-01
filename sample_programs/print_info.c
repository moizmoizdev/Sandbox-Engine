/**
 * Print Info Test Program
 * Prints system and process information - useful for basic testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <time.h>

void print_separator(void) {
    printf("----------------------------------------\n");
}

int main(void) {
    printf("\n");
    print_separator();
    printf("=== Sandbox Environment Info ===\n");
    print_separator();
    
    /* Process info */
    printf("\n[Process Information]\n");
    printf("  PID:  %d\n", getpid());
    printf("  PPID: %d\n", getppid());
    printf("  UID:  %d\n", getuid());
    printf("  GID:  %d\n", getgid());
    printf("  EUID: %d\n", geteuid());
    printf("  EGID: %d\n", getegid());
    
    /* System info */
    printf("\n[System Information]\n");
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("  Hostname: %s\n", uts.nodename);
        printf("  System:   %s\n", uts.sysname);
        printf("  Release:  %s\n", uts.release);
        printf("  Version:  %s\n", uts.version);
        printf("  Machine:  %s\n", uts.machine);
    }
    
    /* Resource limits */
    printf("\n[Resource Limits]\n");
    struct rlimit rl;
    
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY) {
            printf("  Stack:   unlimited\n");
        } else {
            printf("  Stack:   %lu KB\n", rl.rlim_cur / 1024);
        }
    }
    
    if (getrlimit(RLIMIT_AS, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY) {
            printf("  Address: unlimited\n");
        } else {
            printf("  Address: %lu MB\n", rl.rlim_cur / (1024 * 1024));
        }
    }
    
    if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
        if (rl.rlim_cur == RLIM_INFINITY) {
            printf("  Procs:   unlimited\n");
        } else {
            printf("  Procs:   %lu\n", rl.rlim_cur);
        }
    }
    
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("  Files:   %lu\n", rl.rlim_cur);
    }
    
    /* Time */
    printf("\n[Time]\n");
    time_t now = time(NULL);
    printf("  Current: %s", ctime(&now));
    
    /* Working directory */
    printf("\n[Environment]\n");
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("  CWD: %s\n", cwd);
    }
    
    /* Check for namespaces */
    printf("\n[Namespace Indicators]\n");
    if (getpid() == 1) {
        printf("  PID namespace: ACTIVE (we are PID 1)\n");
    } else {
        printf("  PID namespace: Not isolated (PID > 1)\n");
    }
    
    if (strcmp(uts.nodename, "sandbox") == 0) {
        printf("  UTS namespace: ACTIVE (hostname is 'sandbox')\n");
    } else {
        printf("  UTS namespace: May not be active\n");
    }
    
    print_separator();
    printf("=== Test Completed Successfully ===\n");
    print_separator();
    printf("\n");
    
    return 0;
}
