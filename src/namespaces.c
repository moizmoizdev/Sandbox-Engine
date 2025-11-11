#define _GNU_SOURCE
#include "namespaces.h"
#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Linux-specific namespace constants */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS  0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

/* Fallback for systems without unshare */
#ifndef __NR_unshare
#define __NR_unshare 272
#endif

static int unshare_namespace(int flags) {
    int ret = syscall(__NR_unshare, flags);
    if (ret < 0) {
        perror("unshare");
        return -1;
    }
    return 0;
}

/**
 * Setup PID namespace isolation
 */
int setup_pid_namespace(void) {
    printf("Setting up PID namespace...\n");
    
    if (unshare_namespace(CLONE_NEWPID) < 0) {
        fprintf(stderr, "Failed to create PID namespace\n");
        return -1;
    }
    
    /* After creating PID namespace, the next fork() will have PID 1 */
    printf("PID namespace created successfully\n");
    return 0;
}

/**
 * Setup mount namespace isolation
 */
int setup_mount_namespace(void) {
    printf("Setting up mount namespace...\n");
    
    if (unshare_namespace(CLONE_NEWNS) < 0) {
        fprintf(stderr, "Failed to create mount namespace\n");
        return -1;
    }
    
    /* Make mounts private to this namespace */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("mount MS_PRIVATE");
        /* Not critical, continue */
    }
    
    printf("Mount namespace created successfully\n");
    return 0;
}

/**
 * Setup network namespace isolation
 */
int setup_network_namespace(void) {
    printf("Setting up network namespace...\n");
    
    if (unshare_namespace(CLONE_NEWNET) < 0) {
        fprintf(stderr, "Failed to create network namespace\n");
        return -1;
    }
    
    /* Create loopback interface in the new namespace */
    /* Note: This requires root privileges or CAP_NET_ADMIN */
    system("ip link set lo up 2>/dev/null");
    
    printf("Network namespace created successfully\n");
    return 0;
}

/**
 * Setup UTS namespace isolation (hostname isolation)
 */
int setup_uts_namespace(const char *hostname) {
    printf("Setting up UTS namespace...\n");
    
    if (unshare_namespace(CLONE_NEWUTS) < 0) {
        fprintf(stderr, "Failed to create UTS namespace\n");
        return -1;
    }
    
    /* Set hostname in the new namespace */
    if (hostname && strlen(hostname) > 0) {
        if (sethostname(hostname, strlen(hostname)) < 0) {
            perror("sethostname");
            /* Not critical, continue */
        } else {
            printf("Hostname set to: %s\n", hostname);
        }
    }
    
    printf("UTS namespace created successfully\n");
    return 0;
}

/**
 * Setup namespaces for the current process
 */
int setup_namespaces(int flags) {
    int ret = 0;
    
    if (flags & NS_PID) {
        if (setup_pid_namespace() < 0) {
            ret = -1;
        }
    }
    
    if (flags & NS_MOUNT) {
        if (setup_mount_namespace() < 0) {
            ret = -1;
        }
    }
    
    if (flags & NS_NET) {
        if (setup_network_namespace() < 0) {
            ret = -1;
        }
    }
    
    if (flags & NS_UTS) {
        if (setup_uts_namespace("sandbox") < 0) {
            ret = -1;
        }
    }
    
    return ret;
}

