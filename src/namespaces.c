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
#include <limits.h>

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

    /* Optional OS info spoofing: bind-mount a fake /etc/os-release if present.
     * This is purely inside the mount namespace and does NOT affect the host.
     *
     * Layout expected (relative to the directory where ./main is started):
     *   fake_root/etc/os-release
     */
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        char fake_os_release[PATH_MAX];
        snprintf(fake_os_release, sizeof(fake_os_release),
                 "%s/fake_root/etc/os-release", cwd);

        struct stat st;
        if (stat(fake_os_release, &st) == 0 && S_ISREG(st.st_mode)) {
            if (mount(fake_os_release, "/etc/os-release", NULL, MS_BIND, NULL) == 0) {
                printf("Bound fake /etc/os-release from %s\n", fake_os_release);
            } else {
                perror("mount fake /etc/os-release");
            }
        } else {
            /* If fake file is missing, just skip spoofing */
            /* fprintf(stderr, "Note: fake_root/etc/os-release not found, skipping OS spoofing\n"); */
        }
    }

    printf("Mount namespace created successfully\n");
    return 0;
}

/**
 * Setup network namespace isolation (basic - loopback only)
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
 * Configure the namespace side of the veth interface
 * This is called from inside the network namespace
 */
int configure_veth_inside_namespace(pid_t pid) {
    char veth_name[32];
    char cmd[512];
    
    /* Generate unique veth name based on PID */
    snprintf(veth_name, sizeof(veth_name), "veth1_%d", pid);
    
    /* Bring up loopback first */
    if (system("ip link set lo up 2>/dev/null") != 0) {
        fprintf(stderr, "Warning: Failed to bring up loopback\n");
    }
    
    /* Wait a moment for veth interface to appear */
    usleep(100000); /* 100ms */
    
    /* Configure IP address on veth interface (namespace side) */
    snprintf(cmd, sizeof(cmd), 
             "ip addr add 10.200.%d.2/24 dev %s 2>/dev/null",
             (pid % 250) + 1, veth_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to configure veth IP address\n");
        return -1;
    }
    
    /* Bring up the veth interface */
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", veth_name);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to bring up veth interface\n");
        return -1;
    }
    
    /* Add default route through the veth gateway */
    snprintf(cmd, sizeof(cmd),
             "ip route add default via 10.200.%d.1 2>/dev/null",
             (pid % 250) + 1);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to add default route\n");
        return -1;
    }
    
    /* Configure DNS - use Google DNS and Cloudflare DNS */
    FILE *resolv = fopen("/etc/resolv.conf", "w");
    if (resolv) {
        fprintf(resolv, "nameserver 8.8.8.8\n");
        fprintf(resolv, "nameserver 8.8.4.4\n");
        fprintf(resolv, "nameserver 1.1.1.1\n");
        fclose(resolv);
        printf("✓ DNS configured (8.8.8.8, 1.1.1.1)\n");
    } else {
        fprintf(stderr, "Warning: Failed to configure DNS\n");
    }
    
    printf("✓ Network interface configured: %s (10.200.%d.2/24)\n", 
           veth_name, (pid % 250) + 1);
    printf("✓ Default gateway: 10.200.%d.1\n", (pid % 250) + 1);
    printf("✓ Internet connectivity enabled\n");
    
    return 0;
}

/**
 * Check if ip command is available
 */
static int is_ip_available(void) {
    if (access("/usr/sbin/ip", X_OK) == 0) return 1;
    if (access("/sbin/ip", X_OK) == 0) return 1;
    if (access("/usr/bin/ip", X_OK) == 0) return 1;
    
    int ret = system("ip --version >/dev/null 2>&1");
    return (ret == 0);
}

/**
 * Setup network namespace with internet connectivity
 * This is called from the HOST side (parent process)
 * Creates veth pair and configures NAT
 */
int setup_network_namespace_with_internet(pid_t pid) {
    char veth_host[32], veth_ns[32];
    char cmd[512];
    int ret = 0;
    
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID for network setup\n");
        return -1;
    }
    
    /* Check if ip command is available */
    if (!is_ip_available()) {
        fprintf(stderr, "ip command not found - network connectivity disabled\n");
        fprintf(stderr, "Install iproute2: sudo apt-get install iproute2\n");
        return -1;
    }
    
    /* Generate unique veth names based on PID */
    snprintf(veth_host, sizeof(veth_host), "veth0_%d", pid);
    snprintf(veth_ns, sizeof(veth_ns), "veth1_%d", pid);
    
    printf("Setting up veth pair for PID %d...\n", pid);
    
    /* Create veth pair */
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/ip link add %s type veth peer name %s 2>/dev/null || /sbin/ip link add %s type veth peer name %s 2>/dev/null || ip link add %s type veth peer name %s 2>/dev/null",
             veth_host, veth_ns, veth_host, veth_ns, veth_host, veth_ns);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to create veth pair (check if iproute2 is installed)\n");
        return -1;
    }
    printf("  ✓ Created veth pair: %s <-> %s\n", veth_host, veth_ns);
    
    /* Move one end of veth into the namespace */
    snprintf(cmd, sizeof(cmd),
             "/usr/sbin/ip link set %s netns %d 2>/dev/null || /sbin/ip link set %s netns %d 2>/dev/null || ip link set %s netns %d 2>/dev/null",
             veth_ns, pid, veth_ns, pid, veth_ns, pid);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to move veth into namespace\n");
        /* Cleanup the veth pair we just created */
        snprintf(cmd, sizeof(cmd), "/usr/sbin/ip link delete %s 2>/dev/null || /sbin/ip link delete %s 2>/dev/null || ip link delete %s 2>/dev/null", veth_host, veth_host, veth_host);
        system(cmd);
        return -1;
    }
    printf("  ✓ Moved %s into namespace (PID %d)\n", veth_ns, pid);
    
    /* Configure IP on host side of veth */
    snprintf(cmd, sizeof(cmd),
             "ip addr add 10.200.%d.1/24 dev %s 2>/dev/null",
             (pid % 250) + 1, veth_host);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to configure host veth IP\n");
        ret = -1;
    }
    
    /* Bring up host side of veth */
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", veth_host);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to bring up host veth\n");
        ret = -1;
    }
    printf("  ✓ Configured host interface: %s (10.200.%d.1/24)\n", 
           veth_host, (pid % 250) + 1);
    
    /* Enable IP forwarding on host (if not already enabled) */
    system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    
    /* Setup NAT/masquerading for the sandbox subnet */
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -A POSTROUTING -s 10.200.%d.0/24 -j MASQUERADE 2>/dev/null",
             (pid % 250) + 1);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to setup NAT (may already exist)\n");
    } else {
        printf("  ✓ NAT/masquerading enabled for 10.200.%d.0/24\n", (pid % 250) + 1);
    }
    
    /* Allow forwarding from/to the sandbox */
    snprintf(cmd, sizeof(cmd),
             "iptables -A FORWARD -s 10.200.%d.0/24 -j ACCEPT 2>/dev/null",
             (pid % 250) + 1);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd),
             "iptables -A FORWARD -d 10.200.%d.0/24 -j ACCEPT 2>/dev/null",
             (pid % 250) + 1);
    system(cmd);
    
    printf("✓ Network connectivity setup complete (host side)\n");
    printf("  → The sandboxed process must call configure_veth_inside_namespace()\n");
    
    return ret;
}

/**
 * Cleanup network namespace resources
 * Removes veth interfaces and NAT rules
 */
int cleanup_network_namespace(pid_t pid) {
    char veth_host[32];
    char cmd[512];
    
    if (pid <= 0) {
        return -1;
    }
    
    snprintf(veth_host, sizeof(veth_host), "veth0_%d", pid);
    
    /* Remove NAT rule */
    snprintf(cmd, sizeof(cmd),
             "iptables -t nat -D POSTROUTING -s 10.200.%d.0/24 -j MASQUERADE 2>/dev/null",
             (pid % 250) + 1);
    system(cmd);
    
    /* Remove forward rules */
    snprintf(cmd, sizeof(cmd),
             "iptables -D FORWARD -s 10.200.%d.0/24 -j ACCEPT 2>/dev/null",
             (pid % 250) + 1);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd),
             "iptables -D FORWARD -d 10.200.%d.0/24 -j ACCEPT 2>/dev/null",
             (pid % 250) + 1);
    system(cmd);
    
    /* Delete veth pair (deleting one end deletes both) */
    snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null", veth_host);
    system(cmd);
    
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

