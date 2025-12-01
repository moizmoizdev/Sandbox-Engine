/*
 * Simple sandbox test without network features
 * Tests basic isolation without requiring iptables
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

int main() {
    printf("╔═══════════════════════════════════════╗\n");
    printf("║     Simple Sandbox Functionality Test ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");
    
    printf("=== Process Information ===\n");
    printf("PID: %d\n", getpid());
    printf("PPID: %d\n", getppid());
    printf("UID: %d\n", getuid());
    printf("GID: %d\n", getgid());
    
    printf("\n=== Hostname ===\n");
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("Hostname: %s\n", hostname);
    } else {
        printf("Failed to get hostname\n");
    }
    
    printf("\n=== File System ===\n");
    printf("Current directory: ");
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        printf("Failed to get current directory\n");
    }
    
    printf("Can write to /tmp: ");
    FILE *test_file = fopen("/tmp/sandbox_test", "w");
    if (test_file) {
        fprintf(test_file, "test");
        fclose(test_file);
        unlink("/tmp/sandbox_test");
        printf("✓ Yes\n");
    } else {
        printf("❌ No\n");
    }
    
    printf("\n=== Network (Basic) ===\n");
    printf("Can create socket: ");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        printf("✓ Yes\n");
        close(sock);
    } else {
        printf("❌ No - %s\n", strerror(errno));
    }
    
    printf("Can bind to localhost: ");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(0); // Let system choose port
        
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            printf("✓ Yes\n");
        } else {
            printf("❌ No - %s\n", strerror(errno));
        }
        close(sock);
    } else {
        printf("❌ No socket\n");
    }
    
    printf("\n=== System Information ===\n");
    printf("OS Release: ");
    FILE *os_release = fopen("/etc/os-release", "r");
    if (os_release) {
        char line[256];
        while (fgets(line, sizeof(line), os_release)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                printf("%s", line + 12);
                break;
            }
        }
        fclose(os_release);
    } else {
        printf("Not available\n");
    }
    
    printf("\n=== Memory Info ===\n");
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (meminfo) {
        char line[256];
        while (fgets(line, sizeof(line), meminfo)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                printf("Total Memory: %s", line + 9);
                break;
            }
        }
        fclose(meminfo);
    } else {
        printf("Memory info not available\n");
    }
    
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║              Test Complete            ║\n");
    printf("╚═══════════════════════════════════════╝\n");
    
    return 0;
}
