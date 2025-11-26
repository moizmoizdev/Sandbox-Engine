/**
 * Network Firewall Test - Outbound Connections
 * Tests if outbound network connections are blocked by firewall
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

typedef struct {
    const char *name;
    const char *host;
    int port;
} TestTarget;

TestTarget targets[] = {
    {"HTTP (Google DNS)", "8.8.8.8", 80},
    {"HTTPS (Google DNS)", "8.8.8.8", 443},
    {"DNS", "8.8.8.8", 53},
    {"SSH (localhost)", "127.0.0.1", 22},
    {"Telnet (dangerous)", "127.0.0.1", 23},
    {"SMB (dangerous)", "127.0.0.1", 445},
};

int try_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    
    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(sock);
    
    if (result < 0) {
        errno = err;
    }
    return result;
}

int main(void) {
    printf("=== Network Firewall Test ===\n");
    printf("Testing outbound connection attempts...\n\n");
    
    int blocked = 0;
    int allowed = 0;
    int num_tests = sizeof(targets) / sizeof(targets[0]);
    
    for (int i = 0; i < num_tests; i++) {
        printf("[Firewall Test] Trying %s (%s:%d)... ", 
               targets[i].name, targets[i].host, targets[i].port);
        fflush(stdout);
        
        int result = try_connect(targets[i].host, targets[i].port);
        
        if (result == 0) {
            printf("CONNECTED (allowed)\n");
            allowed++;
        } else if (errno == EPERM || errno == EACCES) {
            printf("BLOCKED by firewall\n");
            blocked++;
        } else if (errno == ECONNREFUSED) {
            printf("Connection refused (port closed)\n");
        } else if (errno == ETIMEDOUT || errno == ENETUNREACH || errno == EHOSTUNREACH) {
            printf("Timeout/unreachable\n");
        } else {
            printf("Failed: %s\n", strerror(errno));
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Connections allowed: %d\n", allowed);
    printf("Connections blocked: %d\n", blocked);
    printf("Total tests: %d\n", num_tests);
    
    if (blocked > 0) {
        printf("\nFirewall is actively blocking connections!\n");
    } else if (allowed == 0) {
        printf("\nNo connections succeeded - network may be isolated.\n");
    }
    
    return 0;
}
