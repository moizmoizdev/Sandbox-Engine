/*
 * Simple network connectivity test
 * Just tries to connect to a few common services
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

int try_connect(const char *ip, int port, const char *name) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("❌ %s - Socket failed: %s\n", name, strerror(errno));
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    /* Set timeout */
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    printf("Testing %s (%s:%d)... ", name, ip, port);
    fflush(stdout);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("❌ BLOCKED/FAILED: %s\n", strerror(errno));
        close(sock);
        return -1;
    }
    
    printf("✓ ALLOWED\n");
    close(sock);
    return 0;
}

int main() {
    printf("\n╔══════════════════════════════════╗\n");
    printf("║  Simple Network Connectivity Test║\n");
    printf("╚══════════════════════════════════╝\n\n");
    
    /* These should work if policy allows them */
    try_connect("8.8.8.8", 53, "Google DNS");
    try_connect("1.1.1.1", 53, "Cloudflare DNS");
    try_connect("93.184.216.34", 80, "Example.com HTTP");
    try_connect("93.184.216.34", 443, "Example.com HTTPS");
    
    /* These should be blocked */
    try_connect("203.0.113.50", 80, "Blocked subnet");
    
    printf("\n");
    return 0;
}
