/*
 * Internet Connectivity Test
 * Tests DNS resolution and HTTP connection with IP filtering
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

void test_dns(const char *hostname) {
    printf("\n=== Testing DNS Resolution ===\n");
    printf("Resolving: %s\n", hostname);
    
    struct hostent *host = gethostbyname(hostname);
    if (host == NULL) {
        const char *error_msg;
        switch (h_errno) {
            case HOST_NOT_FOUND: error_msg = "Host not found"; break;
            case NO_ADDRESS: error_msg = "No address associated with hostname"; break;
            case NO_RECOVERY: error_msg = "Non-recoverable name server error"; break;
            case TRY_AGAIN: error_msg = "Temporary failure in name resolution"; break;
            default: error_msg = "Unknown DNS error"; break;
        }
        printf("❌ DNS resolution failed: %s\n", error_msg);
        return;
    }
    
    printf("✓ DNS resolved successfully!\n");
    printf("  Hostname: %s\n", host->h_name);
    printf("  IP addresses:\n");
    
    for (int i = 0; host->h_addr_list[i] != NULL; i++) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, host->h_addr_list[i], ip, sizeof(ip));
        printf("    %s\n", ip);
    }
}

void test_tcp_connection(const char *ip, int port) {
    printf("\n=== Testing TCP Connection ===\n");
    printf("Connecting to: %s:%d\n", ip, port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("❌ Socket creation failed: %s\n", strerror(errno));
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("❌ Invalid IP address\n");
        close(sock);
        return;
    }
    
    printf("Attempting connection...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("❌ Connection failed: %s\n", strerror(errno));
        close(sock);
        return;
    }
    
    printf("✓ Connection successful!\n");
    
    /* Send simple HTTP GET request */
    const char *http_req = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    if (send(sock, http_req, strlen(http_req), 0) < 0) {
        printf("❌ Failed to send request: %s\n", strerror(errno));
    } else {
        printf("✓ HTTP request sent\n");
        
        /* Read response */
        char buffer[1024];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("✓ Received response (%d bytes):\n", bytes);
            printf("--- First 200 chars ---\n");
            printf("%.200s\n", buffer);
            printf("--- End response ---\n");
        }
    }
    
    close(sock);
}

void test_google_dns() {
    printf("\n=== Testing Google DNS (8.8.8.8:53) ===\n");
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("❌ Socket creation failed: %s\n", strerror(errno));
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("❌ Connection to Google DNS failed: %s\n", strerror(errno));
        close(sock);
        return;
    }
    
    printf("✓ Successfully connected to Google DNS!\n");
    close(sock);
}

void test_blocked_ip() {
    printf("\n=== Testing Blocked IP (Should Fail) ===\n");
    printf("Attempting connection to 203.0.113.50:80\n");
    printf("(This IP should be blocked by firewall rules)\n");
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("❌ Socket creation failed: %s\n", strerror(errno));
        return;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "203.0.113.50", &addr.sin_addr);
    
    /* Set timeout to avoid hanging */
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("✓ Connection blocked as expected: %s\n", strerror(errno));
    } else {
        printf("⚠️  WARNING: Connection succeeded (firewall may not be working!)\n");
    }
    
    close(sock);
}

int main() {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║  Internet Connectivity & IP Filter Test   ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    
    /* Show network interface info */
    printf("\n=== Network Configuration ===\n");
    system("ip addr show 2>/dev/null | grep -E 'inet |UP' | head -10");
    
    printf("\n=== Routing Table ===\n");
    system("ip route show 2>/dev/null");
    
    printf("\n=== DNS Configuration ===\n");
    system("cat /etc/resolv.conf 2>/dev/null");
    
    /* Test DNS resolution */
    test_dns("example.com");
    test_dns("google.com");
    
    /* Test Google DNS */
    test_google_dns();
    
    /* Test HTTP connection to example.com */
    test_tcp_connection("93.184.216.34", 80);  /* example.com IP */
    
    /* Test blocked IP */
    test_blocked_ip();
    
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║           Test Complete                    ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    
    return 0;
}
