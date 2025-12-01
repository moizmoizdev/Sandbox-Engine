/*
 * HTTP Request Test Program
 * Attempts to make an HTTP GET request to test web access
 * Used to test firewall rules for HTTP/HTTPS
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define TEST_HOST "example.com"
#define TEST_PORT 80

int main(void) {
    int sockfd;
    struct hostent *server;
    struct sockaddr_in server_addr;
    char request[512];
    char response[4096];
    int bytes_received;
    
    printf("=== HTTP Request Test Program ===\n");
    printf("Attempting HTTP GET to http://%s:%d\n\n", TEST_HOST, TEST_PORT);
    
    /* Test 1: Create socket */
    printf("[TEST 1] Creating socket...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0) {
        printf("❌ BLOCKED: socket() failed - %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            printf("✓ Firewall blocked socket creation (NO_NETWORK mode)\n");
        }
        return 1;
    }
    
    printf("✓ Socket created (fd=%d)\n", sockfd);
    
    /* Test 2: DNS lookup */
    printf("\n[TEST 2] Performing DNS lookup for %s...\n", TEST_HOST);
    server = gethostbyname(TEST_HOST);
    
    if (server == NULL) {
        printf("❌ DNS lookup failed (h_errno=%d)\n", h_errno);
        if (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA) {
            printf("✓ Network namespace isolation or DNS blocking is active\n");
        }
        close(sockfd);
        return 1;
    }
    
    printf("✓ DNS lookup successful: %s\n", 
           inet_ntoa(*(struct in_addr *)server->h_addr_list[0]));
    
    /* Test 3: Connect to HTTP server */
    printf("\n[TEST 3] Connecting to %s:%d...\n", TEST_HOST, TEST_PORT);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_PORT);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("❌ BLOCKED: connect() failed - %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            printf("✓ Firewall blocked connection\n");
        } else if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
            printf("✓ Network isolation is working\n");
        }
        close(sockfd);
        return 1;
    }
    
    printf("✓ Connected to server\n");
    
    /* Test 4: Send HTTP request */
    printf("\n[TEST 4] Sending HTTP GET request...\n");
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "\r\n", TEST_HOST);
    
    if (send(sockfd, request, strlen(request), 0) < 0) {
        printf("❌ send() failed - %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    
    printf("✓ Request sent\n");
    
    /* Test 5: Receive response */
    printf("\n[TEST 5] Receiving response...\n");
    bytes_received = recv(sockfd, response, sizeof(response) - 1, 0);
    
    if (bytes_received < 0) {
        printf("❌ recv() failed - %s\n", strerror(errno));
        close(sockfd);
        return 1;
    }
    
    response[bytes_received] = '\0';
    printf("✓ Received %d bytes\n", bytes_received);
    printf("\n--- Response Preview (first 200 chars) ---\n");
    printf("%.200s\n", response);
    printf("---\n");
    
    printf("\n⚠ SUCCESS: HTTP access is ALLOWED!\n");
    printf("This indicates the firewall is either disabled or allows HTTP.\n");
    
    close(sockfd);
    return 0;
}
