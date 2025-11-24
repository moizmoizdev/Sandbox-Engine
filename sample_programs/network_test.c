/*
 * Network Test Program
 * Attempts to create a socket and connect to external server
 * Used to test firewall blocking of network syscalls
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define TEST_SERVER "8.8.8.8"  /* Google DNS */
#define TEST_PORT 53           /* DNS port */

int main(void) {
    int sockfd;
    struct sockaddr_in server_addr;
    
    printf("=== Network Test Program ===\n");
    printf("This program tests network access by attempting to:\n");
    printf("1. Create a socket\n");
    printf("2. Connect to %s:%d\n\n", TEST_SERVER, TEST_PORT);
    
    /* Test 1: Create socket */
    printf("[TEST 1] Creating socket...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0) {
        printf("❌ BLOCKED: socket() failed - %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            printf("✓ Firewall is working! Network syscalls are blocked.\n");
        }
        return 1;
    }
    
    printf("✓ socket() succeeded (fd=%d)\n", sockfd);
    
    /* Test 2: Connect to external server */
    printf("\n[TEST 2] Attempting to connect to %s:%d...\n", TEST_SERVER, TEST_PORT);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TEST_PORT);
    
    if (inet_pton(AF_INET, TEST_SERVER, &server_addr.sin_addr) <= 0) {
        printf("❌ Invalid address: %s\n", TEST_SERVER);
        close(sockfd);
        return 1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("❌ BLOCKED: connect() failed - %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES) {
            printf("✓ Firewall is working! Connection blocked.\n");
        } else if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
            printf("✓ Network namespace isolation is working!\n");
        }
        close(sockfd);
        return 1;
    }
    
    printf("✓ connect() succeeded\n");
    printf("⚠ WARNING: Network access is ALLOWED! Firewall may not be active.\n");
    
    close(sockfd);
    return 0;
}
