/*
 * Port Scan Test Program
 * Attempts to connect to various ports
 * Used to test firewall port filtering rules
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>

#define TEST_SERVER "127.0.0.1"  /* Localhost */
#define TIMEOUT_SEC 1

typedef struct {
    int port;
    const char *service;
} PortTest;

/* Common ports to test */
PortTest test_ports[] = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {5432, "PostgreSQL"},
    {8080, "HTTP-Alt"},
    {0, NULL}
};

int test_port_connection(int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    int flags;
    fd_set fdset;
    struct timeval tv;
    int result;
    
    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;  /* Socket creation failed */
    }
    
    /* Set non-blocking */
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, TEST_SERVER, &server_addr.sin_addr);
    
    /* Attempt connection */
    result = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (result < 0) {
        if (errno == EINPROGRESS) {
            /* Connection in progress, wait with timeout */
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            tv.tv_sec = TIMEOUT_SEC;
            tv.tv_usec = 0;
            
            if (select(sockfd + 1, NULL, &fdset, NULL, &tv) > 0) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                
                close(sockfd);
                if (so_error == 0) {
                    return 1;  /* Connected */
                } else {
                    return 0;  /* Connection refused/failed */
                }
            } else {
                close(sockfd);
                return 0;  /* Timeout */
            }
        } else if (errno == EPERM || errno == EACCES) {
            close(sockfd);
            return -2;  /* Blocked by firewall */
        } else {
            close(sockfd);
            return 0;  /* Connection failed */
        }
    }
    
    close(sockfd);
    return 1;  /* Connected immediately */
}

int main(void) {
    int i;
    int allowed = 0, blocked = 0, refused = 0, socket_blocked = 0;
    
    printf("=== Port Scan Test Program ===\n");
    printf("Scanning common ports on %s\n", TEST_SERVER);
    printf("This tests which ports the firewall allows/blocks\n\n");
    
    /* First test if socket creation works */
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (test_sock < 0) {
        printf("❌ Socket creation blocked - %s\n", strerror(errno));
        printf("✓ Firewall is in NO_NETWORK mode (all network syscalls blocked)\n");
        return 1;
    }
    close(test_sock);
    printf("✓ Socket creation allowed, testing individual ports...\n\n");
    
    printf("Port  Service       Status\n");
    printf("----  ------------  --------------------\n");
    
    for (i = 0; test_ports[i].service != NULL; i++) {
        int result = test_port_connection(test_ports[i].port);
        
        printf("%-5d %-12s ", test_ports[i].port, test_ports[i].service);
        
        switch (result) {
            case -2:
                printf("❌ BLOCKED (firewall)\n");
                blocked++;
                socket_blocked++;
                break;
            case -1:
                printf("❌ Socket creation failed\n");
                socket_blocked++;
                break;
            case 0:
                printf("⚪ Refused/Timeout\n");
                refused++;
                break;
            case 1:
                printf("✓ OPEN/Allowed\n");
                allowed++;
                break;
        }
    }
    
    printf("\n=== Summary ===\n");
    printf("Allowed/Open:  %d ports\n", allowed);
    printf("Refused:       %d ports\n", refused);
    printf("Blocked:       %d ports\n", blocked);
    printf("Socket Failed: %d ports\n", socket_blocked);
    
    if (socket_blocked > 0) {
        printf("\n✓ Firewall is blocking connections at syscall level\n");
    } else if (blocked > 0) {
        printf("\n✓ Firewall rules are active and blocking specific ports\n");
    } else if (allowed > 0) {
        printf("\n⚠ Some ports are accessible - firewall may be permissive\n");
    } else {
        printf("\n✓ All connections refused - strong network isolation\n");
    }
    
    return 0;
}
