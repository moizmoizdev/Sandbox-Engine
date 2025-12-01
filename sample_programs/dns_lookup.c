/*
 * DNS Lookup Test Program
 * Tests DNS resolution capabilities
 * Used to test if DNS is blocked or allowed by firewall
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

const char *test_domains[] = {
    "google.com",
    "example.com",
    "github.com",
    "localhost",
    NULL
};

int main(void) {
    struct hostent *host;
    struct in_addr **addr_list;
    int i, j;
    
    printf("=== DNS Lookup Test Program ===\n");
    printf("Testing DNS resolution for multiple domains\n\n");
    
    for (i = 0; test_domains[i] != NULL; i++) {
        printf("[TEST %d] Looking up %s...\n", i + 1, test_domains[i]);
        
        host = gethostbyname(test_domains[i]);
        
        if (host == NULL) {
            const char *error_msg = "Unknown error";
            switch (h_errno) {
                case HOST_NOT_FOUND:
                    error_msg = "Host not found";
                    break;
                case NO_DATA:
                    error_msg = "No data available";
                    break;
                case NO_RECOVERY:
                    error_msg = "Non-recoverable error";
                    break;
                case TRY_AGAIN:
                    error_msg = "Temporary failure";
                    break;
            }
            
            printf("❌ DNS lookup failed: %s\n", error_msg);
            
            if (strcmp(test_domains[i], "localhost") != 0) {
                printf("   ✓ Network namespace isolation or DNS blocking is active\n");
            }
        } else {
            printf("✓ DNS lookup successful\n");
            printf("   Official name: %s\n", host->h_name);
            
            addr_list = (struct in_addr **)host->h_addr_list;
            printf("   IP addresses:\n");
            for (j = 0; addr_list[j] != NULL; j++) {
                printf("      %s\n", inet_ntoa(*addr_list[j]));
            }
        }
        printf("\n");
    }
    
    printf("=== Test Complete ===\n");
    printf("If most DNS lookups failed, the firewall/network isolation is working.\n");
    printf("If DNS works, check if firewall policy allows DNS (port 53 UDP).\n");
    
    return 0;
}
