/* Test program to verify namespace isolation
 * Compile with: gcc -o namespaces_test namespaces_test.c namespaces.c
 * Run with: sudo ./namespaces_test
 */

#include "namespaces.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>

int main() {
    printf("=== Namespace Isolation Test ===\n\n");
    
    printf("Original hostname: ");
    struct utsname uts;
    uname(&uts);
    printf("%s\n", uts.nodename);
    
    printf("Original PID: %d\n", getpid());
    printf("Original PPID: %d\n\n", getppid());
    
    /* Test UTS namespace */
    printf("Testing UTS namespace...\n");
    if (setup_uts_namespace("sandbox-test") == 0) {
        uname(&uts);
        printf("New hostname: %s\n", uts.nodename);
    }
    
    printf("\n=== Test completed ===\n");
    printf("Note: PID, mount, and network namespaces require root privileges\n");
    printf("Run with sudo to test all namespaces\n");
    
    return 0;
}

