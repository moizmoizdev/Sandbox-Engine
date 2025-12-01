/**
 * Syscall Test Program
 * Makes various system calls to test syscall tracking
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>

int main(void) {
    printf("=== Syscall Test Program ===\n");
    printf("This program makes various syscalls for tracking.\n\n");
    
    /* 1. File operations */
    printf("[Syscall Test] Testing file operations...\n");
    
    int fd = open("/tmp/syscall_test.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "Hello from syscall test!\n";
        write(fd, msg, strlen(msg));
        close(fd);
        printf("  - open/write/close: OK\n");
    } else {
        printf("  - open failed: %s\n", strerror(errno));
    }
    
    /* Read it back */
    fd = open("/tmp/syscall_test.txt", O_RDONLY);
    if (fd >= 0) {
        char buf[100];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("  - read: OK (%zd bytes)\n", n);
        }
        close(fd);
    }
    
    /* 2. Process info */
    printf("\n[Syscall Test] Testing process info calls...\n");
    printf("  - getpid: %d\n", getpid());
    printf("  - getppid: %d\n", getppid());
    printf("  - getuid: %d\n", getuid());
    printf("  - getgid: %d\n", getgid());
    
    /* 3. System info */
    printf("\n[Syscall Test] Testing system info calls...\n");
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("  - uname: %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }
    
    /* 4. Time calls */
    printf("\n[Syscall Test] Testing time calls...\n");
    time_t now = time(NULL);
    printf("  - time: %ld\n", now);
    
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        printf("  - clock_gettime: %ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
    }
    
    /* 5. Directory operations */
    printf("\n[Syscall Test] Testing directory operations...\n");
    char cwd[256];
    if (getcwd(cwd, sizeof(cwd))) {
        printf("  - getcwd: %s\n", cwd);
    }
    
    /* 6. Memory operations */
    printf("\n[Syscall Test] Testing memory operations...\n");
    void *mem = malloc(4096);
    if (mem) {
        memset(mem, 0, 4096);
        printf("  - malloc/memset: OK\n");
        free(mem);
    }
    
    /* 7. Sleep */
    printf("\n[Syscall Test] Testing sleep (100ms)...\n");
    usleep(100000);
    printf("  - usleep: OK\n");
    
    /* Cleanup */
    unlink("/tmp/syscall_test.txt");
    
    printf("\n=== Syscall test completed ===\n");
    return 0;
}
