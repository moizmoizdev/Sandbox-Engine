/**
 * Memory Protection Test - mprotect
 * Tests if mprotect() can make memory executable
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

/* Simple x86_64 code that returns 123 */
unsigned char code[] = {
    0xb8, 0x7b, 0x00, 0x00, 0x00,  /* mov eax, 123 */
    0xc3                           /* ret */
};

int main(void) {
    printf("=== mprotect() Protection Test ===\n");
    printf("This program tests if mprotect can add EXEC to writable memory.\n\n");
    
    /* First allocate RW memory (no execute) */
    printf("[mprotect Test] Allocating RW memory (no execute)...\n");
    void *mem = mmap(NULL, 4096, 
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (mem == MAP_FAILED) {
        printf("[mprotect Test] mmap failed: %s\n", strerror(errno));
        return 1;
    }
    
    printf("[mprotect Test] Memory allocated at %p\n", mem);
    
    /* Copy code to memory */
    memcpy(mem, code, sizeof(code));
    printf("[mprotect Test] Code copied to memory.\n");
    
    /* Try to make it executable while keeping it writable */
    printf("[mprotect Test] Attempting mprotect with PROT_READ|PROT_WRITE|PROT_EXEC...\n");
    
    if (mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        printf("[mprotect Test] BLOCKED! mprotect failed: %s\n", strerror(errno));
        printf("[mprotect Test] W^X protection is working!\n");
        munmap(mem, 4096);
        return 0;
    }
    
    printf("[mprotect Test] WARNING: mprotect succeeded!\n");
    printf("[mprotect Test] Attempting to execute code...\n");
    
    int (*func)(void) = (int (*)(void))mem;
    int result = func();
    
    printf("[mprotect Test] Code executed! Returned: %d\n", result);
    printf("[mprotect Test] W^X protection is NOT active.\n");
    
    munmap(mem, 4096);
    return 1;
}
