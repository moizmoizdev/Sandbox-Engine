/**
 * Memory Protection Test - Executable Memory
 * Tests W^X (Write XOR Execute) protection
 * This program attempts to create writable+executable memory
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

/* Simple x86_64 shellcode that just returns 42 */
unsigned char shellcode[] = {
    0xb8, 0x2a, 0x00, 0x00, 0x00,  /* mov eax, 42 */
    0xc3                           /* ret */
};

int main(void) {
    printf("=== W^X (Write XOR Execute) Protection Test ===\n");
    printf("This program tests if writable+executable memory is blocked.\n\n");
    
    /* Try to allocate RWX (Read-Write-Execute) memory */
    printf("[W^X Test] Attempting to mmap with PROT_READ|PROT_WRITE|PROT_EXEC...\n");
    
    void *mem = mmap(NULL, 4096, 
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (mem == MAP_FAILED) {
        printf("[W^X Test] BLOCKED! mmap failed: %s\n", strerror(errno));
        printf("[W^X Test] Memory protection is working correctly!\n");
        return 0;
    }
    
    printf("[W^X Test] WARNING: RWX memory allocation succeeded at %p\n", mem);
    printf("[W^X Test] Memory protection may not be active.\n");
    
    /* Copy and execute shellcode */
    printf("[W^X Test] Copying shellcode...\n");
    memcpy(mem, shellcode, sizeof(shellcode));
    
    printf("[W^X Test] Attempting to execute shellcode...\n");
    int (*func)(void) = (int (*)(void))mem;
    int result = func();
    
    printf("[W^X Test] Shellcode executed! Returned: %d\n", result);
    printf("[W^X Test] This indicates W^X protection is NOT active.\n");
    
    munmap(mem, 4096);
    return 1;
}
