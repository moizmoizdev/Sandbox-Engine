#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    printf("Memory allocation test program\n");
    printf("Process ID: %d\n", getpid());
    
    /* Allocate and use some memory */
    size_t size = 10 * 1024 * 1024; /* 10 MB */
    char *buffer = malloc(size);
    
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    
    printf("Allocated %zu bytes\n", size);
    
    /* Fill memory with pattern */
    memset(buffer, 0xAA, size);
    printf("Filled memory with pattern\n");
    
    /* Keep memory allocated for a few seconds */
    sleep(5);
    
    /* Verify pattern */
    int errors = 0;
    for (size_t i = 0; i < size; i += 1024) {
        if (buffer[i] != 0xAA) {
            errors++;
        }
    }
    
    printf("Memory verification: %s\n", errors == 0 ? "PASSED" : "FAILED");
    
    free(buffer);
    printf("Memory freed. Test completed.\n");
    return 0;
}

