#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Memory bomb - rapidly allocates memory to exhaust system resources */
int main() {
    printf("Memory bomb started\n");
    printf("Process ID: %d\n", getpid());
    
    void **pointers = NULL;
    size_t num_allocs = 0;
    size_t max_allocs = 1000;
    size_t alloc_size = 10 * 1024 * 1024; /* 10 MB per allocation */
    
    pointers = malloc(max_allocs * sizeof(void*));
    if (!pointers) {
        fprintf(stderr, "Failed to allocate pointer array\n");
        return 1;
    }
    
    printf("Attempting to allocate %zu MB total...\n", 
           (max_allocs * alloc_size) / (1024 * 1024));
    
    for (size_t i = 0; i < max_allocs; i++) {
        pointers[i] = malloc(alloc_size);
        
        if (pointers[i]) {
            /* Fill with pattern to ensure memory is actually used */
            memset(pointers[i], 0xAA, alloc_size);
            num_allocs++;
            
            if (i % 100 == 0) {
                printf("Allocated %zu chunks (%zu MB)...\n", 
                       i + 1, ((i + 1) * alloc_size) / (1024 * 1024));
            }
        } else {
            printf("Allocation failed at chunk %zu\n", i);
            break;
        }
    }
    
    printf("Successfully allocated %zu chunks (%zu MB)\n", 
           num_allocs, (num_allocs * alloc_size) / (1024 * 1024));
    printf("Holding memory for 10 seconds...\n");
    sleep(10);
    
    /* Free all allocated memory */
    printf("Freeing memory...\n");
    for (size_t i = 0; i < num_allocs; i++) {
        if (pointers[i]) {
            free(pointers[i]);
        }
    }
    free(pointers);
    
    printf("Memory bomb completed\n");
    return 0;
}

