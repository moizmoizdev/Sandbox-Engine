/**
 * Stack Protection Test Program
 * Tests stack size limits and stack-based operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

/* Recursive function to consume stack */
void consume_stack(int depth, int max_depth) {
    char buffer[4096]; /* 4KB per call */
    memset(buffer, 'A', sizeof(buffer));
    
    if (depth % 100 == 0) {
        printf("[Stack Test] Depth: %d, Buffer at: %p\n", depth, (void*)buffer);
    }
    
    if (depth < max_depth) {
        consume_stack(depth + 1, max_depth);
    }
}

void print_stack_limits(void) {
    struct rlimit rl;
    
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
        printf("[Stack Test] Current stack limit: %lu KB (soft), %lu KB (hard)\n",
               rl.rlim_cur / 1024, rl.rlim_max / 1024);
    } else {
        perror("getrlimit");
    }
}

int main(int argc, char *argv[]) {
    int max_depth = 500; /* Default: try 500 recursive calls (~2MB stack) */
    
    if (argc > 1) {
        max_depth = atoi(argv[1]);
    }
    
    printf("=== Stack Protection Test ===\n");
    printf("This program tests stack size limits.\n");
    printf("Will attempt %d recursive calls (4KB each = ~%d KB)\n\n", 
           max_depth, max_depth * 4);
    
    print_stack_limits();
    
    printf("\n[Stack Test] Starting recursive calls...\n");
    
    consume_stack(0, max_depth);
    
    printf("\n[Stack Test] Completed successfully!\n");
    printf("[Stack Test] If stack limit is enforced, this would have crashed.\n");
    
    return 0;
}
