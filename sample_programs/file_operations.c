#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main() {
    printf("File operations test program\n");
    printf("Process ID: %d\n", getpid());
    printf("Current directory: ");
    system("pwd");
    
    /* Try to create a test file */
    const char *filename = "sandbox_test_file.txt";
    FILE *file = fopen(filename, "w");
    
    if (file) {
        fprintf(file, "This is a test file created by sandboxed process\n");
        fprintf(file, "Process ID: %d\n", getpid());
        fclose(file);
        printf("Successfully created file: %s\n", filename);
        
        /* Try to read it back */
        file = fopen(filename, "r");
        if (file) {
            char line[256];
            printf("File contents:\n");
            while (fgets(line, sizeof(line), file)) {
                printf("  %s", line);
            }
            fclose(file);
        }
        
        /* Try to delete it */
        if (unlink(filename) == 0) {
            printf("Successfully deleted file: %s\n", filename);
        } else {
            printf("Failed to delete file: %s\n", strerror(errno));
        }
    } else {
        printf("Failed to create file: %s\n", strerror(errno));
    }
    
    printf("File operations test completed\n");
    return 0;
}

