#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* Disk filler - creates large files to fill disk space */
int main() {
    printf("Disk filler started\n");
    printf("Process ID: %d\n", getpid());
    
    const int num_files = 10;
    const size_t file_size = 50 * 1024 * 1024; /* 50 MB per file */
    char filename[256];
    FILE *file;
    char *buffer;
    int created = 0;
    
    /* Allocate buffer for writing */
    buffer = malloc(1024 * 1024); /* 1 MB buffer */
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }
    
    /* Fill buffer with pattern */
    memset(buffer, 0x42, 1024 * 1024);
    
    printf("Creating %d files of %zu MB each...\n", num_files, file_size / (1024 * 1024));
    
    for (int i = 0; i < num_files; i++) {
        snprintf(filename, sizeof(filename), "disk_fill_%d_%d.dat", getpid(), i);
        
        file = fopen(filename, "wb");
        if (file) {
            size_t written = 0;
            size_t to_write = file_size;
            
            while (to_write > 0) {
                size_t chunk = (to_write > 1024 * 1024) ? 1024 * 1024 : to_write;
                size_t result = fwrite(buffer, 1, chunk, file);
                
                if (result != chunk) {
                    fprintf(stderr, "Write error: %s\n", strerror(errno));
                    break;
                }
                
                written += result;
                to_write -= result;
            }
            
            fclose(file);
            created++;
            printf("Created file %d: %s (%zu MB)\n", i + 1, filename, written / (1024 * 1024));
        } else {
            fprintf(stderr, "Failed to create %s: %s\n", filename, strerror(errno));
        }
    }
    
    printf("Created %d files total\n", created);
    printf("Sleeping for 5 seconds before cleanup...\n");
    sleep(5);
    
    /* Cleanup */
    printf("Cleaning up files...\n");
    for (int i = 0; i < num_files; i++) {
        snprintf(filename, sizeof(filename), "disk_fill_%d_%d.dat", getpid(), i);
        unlink(filename);
    }
    
    free(buffer);
    printf("Disk filler completed\n");
    return 0;
}

