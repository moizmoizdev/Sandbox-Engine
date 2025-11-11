#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* Creates many files rapidly - simulates file system spam */
int main() {
    printf("File spammer started\n");
    printf("Process ID: %d\n", getpid());
    
    const int num_files = 100;
    char filename[256];
    FILE *file;
    int created = 0;
    
    for (int i = 0; i < num_files; i++) {
        snprintf(filename, sizeof(filename), "spam_file_%d_%d.txt", getpid(), i);
        
        file = fopen(filename, "w");
        if (file) {
            fprintf(file, "This is spam file number %d\n", i);
            fprintf(file, "Created by process %d\n", getpid());
            fprintf(file, "File spam attack simulation\n");
            fclose(file);
            created++;
            
            if (i % 10 == 0) {
                printf("Created %d files...\n", i + 1);
            }
        } else {
            fprintf(stderr, "Failed to create %s: %s\n", filename, strerror(errno));
        }
    }
    
    printf("Created %d files total\n", created);
    printf("Sleeping for 5 seconds before cleanup...\n");
    sleep(5);
    
    /* Cleanup - delete all created files */
    printf("Cleaning up files...\n");
    for (int i = 0; i < num_files; i++) {
        snprintf(filename, sizeof(filename), "spam_file_%d_%d.txt", getpid(), i);
        unlink(filename);
    }
    
    printf("File spammer completed\n");
    return 0;
}

