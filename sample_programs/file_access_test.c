#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

#define TEST_PASSED "✓ PASSED"
#define TEST_FAILED "✗ FAILED"

static void test_result(const char *test_name, int success, const char *details) {
    printf("[%s] %s", success ? TEST_PASSED : TEST_FAILED, test_name);
    if (details) {
        printf(" - %s", details);
    }
    printf("\n");
}

int main() {
    printf("========================================\n");
    printf("Landlock File Access Test Program\n");
    printf("========================================\n");
    printf("Process ID: %d\n", getpid());
    printf("Current directory: ");
    system("pwd");
    printf("\n");
    
    int tests_run = 0;
    int tests_passed = 0;
    
    /* Test 1: Write to /tmp */
    tests_run++;
    printf("\n[Test 1] Attempting to write to /tmp/test_write.txt\n");
    FILE *file = fopen("/tmp/test_write.txt", "w");
    if (file) {
        fprintf(file, "Test content\n");
        fclose(file);
        test_result("Write to /tmp", 0, "Should be blocked by Landlock");
    } else {
        test_result("Write to /tmp", 1, strerror(errno));
        tests_passed++;
    }
    
    /* Test 2: Read from /etc/passwd */
    tests_run++;
    printf("\n[Test 2] Attempting to read from /etc/passwd\n");
    file = fopen("/etc/passwd", "r");
    if (file) {
        char line[256];
        if (fgets(line, sizeof(line), file)) {
            test_result("Read from /etc/passwd", 1, "First line read successfully");
            tests_passed++;
        } else {
            test_result("Read from /etc/passwd", 1, "File opened but empty");
            tests_passed++;
        }
        fclose(file);
    } else {
        test_result("Read from /etc/passwd", 0, strerror(errno));
    }
    
    /* Test 3: Read from /usr/lib (should be allowed in moderate/permissive) */
    tests_run++;
    printf("\n[Test 3] Attempting to read directory /usr/lib\n");
    DIR *dir = opendir("/usr/lib");
    if (dir) {
        struct dirent *entry;
        if ((entry = readdir(dir)) != NULL) {
            test_result("Read /usr/lib directory", 1, "Directory accessible");
            tests_passed++;
        } else {
            test_result("Read /usr/lib directory", 0, "Directory opened but empty");
        }
        closedir(dir);
    } else {
        test_result("Read /usr/lib directory", 0, strerror(errno));
    }
    
    /* Test 4: Read from /lib (should be allowed in moderate/permissive) */
    tests_run++;
    printf("\n[Test 4] Attempting to read directory /lib\n");
    dir = opendir("/lib");
    if (dir) {
        struct dirent *entry;
        if ((entry = readdir(dir)) != NULL) {
            test_result("Read /lib directory", 1, "Directory accessible");
            tests_passed++;
        } else {
            test_result("Read /lib directory", 0, "Directory opened but empty");
        }
        closedir(dir);
    } else {
        test_result("Read /lib directory", 0, strerror(errno));
    }
    
    /* Test 5: Write to /tmp */
    tests_run++;
    printf("\n[Test 5] Attempting to create file in /tmp\n");
    file = fopen("/tmp/landlock_test_file.txt", "w");
    if (file) {
        fprintf(file, "test content\n");
        fclose(file);
        if (unlink("/tmp/landlock_test_file.txt") == 0) {
            test_result("Create/delete in /tmp", 0, "Should be blocked by Landlock");
        } else {
            test_result("Create/delete in /tmp", 0, "Created but delete failed");
        }
    } else {
        test_result("Create/delete in /tmp", 1, strerror(errno));
        tests_passed++;
    }
    
    /* Test 6: Read from current directory */
    tests_run++;
    printf("\n[Test 6] Attempting to read current directory\n");
    dir = opendir(".");
    if (dir) {
        struct dirent *entry;
        if ((entry = readdir(dir)) != NULL) {
            test_result("Read current directory", 1, "Directory accessible");
            tests_passed++;
        } else {
            test_result("Read current directory", 0, "Directory opened but empty");
        }
        closedir(dir);
    } else {
        test_result("Read current directory", 0, strerror(errno));
    }
    
    /* Test 7: Write to current directory */
    tests_run++;
    printf("\n[Test 7] Attempting to write to current directory\n");
    file = fopen("./test_local.txt", "w");
    if (file) {
        fprintf(file, "Local test file\n");
        fclose(file);
        test_result("Write to current directory", 1, "File created successfully");
        unlink("./test_local.txt");
        tests_passed++;
    } else {
        test_result("Write to current directory", 0, strerror(errno));
    }
    
    /* Test 8: Read from /proc (should be accessible) */
    tests_run++;
    printf("\n[Test 8] Attempting to read from /proc/self/status\n");
    file = fopen("/proc/self/status", "r");
    if (file) {
        char line[256];
        if (fgets(line, sizeof(line), file)) {
            test_result("Read /proc/self/status", 1, "Proc filesystem accessible");
            tests_passed++;
        } else {
            test_result("Read /proc/self/status", 0, "File opened but empty");
        }
        fclose(file);
    } else {
        test_result("Read /proc/self/status", 0, strerror(errno));
    }
    
    /* Summary */
    printf("\n========================================\n");
    printf("Test Summary: %d/%d tests passed\n", tests_passed, tests_run);
    printf("========================================\n");
    
    if (tests_passed == tests_run) {
        printf("All tests passed! Landlock restrictions may not be active.\n");
    } else {
        printf("Some tests failed - this indicates Landlock is restricting access.\n");
    }
    
    return 0;
}

