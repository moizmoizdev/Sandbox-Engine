/**
 * Automated Firewall Test Runner
 * Non-interactive CLI tool for testing firewall enforcement
 */

#define _DEFAULT_SOURCE  // For usleep()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "process_control.h"
#include "namespaces.h"
#include "firewall.h"
#include "cgroups.h"
#include "memory_protection.h"
#include "landlock.h"

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_RESET   "\x1b[0m"

typedef enum {
    TEST_PASS,
    TEST_FAIL,
    TEST_SKIP,
    TEST_ERROR
} TestResult;

typedef struct {
    const char *test_name;
    const char *program_path;
    FirewallPolicy firewall_policy;
    int enable_network_namespace;
    int expected_to_succeed;  // 1 if network should work, 0 if blocked
    TestResult result;
    char error_msg[256];
} TestCase;

/**
 * Run a single test case
 */
TestResult run_test(TestCase *test) {
    printf("\n" COLOR_BLUE "═══════════════════════════════════════════════════════════" COLOR_RESET "\n");
    printf(COLOR_BLUE "  Test: %s" COLOR_RESET "\n", test->test_name);
    printf(COLOR_BLUE "═══════════════════════════════════════════════════════════" COLOR_RESET "\n");
    
    printf("Program: %s\n", test->program_path);
    printf("Firewall Policy: %s\n", firewall_policy_name(test->firewall_policy));
    printf("Network Namespace: %s\n", test->enable_network_namespace ? "ENABLED" : "DISABLED");
    printf("Expected Behavior: Network should %s\n", 
           test->expected_to_succeed ? COLOR_GREEN "SUCCEED" COLOR_RESET : COLOR_RED "FAIL" COLOR_RESET);
    
    // Check if program exists
    if (access(test->program_path, X_OK) != 0) {
        snprintf(test->error_msg, sizeof(test->error_msg), 
                 "Test program not found or not executable: %s", test->program_path);
        printf(COLOR_YELLOW "⊘ SKIP: %s" COLOR_RESET "\n", test->error_msg);
        return TEST_SKIP;
    }
    
    // Configure namespaces
    int ns_flags = 0;
    if (test->enable_network_namespace) {
        ns_flags |= NS_NET;
    }
    // Always use PID namespace for isolation
    ns_flags |= NS_PID;
    
    // Configure firewall
    FirewallPolicy fw_policy = test->firewall_policy;
    
    // No cgroups for testing (keep it simple)
    CgroupConfig *cg_config = NULL;
    
    // No memory protection for testing
    MemoryProtectionConfig *mem_config = NULL;
    
    // No landlock for testing
    LandlockConfig *ll_config = NULL;
    
    printf("\n" COLOR_YELLOW "► Running test..." COLOR_RESET "\n");
    
    // Run the sandboxed process
    pid_t child_pid = create_sandboxed_process(
        test->program_path,
        ns_flags,
        "sandbox-test",    // UTS hostname
        fw_policy,
        NULL,              // No custom policy file
        cg_config,
        mem_config,
        ll_config
    );
    
    if (child_pid < 0) {
        snprintf(test->error_msg, sizeof(test->error_msg), 
                 "Failed to create sandboxed process");
        printf(COLOR_RED "✗ ERROR: %s" COLOR_RESET "\n", test->error_msg);
        return TEST_ERROR;
    }
    
    // Wait for process to complete (timeout after 10 seconds)
    int status;
    int wait_count = 0;
    while (wait_count < 100) {  // 10 seconds max (100 * 100ms)
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        if (result == child_pid) {
            break;
        } else if (result < 0) {
            snprintf(test->error_msg, sizeof(test->error_msg), 
                     "waitpid failed");
            printf(COLOR_RED "✗ ERROR: %s" COLOR_RESET "\n", test->error_msg);
            return TEST_ERROR;
        }
        usleep(100000);  // 100ms
        wait_count++;
    }
    
    if (wait_count >= 100) {
        // Timeout - kill the process
        kill(child_pid, SIGKILL);
        waitpid(child_pid, &status, 0);
        snprintf(test->error_msg, sizeof(test->error_msg), 
                 "Test timed out (>10 seconds)");
        printf(COLOR_YELLOW "⊘ TIMEOUT: %s" COLOR_RESET "\n", test->error_msg);
        return TEST_ERROR;
    }
    
    // Check exit status
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("\nProgram exit code: %d\n", exit_code);
    
    /**
     * Exit code interpretation:
     * 0 = Network operation succeeded
     * 1 = Network operation failed (as expected when blocked)
     * Other = Error
     */
    
    int network_succeeded = (exit_code == 0);
    
    // Determine if test passed based on expected behavior
    if (test->expected_to_succeed) {
        // We expect network to work
        if (network_succeeded) {
            printf(COLOR_GREEN "✓ PASS: Network operation succeeded (as expected)" COLOR_RESET "\n");
            return TEST_PASS;
        } else {
            snprintf(test->error_msg, sizeof(test->error_msg), 
                     "Network was blocked but should have succeeded");
            printf(COLOR_RED "✗ FAIL: %s" COLOR_RESET "\n", test->error_msg);
            return TEST_FAIL;
        }
    } else {
        // We expect network to be blocked
        if (!network_succeeded) {
            printf(COLOR_GREEN "✓ PASS: Network operation blocked (as expected)" COLOR_RESET "\n");
            return TEST_PASS;
        } else {
            snprintf(test->error_msg, sizeof(test->error_msg), 
                     "Network succeeded but should have been blocked");
            printf(COLOR_RED "✗ FAIL: %s" COLOR_RESET "\n", test->error_msg);
            return TEST_FAIL;
        }
    }
}

/**
 * Main test runner
 */
int main(int argc, char *argv[]) {
    (void)argc;  // Unused
    (void)argv;  // Unused
    printf("\n");
    printf(COLOR_BLUE "╔═══════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BLUE "║     SANDBOX ENGINE FIREWALL AUTOMATED TEST SUITE          ║\n" COLOR_RESET);
    printf(COLOR_BLUE "╚═══════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    
    // Define test cases
    TestCase tests[] = {
        // Test 1: NO_NETWORK mode blocks everything
        {
            .test_name = "NO_NETWORK Mode - Blocks Socket Creation",
            .program_path = "./sample_programs/network_test",
            .firewall_policy = FIREWALL_NO_NETWORK,
            .enable_network_namespace = 0,
            .expected_to_succeed = 0,  // Should be blocked
        },
        
        // Test 2: STRICT mode blocks everything
        {
            .test_name = "STRICT Mode - Blocks Socket Creation",
            .program_path = "./sample_programs/network_test",
            .firewall_policy = FIREWALL_STRICT,
            .enable_network_namespace = 0,
            .expected_to_succeed = 0,  // Should be blocked
        },
        
        // Test 3: STRICT mode with NS still blocks
        {
            .test_name = "STRICT Mode + Network Namespace - Still Blocks",
            .program_path = "./sample_programs/network_test",
            .firewall_policy = FIREWALL_STRICT,
            .enable_network_namespace = 1,
            .expected_to_succeed = 0,  // Should be blocked by seccomp
        },
        
        // Test 4: Network Namespace alone blocks network
        {
            .test_name = "Network Namespace Only - Blocks External Network",
            .program_path = "./sample_programs/network_connect",
            .firewall_policy = FIREWALL_DISABLED,
            .enable_network_namespace = 1,
            .expected_to_succeed = 0,  // Should be blocked by namespace
        },
        
        // Test 5: MODERATE without NS has limited protection
        {
            .test_name = "MODERATE Mode without NS - Limited Protection",
            .program_path = "./sample_programs/network_test",
            .firewall_policy = FIREWALL_MODERATE,
            .enable_network_namespace = 0,
            .expected_to_succeed = 1,  // May succeed (weak setup)
        },
        
        // Test 6: MODERATE with NS provides isolation
        {
            .test_name = "MODERATE Mode + Network Namespace - Strong Protection",
            .program_path = "./sample_programs/network_connect",
            .firewall_policy = FIREWALL_MODERATE,
            .enable_network_namespace = 1,
            .expected_to_succeed = 0,  // Should be blocked by namespace
        },
        
        // Test 7: NO_NETWORK blocks HTTP requests
        {
            .test_name = "NO_NETWORK Mode - Blocks HTTP Request",
            .program_path = "./sample_programs/http_request",
            .firewall_policy = FIREWALL_NO_NETWORK,
            .enable_network_namespace = 0,
            .expected_to_succeed = 0,  // Should be blocked
        },
        
        // Test 8: NO_NETWORK blocks DNS lookups
        {
            .test_name = "NO_NETWORK Mode - Blocks DNS Lookup",
            .program_path = "./sample_programs/dns_lookup",
            .firewall_policy = FIREWALL_NO_NETWORK,
            .enable_network_namespace = 0,
            .expected_to_succeed = 0,  // Should be blocked
        },
        
        // Test 9: Disabled firewall without NS allows network
        {
            .test_name = "DISABLED Firewall without NS - Allows Network (Baseline)",
            .program_path = "./sample_programs/network_test",
            .firewall_policy = FIREWALL_DISABLED,
            .enable_network_namespace = 0,
            .expected_to_succeed = 1,  // Should succeed (no protection)
        },
    };
    
    int num_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    int errors = 0;
    
    printf("Running %d test cases...\n", num_tests);
    
    // Run all tests
    for (int i = 0; i < num_tests; i++) {
        tests[i].result = run_test(&tests[i]);
        
        switch (tests[i].result) {
            case TEST_PASS:
                passed++;
                break;
            case TEST_FAIL:
                failed++;
                break;
            case TEST_SKIP:
                skipped++;
                break;
            case TEST_ERROR:
                errors++;
                break;
        }
        
        // Small delay between tests
        sleep(1);
    }
    
    // Print summary
    printf("\n");
    printf(COLOR_BLUE "╔═══════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BLUE "║                    TEST RESULTS SUMMARY                   ║\n" COLOR_RESET);
    printf(COLOR_BLUE "╚═══════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    printf("Total Tests:  %d\n", num_tests);
    printf(COLOR_GREEN "✓ Passed:     %d" COLOR_RESET "\n", passed);
    printf(COLOR_RED "✗ Failed:     %d" COLOR_RESET "\n", failed);
    printf(COLOR_YELLOW "⊘ Skipped:    %d" COLOR_RESET "\n", skipped);
    printf(COLOR_RED "⚠ Errors:     %d" COLOR_RESET "\n", errors);
    printf("\n");
    
    // Print failed test details
    if (failed > 0 || errors > 0) {
        printf(COLOR_RED "Failed/Error Test Details:" COLOR_RESET "\n");
        for (int i = 0; i < num_tests; i++) {
            if (tests[i].result == TEST_FAIL || tests[i].result == TEST_ERROR) {
                printf("  • %s: %s\n", tests[i].test_name, tests[i].error_msg);
            }
        }
        printf("\n");
    }
    
    // Overall result
    if (failed == 0 && errors == 0) {
        printf(COLOR_GREEN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
        printf(COLOR_GREEN "  ✓ ALL TESTS PASSED!\n" COLOR_RESET);
        printf(COLOR_GREEN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
        printf("\n");
        return 0;
    } else {
        printf(COLOR_RED "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
        printf(COLOR_RED "  ✗ SOME TESTS FAILED\n" COLOR_RESET);
        printf(COLOR_RED "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
        printf("\n");
        return 1;
    }
}
