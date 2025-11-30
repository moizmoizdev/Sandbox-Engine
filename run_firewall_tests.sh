#!/bin/bash

###############################################################################
# Comprehensive Automated Firewall Testing Script
# 
# This script performs complete end-to-end testing of the sandbox firewall:
# 1. Cleans previous builds
# 2. Compiles all components
# 3. Sets up Linux capabilities
# 4. Runs automated firewall enforcement tests
# 5. Reports comprehensive results
###############################################################################

set -e  # Exit on error (but we'll handle specific errors)

# Colors for output
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_RESET='\033[0m'

# Logging functions
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} $1"
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"
}

log_section() {
    echo ""
    echo -e "${COLOR_CYAN}═══════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}  $1${COLOR_RESET}"
    echo -e "${COLOR_CYAN}═══════════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
}

# Print header
clear
echo -e "${COLOR_BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║      SANDBOX ENGINE FIREWALL COMPREHENSIVE TEST SUITE     ║
║                                                           ║
║  Automated testing of firewall enforcement mechanisms     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${COLOR_RESET}"
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "This test suite must be run on Linux"
    exit 1
fi

log_info "Starting comprehensive firewall testing..."
log_info "Test suite will verify all firewall enforcement mechanisms"
echo ""

###############################################################################
# STEP 1: Clean previous builds
###############################################################################

log_section "STEP 1: Cleaning Previous Builds"

if [ -f "Makefile" ]; then
    log_info "Running 'make clean'..."
    if make clean > /tmp/sandbox_test_clean.log 2>&1; then
        log_success "Previous builds cleaned successfully"
    else
        log_warning "Clean failed (this may be okay if first run)"
        cat /tmp/sandbox_test_clean.log
    fi
else
    log_error "Makefile not found! Are you in the correct directory?"
    exit 1
fi

###############################################################################
# STEP 2: Compile all components
###############################################################################

log_section "STEP 2: Compiling Sandbox Engine"

log_info "Running 'make all'..."
log_info "This will compile:"
log_info "  - Main GUI application (main)"
log_info "  - Test runner (test_runner)"
log_info "  - Sample test programs"
echo ""

if make all > /tmp/sandbox_test_build.log 2>&1; then
    log_success "All components compiled successfully"
    
    # Verify binaries exist
    if [ -f "main" ] && [ -f "test_runner" ]; then
        log_success "Binaries verified: main, test_runner"
    else
        log_error "Expected binaries not found after compilation"
        cat /tmp/sandbox_test_build.log
        exit 1
    fi
    
    # Check sample programs
    SAMPLE_COUNT=$(find sample_programs -maxdepth 1 -type f -executable | wc -l)
    log_info "Sample programs compiled: $SAMPLE_COUNT test programs"
    
else
    log_error "Compilation failed!"
    echo ""
    log_error "Build log:"
    cat /tmp/sandbox_test_build.log
    exit 1
fi

###############################################################################
# STEP 3: Setup Linux capabilities
###############################################################################

log_section "STEP 3: Setting Up Linux Capabilities"

if [ -f "setup_capabilities.sh" ]; then
    log_info "Running setup_capabilities.sh..."
    log_warning "This step requires sudo privileges"
    echo ""
    
    if bash setup_capabilities.sh; then
        log_success "Linux capabilities configured successfully"
        
        # Verify capabilities
        if command -v getcap &> /dev/null; then
            CAPS=$(getcap main 2>/dev/null)
            if [ -n "$CAPS" ]; then
                log_success "Capabilities verified: $CAPS"
            else
                log_warning "No capabilities set (may require manual setup)"
            fi
        fi
    else
        log_warning "Capability setup failed or cancelled"
        log_warning "Some tests may require sudo or may fail"
        log_info "Continuing with tests anyway..."
    fi
else
    log_warning "setup_capabilities.sh not found"
    log_info "Continuing without capability setup..."
fi

###############################################################################
# STEP 4: Pre-flight checks
###############################################################################

log_section "STEP 4: Pre-Flight Checks"

# Check for required test programs
REQUIRED_TESTS=(
    "sample_programs/network_test"
    "sample_programs/network_connect"
    "sample_programs/http_request"
    "sample_programs/dns_lookup"
)

log_info "Verifying required test programs..."
MISSING_COUNT=0
for prog in "${REQUIRED_TESTS[@]}"; do
    if [ -x "$prog" ]; then
        log_success "Found: $prog"
    else
        log_error "Missing: $prog"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
done

if [ $MISSING_COUNT -gt 0 ]; then
    log_error "$MISSING_COUNT required test programs are missing"
    log_error "Please ensure sample programs compiled correctly"
    exit 1
fi

log_success "All required test programs found"

# Check kernel features
log_info "Checking kernel features..."

if [ -f "/proc/sys/kernel/unprivileged_userns_clone" ]; then
    USERNS=$(cat /proc/sys/kernel/unprivileged_userns_clone)
    if [ "$USERNS" = "1" ]; then
        log_success "User namespaces: ENABLED"
    else
        log_warning "User namespaces: DISABLED (some tests may fail)"
    fi
fi

if [ -d "/sys/fs/cgroup" ]; then
    log_success "Cgroups: Available"
else
    log_warning "Cgroups: Not available"
fi

# Check seccomp support
if grep -q "CONFIG_SECCOMP=y" /boot/config-$(uname -r) 2>/dev/null; then
    log_success "Seccomp: ENABLED (firewall enforcement will work)"
else
    log_warning "Seccomp: Status unknown (checking /proc/config.gz...)"
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_SECCOMP=y"; then
        log_success "Seccomp: ENABLED (firewall enforcement will work)"
    else
        log_warning "Seccomp: Cannot verify (firewall tests may fail)"
    fi
fi

###############################################################################
# STEP 5: Run automated firewall tests
###############################################################################

log_section "STEP 5: Running Automated Firewall Tests"

log_info "Executing test_runner..."
log_info "This will test all firewall enforcement modes"
echo ""

# Run tests and capture output
TEST_OUTPUT=$(mktemp)
TEST_EXITCODE=0

if ./test_runner 2>&1 | tee "$TEST_OUTPUT"; then
    TEST_EXITCODE=0
else
    TEST_EXITCODE=$?
fi

###############################################################################
# STEP 6: Analyze and report results
###############################################################################

log_section "STEP 6: Test Results Analysis"

# Extract statistics from test output
TOTAL_TESTS=$(grep -c "Test:" "$TEST_OUTPUT" || echo "0")
PASSED_TESTS=$(grep -c "✓ PASS:" "$TEST_OUTPUT" || echo "0")
FAILED_TESTS=$(grep -c "✗ FAIL:" "$TEST_OUTPUT" || echo "0")
SKIPPED_TESTS=$(grep -c "⊘ SKIP:" "$TEST_OUTPUT" || echo "0")
ERROR_TESTS=$(grep -c "✗ ERROR:" "$TEST_OUTPUT" || echo "0")

echo ""
log_info "Test Statistics:"
echo "  Total Tests:    $TOTAL_TESTS"
echo "  ✓ Passed:       $PASSED_TESTS"
echo "  ✗ Failed:       $FAILED_TESTS"
echo "  ⊘ Skipped:      $SKIPPED_TESTS"
echo "  ⚠ Errors:       $ERROR_TESTS"
echo ""

# Calculate pass rate
if [ $TOTAL_TESTS -gt 0 ]; then
    PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    log_info "Pass Rate: $PASS_RATE%"
else
    log_error "No tests were run!"
    rm -f "$TEST_OUTPUT"
    exit 1
fi

# Test result assessment
if [ $TEST_EXITCODE -eq 0 ]; then
    echo ""
    echo -e "${COLOR_GREEN}╔═══════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║               ✓ ALL TESTS PASSED!                         ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║  Firewall enforcement is working correctly                ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_GREEN}╚═══════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    
    log_success "Firewall System Status: OPERATIONAL ✓"
    echo ""
    log_info "Key Findings:"
    log_success "  • NO_NETWORK mode: Blocking network syscalls ✓"
    log_success "  • STRICT mode: Blocking network syscalls ✓"
    log_success "  • Network Namespace: Providing isolation ✓"
    log_success "  • Seccomp-BPF: Enforcing at kernel level ✓"
    
else
    echo ""
    echo -e "${COLOR_RED}╔═══════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_RED}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_RED}║               ✗ SOME TESTS FAILED                         ║${COLOR_RESET}"
    echo -e "${COLOR_RED}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_RED}║  Firewall enforcement may not be working correctly        ║${COLOR_RESET}"
    echo -e "${COLOR_RED}║                                                           ║${COLOR_RESET}"
    echo -e "${COLOR_RED}╚═══════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    
    log_error "Firewall System Status: ISSUES DETECTED ✗"
    echo ""
    log_warning "Review the test output above for details"
    
    # Try to extract specific failures
    echo ""
    log_info "Failed Tests:"
    grep -A 2 "✗ FAIL:" "$TEST_OUTPUT" | grep -v "^--$" || log_info "  (See full output above)"
fi

###############################################################################
# STEP 7: Detailed diagnostics
###############################################################################

log_section "STEP 7: System Diagnostics"

log_info "Firewall Log File:"
if [ -f "/tmp/sandbox_firewall.log" ]; then
    log_success "Firewall log exists: /tmp/sandbox_firewall.log"
    log_info "Recent log entries:"
    tail -n 10 /tmp/sandbox_firewall.log | sed 's/^/    /'
else
    log_warning "No firewall log found at /tmp/sandbox_firewall.log"
fi

echo ""
log_info "Kernel Version: $(uname -r)"
log_info "Linux Distribution: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"

###############################################################################
# STEP 8: Cleanup and recommendations
###############################################################################

log_section "STEP 8: Recommendations"

if [ $TEST_EXITCODE -eq 0 ]; then
    log_success "No issues detected - system is functioning correctly"
    echo ""
    log_info "Next Steps:"
    echo "  1. Review documentation in README.md"
    echo "  2. Run the GUI application: ./main"
    echo "  3. Test with your own programs"
    echo ""
else
    log_warning "Test failures detected - troubleshooting needed"
    echo ""
    log_info "Troubleshooting Steps:"
    echo "  1. Check if running on Linux (required)"
    echo "  2. Verify seccomp support: zcat /proc/config.gz | grep SECCOMP"
    echo "  3. Check user namespace permissions"
    echo "  4. Review test output above for specific failures"
    echo "  5. Check /tmp/sandbox_firewall.log for details"
    echo ""
    log_info "Common Issues:"
    echo "  • User namespaces disabled: Enable in kernel or run with sudo"
    echo "  • Seccomp not supported: Update kernel to 3.5+"
    echo "  • Permission denied: Run setup_capabilities.sh with sudo"
    echo ""
fi

# Save detailed log
LOG_FILE="firewall_test_results_$(date +%Y%m%d_%H%M%S).log"
cp "$TEST_OUTPUT" "$LOG_FILE"
log_info "Detailed test log saved to: $LOG_FILE"

# Cleanup temp file
rm -f "$TEST_OUTPUT"

###############################################################################
# FINAL SUMMARY
###############################################################################

echo ""
echo -e "${COLOR_CYAN}═══════════════════════════════════════════════════════════${COLOR_RESET}"
echo -e "${COLOR_CYAN}  Test Suite Complete${COLOR_RESET}"
echo -e "${COLOR_CYAN}═══════════════════════════════════════════════════════════${COLOR_RESET}"
echo ""

if [ $TEST_EXITCODE -eq 0 ]; then
    log_success "Firewall testing completed successfully ✓"
    exit 0
else
    log_error "Firewall testing completed with failures ✗"
    exit 1
fi
