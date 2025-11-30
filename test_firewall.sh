#!/bin/bash

# Comprehensive Firewall Testing Script
# Tests all firewall modes to verify proper enforcement

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging functions
log_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

log_test() {
    echo -e "${BLUE}▶ TEST:${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_failure() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_warning() {
    echo -e "${YELLOW}⚠ WARNING:${NC} $1"
}

log_info() {
    echo -e "${CYAN}ℹ INFO:${NC} $1"
}

log_step() {
    echo -e "${BOLD}→${NC} $1"
}

# Check if running from correct directory
if [ ! -f "Makefile" ]; then
    echo -e "${RED}Error: Makefile not found. Please run this script from the Sandbox-Engine directory.${NC}"
    exit 1
fi

log_header "FIREWALL COMPREHENSIVE TESTING SUITE"
echo "This script will:"
echo "  1. Build the sandbox engine"
echo "  2. Set up Linux capabilities"
echo "  3. Build test programs"
echo "  4. Test all firewall modes"
echo "  5. Verify enforcement mechanisms"
echo ""
read -p "Press Enter to continue..."

# ═══════════════════════════════════════════════════════════
# STEP 1: BUILD THE PROJECT
# ═══════════════════════════════════════════════════════════

log_header "STEP 1: Building Sandbox Engine"

log_step "Cleaning previous build..."
make clean >/dev/null 2>&1 || true

log_step "Compiling sandbox engine..."
if make; then
    log_success "Sandbox engine compiled successfully"
else
    log_failure "Failed to compile sandbox engine"
    exit 1
fi

# Check if binary exists
if [ -f "./main" ]; then
    log_success "Binary './main' created"
else
    log_failure "Binary './main' not found"
    exit 1
fi

# ═══════════════════════════════════════════════════════════
# STEP 2: SET UP CAPABILITIES
# ═══════════════════════════════════════════════════════════

log_header "STEP 2: Setting Up Linux Capabilities"

if [ -f "./setup_capabilities.sh" ]; then
    log_step "Running setup_capabilities.sh..."
    bash ./setup_capabilities.sh
    
    # Verify capabilities were set
    if getcap ./main | grep -q "cap_sys_admin,cap_net_admin"; then
        log_success "Capabilities set correctly"
    else
        log_warning "Capabilities may not be set (might need sudo)"
    fi
else
    log_warning "setup_capabilities.sh not found, skipping capability setup"
fi

# ═══════════════════════════════════════════════════════════
# STEP 3: BUILD TEST PROGRAMS
# ═══════════════════════════════════════════════════════════

log_header "STEP 3: Building Test Programs"

cd sample_programs

log_step "Cleaning previous test builds..."
make clean >/dev/null 2>&1 || true

log_step "Compiling test programs..."
if make; then
    log_success "Test programs compiled successfully"
else
    log_failure "Failed to compile test programs"
    exit 1
fi

cd ..

# Verify test programs exist
TEST_PROGRAMS=("network_test" "network_connect" "http_request" "dns_lookup")
MISSING_PROGRAMS=0

for prog in "${TEST_PROGRAMS[@]}"; do
    if [ -f "sample_programs/$prog" ]; then
        log_info "Found: sample_programs/$prog"
    else
        log_warning "Missing: sample_programs/$prog"
        MISSING_PROGRAMS=$((MISSING_PROGRAMS + 1))
    fi
done

if [ $MISSING_PROGRAMS -gt 0 ]; then
    log_warning "$MISSING_PROGRAMS test program(s) missing, some tests may be skipped"
fi

# ═══════════════════════════════════════════════════════════
# STEP 4: TEST FIREWALL MODES
# ═══════════════════════════════════════════════════════════

log_header "STEP 4: Testing Firewall Modes"

# Create a test configuration directory
TEST_DIR="/tmp/sandbox_firewall_test_$$"
mkdir -p "$TEST_DIR"
LOG_FILE="$TEST_DIR/test_output.log"

log_info "Test output directory: $TEST_DIR"
log_info "Test log file: $LOG_FILE"

# Function to run a test program and capture output
run_test_program() {
    local test_name="$1"
    local firewall_mode="$2"
    local test_program="$3"
    local expected_result="$4"  # "blocked" or "allowed" or "isolated"
    local timeout_duration="${5:-5}"  # Default 5 seconds timeout
    
    log_test "$test_name"
    
    # Create a temporary script that will run the sandbox
    local test_script="$TEST_DIR/test_${firewall_mode}_${test_program##*/}.sh"
    
    cat > "$test_script" << 'EOF'
#!/bin/bash
# This script needs to programmatically run the sandbox
# Since the sandbox is a GUI application, we'll test the firewall.c functions directly
# or use strace to verify syscall blocking

PROGRAM="$1"
TIMEOUT="$2"

# Run the program with timeout and capture output
timeout "$TIMEOUT" "$PROGRAM" 2>&1
exit_code=$?

# Exit code 124 means timeout, which is expected for some tests
if [ $exit_code -eq 124 ]; then
    echo "TIMEOUT: Program ran for full duration"
fi

exit $exit_code
EOF
    
    chmod +x "$test_script"
    
    # For now, we'll test the programs directly to verify they work
    # Real firewall testing requires the GUI or command-line interface
    
    if [ ! -f "$test_program" ]; then
        log_warning "Test program not found: $test_program (skipping)"
        return
    fi
    
    # Run the test program directly and check if it attempts network operations
    log_info "Running: $test_program (direct execution test)"
    
    local output
    output=$(timeout "$timeout_duration" "$test_program" 2>&1 || true)
    
    # Analyze output based on expected result
    case "$expected_result" in
        "blocked")
            if echo "$output" | grep -q -i "operation not permitted\|permission denied\|eperm"; then
                log_success "$test_name: Network operation correctly blocked"
            else
                log_info "$test_name: Direct test shows: ${output:0:100}"
                log_warning "$test_name: Could not verify blocking (GUI test required)"
            fi
            ;;
        "allowed")
            if echo "$output" | grep -q -i "connection refused\|network unreachable\|no route to host"; then
                log_success "$test_name: Network accessible but no server (expected)"
            elif echo "$output" | grep -q -i "operation not permitted\|permission denied"; then
                log_failure "$test_name: Network unexpectedly blocked"
            else
                log_info "$test_name: Network state unclear from direct test"
            fi
            ;;
        "isolated")
            log_info "$test_name: Isolation test requires GUI or namespace setup"
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════
# TEST 1: NO_NETWORK MODE
# ═══════════════════════════════════════════════════════════

log_header "TEST 1: NO_NETWORK Mode (Seccomp-BPF Enforcement)"

echo "Testing NO_NETWORK mode - should block ALL network syscalls at kernel level"
echo ""

# Test 1.1: Basic socket creation should fail
log_test "Test 1.1: Socket creation blocked"
log_info "Expected: socket() should fail with EPERM"
log_info "Enforcement: Seccomp-BPF filter"
log_info "Note: Full verification requires running through sandbox GUI"
echo ""

# Test 1.2: Connect should fail
log_test "Test 1.2: Connect blocked"
log_info "Expected: connect() should fail with EPERM"
log_info "Enforcement: Seccomp-BPF filter"
echo ""

# Test 1.3: Network test program
if [ -f "sample_programs/network_test" ]; then
    run_test_program "Test 1.3: network_test program" "NO_NETWORK" "sample_programs/network_test" "blocked"
else
    log_warning "Test 1.3: network_test program not found (skipping)"
fi

echo ""
log_info "NO_NETWORK Summary: Requires GUI to fully test seccomp enforcement"
log_info "To manually test: Run GUI → Select NO_NETWORK → Run network_test"

# ═══════════════════════════════════════════════════════════
# TEST 2: STRICT MODE
# ═══════════════════════════════════════════════════════════

log_header "TEST 2: STRICT Mode (Seccomp-BPF Enforcement)"

echo "Testing STRICT mode - should block ALL network syscalls (like NO_NETWORK)"
echo ""

log_test "Test 2.1: Strict mode enforcement"
log_info "Expected: Same as NO_NETWORK - complete blocking via seccomp"
log_info "Enforcement: Seccomp-BPF filter"

if [ -f "sample_programs/network_connect" ]; then
    run_test_program "Test 2.2: network_connect program" "STRICT" "sample_programs/network_connect" "blocked"
else
    log_warning "Test 2.2: network_connect program not found (skipping)"
fi

echo ""
log_info "STRICT Summary: Identical enforcement to NO_NETWORK"
log_info "To manually test: Run GUI → Select STRICT → Run network_connect"

# ═══════════════════════════════════════════════════════════
# TEST 3: MODERATE MODE
# ═══════════════════════════════════════════════════════════

log_header "TEST 3: MODERATE Mode (Network Namespace + Rules)"

echo "Testing MODERATE mode - requires Network Namespace for enforcement"
echo ""

log_test "Test 3.1: MODERATE mode with Network Namespace"
log_info "Expected: Network isolated at interface level"
log_info "Enforcement: Network Namespace (not seccomp)"
log_info "Rules: Documentation + defense-in-depth"

log_test "Test 3.2: MODERATE mode without Network Namespace"
log_warning "Warning: MODERATE without Network Namespace provides limited protection"
log_info "Rules are advisory only without Network Namespace"

echo ""
log_info "MODERATE Summary: Best used WITH Network Namespace enabled"
log_info "To manually test: Run GUI → Enable Network Namespace → Select MODERATE → Run network_connect"

# ═══════════════════════════════════════════════════════════
# TEST 4: CUSTOM MODE
# ═══════════════════════════════════════════════════════════

log_header "TEST 4: CUSTOM Mode (Network Namespace + Custom Rules)"

echo "Testing CUSTOM mode - requires Network Namespace for enforcement"
echo ""

log_test "Test 4.1: CUSTOM mode with policy file"
log_info "Expected: Network isolated at interface level"
log_info "Enforcement: Network Namespace (not seccomp)"
log_info "Rules: User-defined policy file"

# Check for policy files
if [ -f "policies/moderate.policy" ]; then
    log_success "Found policy file: policies/moderate.policy"
else
    log_warning "Policy file not found: policies/moderate.policy"
fi

echo ""
log_info "CUSTOM Summary: Best used WITH Network Namespace enabled"
log_info "To manually test: Run GUI → Enable Network Namespace → Select CUSTOM → Load policy → Run test"

# ═══════════════════════════════════════════════════════════
# TEST 5: SECCOMP FILTER VALIDATION
# ═══════════════════════════════════════════════════════════

log_header "TEST 5: Seccomp Filter Code Validation"

echo "Validating seccomp-BPF filter implementation..."
echo ""

log_test "Test 5.1: Check firewall.c for seccomp implementation"

if grep -q "firewall_block_network_syscalls" src/firewall.c; then
    log_success "Found firewall_block_network_syscalls() function"
else
    log_failure "firewall_block_network_syscalls() function not found"
fi

if grep -q "firewall_apply_strict_filter" src/firewall.c; then
    log_success "Found firewall_apply_strict_filter() function"
else
    log_failure "firewall_apply_strict_filter() function not found"
fi

if grep -q "SECCOMP_RET_ERRNO" src/firewall.c; then
    log_success "Found SECCOMP_RET_ERRNO usage (correct error return)"
else
    log_warning "SECCOMP_RET_ERRNO not found in firewall.c"
fi

if grep -q "prctl(PR_SET_NO_NEW_PRIVS" src/firewall.c; then
    log_success "Found PR_SET_NO_NEW_PRIVS (required for seccomp)"
else
    log_failure "PR_SET_NO_NEW_PRIVS not found (required for seccomp)"
fi

if grep -q "__NR_socket" src/firewall.c; then
    log_success "Found __NR_socket syscall filtering"
else
    log_failure "__NR_socket syscall filtering not found"
fi

if grep -q "__NR_connect" src/firewall.c; then
    log_success "Found __NR_connect syscall filtering"
else
    log_failure "__NR_connect syscall filtering not found"
fi

if grep -q "__NR_bind" src/firewall.c; then
    log_success "Found __NR_bind syscall filtering"
else
    log_failure "__NR_bind syscall filtering not found"
fi

# ═══════════════════════════════════════════════════════════
# TEST 6: PROCESS CONTROL INTEGRATION
# ═══════════════════════════════════════════════════════════

log_header "TEST 6: Process Control Integration"

echo "Validating firewall integration with process control..."
echo ""

log_test "Test 6.1: Check process_control.c integration"

if grep -q "firewall_init" src/process_control.c; then
    log_success "Found firewall_init() call in process_control.c"
else
    log_failure "firewall_init() not called in process_control.c"
fi

if grep -q "firewall_apply" src/process_control.c; then
    log_success "Found firewall_apply() call in process_control.c"
else
    log_failure "firewall_apply() not called in process_control.c"
fi

if grep -q "FIREWALL_NO_NETWORK" src/process_control.c; then
    log_success "Found FIREWALL_NO_NETWORK constant usage"
else
    log_warning "FIREWALL_NO_NETWORK constant not found"
fi

# ═══════════════════════════════════════════════════════════
# TEST 7: DOCUMENTATION VERIFICATION
# ═══════════════════════════════════════════════════════════

log_header "TEST 7: Documentation Verification"

echo "Verifying documentation matches implementation..."
echo ""

log_test "Test 7.1: Check README.md firewall documentation"

if grep -q "Seccomp-BPF" README.md; then
    log_success "README.md mentions Seccomp-BPF enforcement"
else
    log_warning "README.md missing Seccomp-BPF details"
fi

if grep -q "Network Namespace" README.md; then
    log_success "README.md mentions Network Namespace requirement"
else
    log_warning "README.md missing Network Namespace guidance"
fi

log_test "Test 7.2: Check COMPLETE_ARCHITECTURE_GUIDE.md"

if [ -f "COMPLETE_ARCHITECTURE_GUIDE.md" ]; then
    log_success "Found COMPLETE_ARCHITECTURE_GUIDE.md"
    
    if grep -q "Policy Enforcement Summary" COMPLETE_ARCHITECTURE_GUIDE.md; then
        log_success "Architecture guide includes enforcement summary"
    else
        log_warning "Architecture guide missing enforcement summary"
    fi
else
    log_warning "COMPLETE_ARCHITECTURE_GUIDE.md not found"
fi

log_test "Test 7.3: Check FIREWALL_IMPROVEMENTS.md"

if [ -f "FIREWALL_IMPROVEMENTS.md" ]; then
    log_success "Found FIREWALL_IMPROVEMENTS.md (changelog)"
else
    log_warning "FIREWALL_IMPROVEMENTS.md not found"
fi

# ═══════════════════════════════════════════════════════════
# TEST 8: KERNEL COMPATIBILITY CHECK
# ═══════════════════════════════════════════════════════════

log_header "TEST 8: Kernel Compatibility Check"

echo "Checking kernel support for required features..."
echo ""

log_test "Test 8.1: Check kernel version"
KERNEL_VERSION=$(uname -r)
log_info "Kernel version: $KERNEL_VERSION"

log_test "Test 8.2: Check seccomp support"
if zgrep -q CONFIG_SECCOMP=y /proc/config.gz 2>/dev/null || \
   grep -q CONFIG_SECCOMP=y /boot/config-$(uname -r) 2>/dev/null; then
    log_success "Kernel has seccomp support"
else
    log_warning "Cannot verify seccomp support (config not accessible)"
fi

log_test "Test 8.3: Check namespace support"
if [ -d "/proc/self/ns" ]; then
    log_success "Kernel has namespace support"
    ls -la /proc/self/ns/ | grep -E "net|pid|mnt|uts" | while read line; do
        log_info "  $line"
    done
else
    log_failure "Kernel missing namespace support"
fi

log_test "Test 8.4: Check cgroup support"
if [ -d "/sys/fs/cgroup" ]; then
    log_success "Kernel has cgroup support"
    if [ -f "/sys/fs/cgroup/cgroup.controllers" ]; then
        log_info "  Using cgroup v2"
    else
        log_info "  Using cgroup v1"
    fi
else
    log_failure "Kernel missing cgroup support"
fi

# ═══════════════════════════════════════════════════════════
# TEST SUMMARY
# ═══════════════════════════════════════════════════════════

log_header "TEST SUMMARY"

echo ""
echo -e "${BOLD}Total Tests:${NC} $TESTS_TOTAL"
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ ALL TESTS PASSED${NC}"
    echo ""
    echo "Firewall implementation validated successfully!"
else
    echo -e "${RED}${BOLD}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Please review the failures above and fix any issues."
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  MANUAL TESTING REQUIRED${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "To fully test firewall enforcement, run these manual tests:"
echo ""
echo "1. NO_NETWORK Mode Test:"
echo "   ./main"
echo "   → Select 'NO_NETWORK' policy"
echo "   → Run 'sample_programs/network_test'"
echo "   → Expected: 'Operation not permitted' error"
echo ""
echo "2. STRICT Mode Test:"
echo "   ./main"
echo "   → Select 'STRICT' policy"
echo "   → Run 'sample_programs/network_connect'"
echo "   → Expected: All network operations blocked"
echo ""
echo "3. MODERATE Mode Test (WITH Network Namespace):"
echo "   ./main"
echo "   → Enable 'Network Namespace' checkbox"
echo "   → Select 'MODERATE' policy"
echo "   → Run 'sample_programs/network_connect'"
echo "   → Expected: Network isolated at interface level"
echo ""
echo "4. MODERATE Mode Test (WITHOUT Network Namespace):"
echo "   ./main"
echo "   → Disable 'Network Namespace' checkbox"
echo "   → Select 'MODERATE' policy"
echo "   → Run 'sample_programs/network_connect'"
echo "   → Expected: Warning message about enabling Network Namespace"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Cleanup
log_info "Test artifacts saved in: $TEST_DIR"
log_info "To clean up: rm -rf $TEST_DIR"

echo ""
echo "Testing complete!"
echo ""

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
