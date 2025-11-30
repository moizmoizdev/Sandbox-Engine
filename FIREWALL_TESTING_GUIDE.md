# Firewall Testing Guide

## Quick Start

### Automatic Testing Script

Run the comprehensive firewall test suite:

```bash
chmod +x test_firewall.sh
./test_firewall.sh
```

This script will:
1. ✅ Build the sandbox engine (`make`)
2. ✅ Set up Linux capabilities (`setup_capabilities.sh`)
3. ✅ Build test programs (`make` in sample_programs/)
4. ✅ Test all firewall modes
5. ✅ Validate seccomp-BPF implementation
6. ✅ Check kernel compatibility
7. ✅ Verify documentation accuracy

---

## What the Test Script Does

### Automated Tests (8 Test Suites)

#### TEST 1: NO_NETWORK Mode
- ✅ Validates seccomp-BPF enforcement
- ✅ Checks for syscall blocking
- ✅ Tests network_test program

#### TEST 2: STRICT Mode
- ✅ Validates seccomp-BPF enforcement (similar to NO_NETWORK)
- ✅ Tests network_connect program

#### TEST 3: MODERATE Mode
- ⚠️ Validates Network Namespace requirement
- ⚠️ Checks for proper warning messages

#### TEST 4: CUSTOM Mode
- ⚠️ Validates policy file loading
- ⚠️ Checks Network Namespace integration

#### TEST 5: Seccomp Filter Code Validation
- ✅ Verifies `firewall_block_network_syscalls()` exists
- ✅ Verifies `firewall_apply_strict_filter()` exists
- ✅ Checks for SECCOMP_RET_ERRNO usage
- ✅ Validates PR_SET_NO_NEW_PRIVS flag
- ✅ Confirms __NR_socket filtering
- ✅ Confirms __NR_connect filtering
- ✅ Confirms __NR_bind filtering

#### TEST 6: Process Control Integration
- ✅ Validates firewall_init() calls
- ✅ Validates firewall_apply() calls
- ✅ Checks policy constant usage

#### TEST 7: Documentation Verification
- ✅ Validates README.md accuracy
- ✅ Checks COMPLETE_ARCHITECTURE_GUIDE.md
- ✅ Verifies FIREWALL_IMPROVEMENTS.md exists

#### TEST 8: Kernel Compatibility
- ✅ Checks kernel version
- ✅ Validates seccomp support
- ✅ Validates namespace support
- ✅ Validates cgroup support

---

## Manual Testing (Required for Full Verification)

The automated script validates the code implementation, but **manual GUI testing** is required to verify runtime behavior.

### Manual Test 1: NO_NETWORK Mode

```bash
# 1. Start the sandbox
./main

# 2. In GUI:
#    - Select firewall policy: "No Network"
#    - Click "Select File"
#    - Choose: sample_programs/network_test
#    - Click "Run"

# 3. Expected output in Logs tab:
✓ NO_NETWORK: Complete network isolation active
Network syscalls blocked via seccomp

# 4. Expected in program output:
socket() failed: Operation not permitted
✓ Firewall is working! Network syscalls are blocked.
```

**Expected Result**: ✅ socket() call fails with EPERM

### Manual Test 2: STRICT Mode

```bash
# 1. Start the sandbox
./main

# 2. In GUI:
#    - Select firewall policy: "Strict"
#    - Click "Select File"
#    - Choose: sample_programs/network_connect
#    - Click "Run"

# 3. Expected output:
✓ STRICT: Network blocked at kernel level
To allow specific connections, enable Network Namespace and configure routing

# 4. Expected in program output:
socket() failed: Operation not permitted
```

**Expected Result**: ✅ All network syscalls blocked at kernel level

### Manual Test 3: MODERATE Mode WITH Network Namespace

```bash
# 1. Start the sandbox
./main

# 2. In GUI:
#    - Go to "Namespaces" tab
#    - ✅ Enable "Network Namespace" checkbox
#    - Go to "Firewall" tab
#    - Select firewall policy: "Moderate"
#    - Click "Select File"
#    - Choose: sample_programs/network_connect
#    - Click "Run"

# 3. Expected output:
=== Firewall Rules Active (6 rules) ===
  [0] ✗ DENY TCP Block Telnet port 23
  [1] ✗ DENY TCP Block FTP port 21
  ...

ⓘ IMPORTANT: MODERATE/CUSTOM modes provide rule-based filtering.
  For strongest isolation, enable Network Namespace in the Namespaces tab.

# 4. Expected behavior:
Network isolated at interface level (no host network access)
```

**Expected Result**: ✅ Network isolated by Network Namespace, rules documented

### Manual Test 4: MODERATE Mode WITHOUT Network Namespace

```bash
# 1. Start the sandbox
./main

# 2. In GUI:
#    - Go to "Namespaces" tab
#    - ❌ Disable "Network Namespace" checkbox
#    - Go to "Firewall" tab
#    - Select firewall policy: "Moderate"
#    - Click "Select File"
#    - Choose: sample_programs/network_connect
#    - Click "Run"

# 3. Expected output:
MODERATE mode: Rules configured, best used with Network Namespace
NOTE: For strongest protection, enable Network Namespace isolation

⚠ WARNING: Limited protection without Network Namespace

# 4. Expected behavior:
Warning message displayed
Rules advisory only
```

**Expected Result**: ⚠️ Warning displayed about enabling Network Namespace

### Manual Test 5: CUSTOM Policy with File

```bash
# 1. Start the sandbox
./main

# 2. In GUI:
#    - Enable "Network Namespace" (recommended)
#    - Select firewall policy: "Custom"
#    - Click "Load Policy File"
#    - Choose: policies/moderate.policy
#    - Click "Select File"
#    - Choose: sample_programs/port_scan
#    - Click "Run"

# 3. Expected output:
Loaded 9 firewall rules from policies/moderate.policy

=== Firewall Rules Active (9 rules) ===
  ...rules displayed...

# 4. Expected behavior:
Custom rules loaded and displayed
```

**Expected Result**: ✅ Custom policy loaded correctly

---

## Test Results Interpretation

### ✅ PASS Indicators

- `✓ PASS:` - Test passed successfully
- `✓` in output - Feature working correctly
- Green colored output - Success

### ✗ FAIL Indicators

- `✗ FAIL:` - Test failed
- Red colored output - Failure
- Missing expected functionality

### ⚠️ WARNING Indicators

- `⚠ WARNING:` - Non-critical issue or limitation
- Yellow colored output - Needs attention
- Feature may work with caveats

### ℹ INFO Indicators

- `ℹ INFO:` - Informational message
- Cyan colored output - Additional context
- Not a test result, just information

---

## Expected Test Output

### Successful Run

```
═══════════════════════════════════════════════════════════
  FIREWALL COMPREHENSIVE TESTING SUITE
═══════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════
  STEP 1: Building Sandbox Engine
═══════════════════════════════════════════════════════════

→ Cleaning previous build...
→ Compiling sandbox engine...
✓ PASS: Sandbox engine compiled successfully
✓ PASS: Binary './main' created

═══════════════════════════════════════════════════════════
  STEP 2: Setting Up Linux Capabilities
═══════════════════════════════════════════════════════════

...

═══════════════════════════════════════════════════════════
  TEST SUMMARY
═══════════════════════════════════════════════════════════

Total Tests: 25
Passed: 25
Failed: 0

✓ ALL TESTS PASSED

Firewall implementation validated successfully!
```

---

## Troubleshooting

### Issue: Tests fail to compile

**Solution**:
```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install build-essential pkg-config libgtk-4-dev libwebkitgtk-6.0-dev

# Clean and rebuild
make clean
make
```

### Issue: Capabilities not set

**Solution**:
```bash
# Install libcap
sudo apt install libcap2-bin

# Run setup script
./setup_capabilities.sh

# Or run with sudo
sudo ./main
```

### Issue: "Operation not permitted" errors

**Solution**:
```bash
# Option 1: Set capabilities
sudo setcap cap_sys_admin,cap_net_admin+ep ./main

# Option 2: Run with sudo
sudo ./main

# Option 3: Continue without namespaces
# Firewall seccomp filters still work without root
```

### Issue: Network tests don't show blocking

**Possible Causes**:
1. Firewall mode is DISABLED
2. Network Namespace not enabled for MODERATE/CUSTOM
3. Seccomp not supported by kernel
4. Test program not correctly built

**Solution**:
1. Verify firewall policy selected (NO_NETWORK or STRICT for guaranteed blocking)
2. Enable Network Namespace for MODERATE/CUSTOM modes
3. Check kernel version (Linux 3.5+ for seccomp)
4. Rebuild test programs: `cd sample_programs && make clean && make`

### Issue: Kernel doesn't support seccomp

**Check**:
```bash
# Check kernel config
zgrep CONFIG_SECCOMP /proc/config.gz

# Or check in boot config
grep CONFIG_SECCOMP /boot/config-$(uname -r)
```

**Solution**: Upgrade kernel to version 3.5 or later

---

## Quick Reference

### Test Script Commands

```bash
# Run full test suite
./test_firewall.sh

# View test output
cat /tmp/sandbox_firewall_test_*/test_output.log

# Clean up test artifacts
rm -rf /tmp/sandbox_firewall_test_*
```

### Build Commands

```bash
# Build sandbox
make

# Clean and rebuild
make clean && make

# Build test programs
cd sample_programs && make

# Set capabilities
./setup_capabilities.sh
```

### Manual Testing Commands

```bash
# Start GUI
./main

# Run with sudo (if capabilities not set)
sudo ./main

# Check capabilities
getcap ./main
```

---

## Test Program Descriptions

### network_test
- Tests basic socket creation
- Best for: Testing NO_NETWORK/STRICT modes
- Expected with firewall: EPERM error

### network_connect
- Tests socket + connect operations
- Best for: Comprehensive network testing
- Expected with firewall: Connection blocked

### http_request
- Tests HTTP GET request
- Best for: Testing MODERATE mode with HTTP allowed
- Expected: May succeed with MODERATE if DNS works

### dns_lookup
- Tests DNS resolution
- Best for: Testing DNS rules in MODERATE mode
- Expected: Blocked in NO_NETWORK/STRICT

### port_scan
- Tests connections to multiple ports
- Best for: Testing MODERATE port filtering
- Expected: Dangerous ports blocked, safe ports may work

---

## Continuous Integration

For automated testing in CI/CD:

```bash
#!/bin/bash
# ci_test.sh

set -e

# Run firewall tests
./test_firewall.sh

# Check exit code
if [ $? -eq 0 ]; then
    echo "✓ All firewall tests passed"
    exit 0
else
    echo "✗ Firewall tests failed"
    exit 1
fi
```

---

## Additional Resources

- **COMPLETE_ARCHITECTURE_GUIDE.md** - Detailed firewall architecture
- **FIREWALL_IMPROVEMENTS.md** - Changelog of firewall enhancements
- **README.md** - General usage and setup
- **TESTING_FIREWALL.md** - Specific firewall testing scenarios

---

**Last Updated**: November 30, 2025  
**Script Version**: 1.0  
**Status**: Ready for Testing
