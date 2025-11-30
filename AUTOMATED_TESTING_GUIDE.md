# Automated Firewall Testing Guide

## Overview

This guide explains the **fully automated testing system** for the Sandbox Engine firewall. The testing suite performs comprehensive end-to-end verification of firewall enforcement without requiring manual intervention.

---

## Quick Start

### Run All Tests Automatically

```bash
# Make the test script executable (first time only)
chmod +x run_firewall_tests.sh

# Run comprehensive automated tests
./run_firewall_tests.sh
```

This single command will:
1. ✅ Clean previous builds
2. ✅ Compile all components (main, test_runner, sample programs)
3. ✅ Set up Linux capabilities (requires sudo)
4. ✅ Run automated firewall enforcement tests
5. ✅ Generate comprehensive test report

**No manual testing required!**

---

## What Gets Tested

### Firewall Enforcement Tests

The automated test suite verifies the following scenarios:

#### Test 1: NO_NETWORK Mode - Blocks Socket Creation
- **Firewall**: NO_NETWORK
- **Network Namespace**: Disabled
- **Expected**: Network syscalls blocked via seccomp-BPF
- **Test Program**: `network_test`
- **Verifies**: `socket()` returns EPERM

#### Test 2: STRICT Mode - Blocks Socket Creation
- **Firewall**: STRICT
- **Network Namespace**: Disabled
- **Expected**: Network syscalls blocked via seccomp-BPF
- **Test Program**: `network_test`
- **Verifies**: Complete network isolation at kernel level

#### Test 3: STRICT Mode + Network Namespace
- **Firewall**: STRICT
- **Network Namespace**: Enabled
- **Expected**: Network still blocked (seccomp takes precedence)
- **Test Program**: `network_test`
- **Verifies**: Defense-in-depth layers work together

#### Test 4: Network Namespace Only
- **Firewall**: DISABLED
- **Network Namespace**: Enabled
- **Expected**: External network blocked by namespace
- **Test Program**: `network_connect`
- **Verifies**: Namespace provides interface-level isolation

#### Test 5: MODERATE Mode without Network Namespace
- **Firewall**: MODERATE
- **Network Namespace**: Disabled
- **Expected**: Limited protection (network may succeed)
- **Test Program**: `network_test`
- **Verifies**: Weak setup detection

#### Test 6: MODERATE Mode + Network Namespace
- **Firewall**: MODERATE
- **Network Namespace**: Enabled
- **Expected**: Network blocked by namespace
- **Test Program**: `network_connect`
- **Verifies**: Recommended configuration works

#### Test 7: NO_NETWORK Blocks HTTP
- **Firewall**: NO_NETWORK
- **Network Namespace**: Disabled
- **Expected**: HTTP requests blocked
- **Test Program**: `http_request`
- **Verifies**: Application-level network operations blocked

#### Test 8: NO_NETWORK Blocks DNS
- **Firewall**: NO_NETWORK
- **Network Namespace**: Disabled
- **Expected**: DNS lookups blocked
- **Test Program**: `dns_lookup`
- **Verifies**: DNS resolution prevented

#### Test 9: Baseline Test (No Protection)
- **Firewall**: DISABLED
- **Network Namespace**: Disabled
- **Expected**: Network succeeds (baseline)
- **Test Program**: `network_test`
- **Verifies**: Test programs work when unprotected

---

## Test Components

### 1. Test Runner (`test_runner`)

**Location**: `src/test_runner.c`

A CLI tool that:
- Runs test programs inside the sandbox with different configurations
- Uses the sandbox API directly (no GUI required)
- Captures exit codes to determine success/failure
- Provides colored output with clear pass/fail indicators
- Runs non-interactively for CI/CD integration

**Exit Codes**:
- `0` = All tests passed ✓
- `1` = Some tests failed ✗

### 2. Test Script (`run_firewall_tests.sh`)

**Location**: `run_firewall_tests.sh`

Comprehensive test orchestration script that:
- Cleans and rebuilds the project
- Sets up Linux capabilities
- Runs pre-flight checks
- Executes all test cases
- Analyzes results
- Generates detailed reports
- Provides troubleshooting recommendations

### 3. Test Programs

**Location**: `sample_programs/`

Programs specifically designed to test firewall enforcement:

- **`network_test`**: Attempts to create TCP socket
- **`network_connect`**: Attempts to connect to remote server
- **`http_request`**: Attempts HTTP GET request
- **`dns_lookup`**: Attempts DNS resolution
- **`port_scan`**: Attempts port scanning

Each program:
- Returns exit code `0` if network operation succeeded
- Returns exit code `1` if network operation failed (as expected when blocked)
- Provides clear output about what happened

---

## Understanding Test Results

### Success Output

```
╔═══════════════════════════════════════════════════════════╗
║               ✓ ALL TESTS PASSED!                         ║
║                                                           ║
║  Firewall enforcement is working correctly                ║
╚═══════════════════════════════════════════════════════════╝

Firewall System Status: OPERATIONAL ✓

Key Findings:
  • NO_NETWORK mode: Blocking network syscalls ✓
  • STRICT mode: Blocking network syscalls ✓
  • Network Namespace: Providing isolation ✓
  • Seccomp-BPF: Enforcing at kernel level ✓
```

### Failure Output

```
╔═══════════════════════════════════════════════════════════╗
║               ✗ SOME TESTS FAILED                         ║
║                                                           ║
║  Firewall enforcement may not be working correctly        ║
╚═══════════════════════════════════════════════════════════╝

Firewall System Status: ISSUES DETECTED ✗

Failed Tests:
  • NO_NETWORK Mode - Blocks Socket Creation: Network succeeded but should have been blocked
```

### Test Status Indicators

- ✓ **PASS**: Test behaved as expected
- ✗ **FAIL**: Test did not behave as expected (enforcement failure)
- ⊘ **SKIP**: Test was skipped (missing program or dependency)
- ⚠ **ERROR**: Test encountered an error (timeout, crash, etc.)

---

## Manual Testing (Optional)

If you want to run tests manually:

### Build Test Runner Only

```bash
make test_runner
```

### Run Test Runner Directly

```bash
./test_runner
```

### Run Individual Test Programs

```bash
# Create sandbox manually and run test program
sudo ./main  # Use GUI to select program and configure firewall
```

---

## Troubleshooting

### Common Issues

#### Issue: "User namespaces not available"

**Solution**:
```bash
# Enable user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Or run with sudo
sudo ./run_firewall_tests.sh
```

#### Issue: "Seccomp not supported"

**Check kernel support**:
```bash
zcat /proc/config.gz | grep CONFIG_SECCOMP
# Should show: CONFIG_SECCOMP=y
```

**Solution**: Update to kernel 3.5+ or use a distribution with seccomp enabled

#### Issue: "Permission denied" errors

**Solution**:
```bash
# Run capability setup with sudo
sudo bash setup_capabilities.sh

# Verify capabilities
getcap main
```

#### Issue: Tests timeout

**Possible causes**:
- Slow system
- Test program hanging
- Firewall blocking unexpectedly

**Solution**:
```bash
# Check firewall log
cat /tmp/sandbox_firewall.log

# Run test manually to see output
./sample_programs/network_test
```

---

## Advanced Usage

### Run Specific Tests

Edit `src/test_runner.c` to comment out tests you don't want to run, then:

```bash
make test_runner
./test_runner
```

### Add Custom Tests

1. Create test program in `sample_programs/`
2. Add test case to `src/test_runner.c`:

```c
{
    .test_name = "My Custom Test",
    .program_path = "./sample_programs/my_test",
    .firewall_policy = FIREWALL_NO_NETWORK,
    .enable_network_namespace = 0,
    .expected_to_succeed = 0,  // Should be blocked
},
```

3. Rebuild and run:

```bash
make test_runner
./test_runner
```

### Integration with CI/CD

The test script is designed for automated CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Firewall Tests
  run: |
    chmod +x run_firewall_tests.sh
    ./run_firewall_tests.sh
```

Exit code `0` = all tests passed  
Exit code `1` = some tests failed

---

## Test Output Files

### Generated Files

- **`firewall_test_results_YYYYMMDD_HHMMSS.log`**: Detailed test output
- **`/tmp/sandbox_firewall.log`**: Firewall events and enforcement actions
- **`/tmp/sandbox_test_build.log`**: Compilation output
- **`/tmp/sandbox_test_clean.log`**: Clean operation output

### Log Analysis

```bash
# View detailed test results
cat firewall_test_results_*.log

# View firewall enforcement events
cat /tmp/sandbox_firewall.log

# Check recent firewall activity
tail -f /tmp/sandbox_firewall.log
```

---

## Performance

### Test Execution Time

Typical test suite execution time:
- **Compilation**: 10-30 seconds (depending on system)
- **Capability Setup**: 2-5 seconds (requires sudo interaction)
- **Test Execution**: 20-40 seconds (9 tests × ~2-3 seconds each)
- **Total**: ~1-2 minutes for complete test suite

### Resource Usage

- **CPU**: Low (test programs are lightweight)
- **Memory**: Minimal (<100 MB total)
- **Disk**: Negligible (logs <1 MB)
- **Network**: None (all tests are local)

---

## Validation Criteria

### What Makes a Test Pass?

A test passes when:

1. **Seccomp Enforcement**: NO_NETWORK/STRICT modes block syscalls
   - `socket()` returns `-1` with `errno = EPERM`
   - Test program exits with code `1` (failure, as expected)

2. **Namespace Isolation**: Network namespace blocks external access
   - `connect()` fails to reach external hosts
   - Only loopback interface visible

3. **Baseline Verification**: Disabled firewall allows network
   - Test programs can create sockets when unprotected
   - Confirms test programs work correctly

### What Makes a Test Fail?

A test fails when:

1. **Expected Blocking Doesn't Occur**:
   - NO_NETWORK mode allows socket creation
   - STRICT mode allows network access
   - Network namespace doesn't isolate

2. **Unexpected Blocking Occurs**:
   - DISABLED firewall blocks network
   - Baseline test fails

3. **Error Conditions**:
   - Test program doesn't exist
   - Timeout (>10 seconds)
   - Crash or segmentation fault

---

## Best Practices

### Before Running Tests

1. **Update system**: Ensure kernel supports required features
2. **Build clean**: Run `make clean` before testing
3. **Check dependencies**: Verify all sample programs compiled
4. **Review logs**: Check previous logs for clues if issues exist

### After Running Tests

1. **Review results**: Check pass/fail status for each test
2. **Analyze failures**: Look at specific error messages
3. **Check logs**: Review `/tmp/sandbox_firewall.log` for details
4. **Document issues**: Save test logs for troubleshooting

### Continuous Testing

Run tests regularly:
- After code changes
- Before commits/releases
- When updating kernel
- After configuration changes

---

## Summary

The automated testing system provides:

✅ **Comprehensive Coverage**: Tests all firewall modes and configurations  
✅ **Fully Automated**: No manual intervention required  
✅ **Clear Results**: Color-coded pass/fail indicators  
✅ **Detailed Reports**: Comprehensive logs and diagnostics  
✅ **CI/CD Ready**: Integrates with automated pipelines  
✅ **Fast Execution**: Complete test suite in ~1-2 minutes  

**Run tests before deploying to ensure firewall is working correctly!**

---

## Quick Reference

```bash
# Full test suite (recommended)
./run_firewall_tests.sh

# Just run tests (skip build)
./test_runner

# Build and run tests
make test

# Manual testing with GUI
./main
```

---

**For questions or issues, see TROUBLESHOOTING section or review test logs.**
