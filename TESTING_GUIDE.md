# Sandbox Engine Testing Guide

This guide explains how to test the various security features of the Sandbox Engine.

## Building Test Programs

```bash
# Build all programs including security tests
make clean && make

# Or build only security test programs
cd sample_programs && make security_tests
```

## Test Programs Overview

| Program | Purpose | Tests |
|---------|---------|-------|
| `print_info` | Displays sandbox environment info | Namespace isolation, hostname |
| `stack_test` | Tests stack size limits | Memory protection - stack limits |
| `mmap_exec_test` | Tests W^X protection | Memory protection - RWX memory |
| `mprotect_test` | Tests mprotect restrictions | Memory protection - W^X via mprotect |
| `network_connect` | Tests network connections | Firewall policies |
| `syscall_test` | Makes various syscalls | Syscall tracking feature |

---

## Testing Scenarios

### 1. Basic Sandbox Test

**Program:** `sample_programs/print_info`

**Expected Behavior:**
- Shows PID = 1 if PID namespace is enabled
- Shows hostname = "sandbox" if UTS namespace is enabled
- Displays current resource limits

**Steps:**
1. Select `sample_programs/print_info`
2. Enable PID and UTS namespaces in the "Namespaces" tab
3. Click "Run in Sandbox"
4. Check the Logs tab for output

---

### 2. Stack Protection Test

**Program:** `sample_programs/stack_test`

**Test Configurations:**

| Stack Limit | Expected Result |
|-------------|-----------------|
| 8192 KB (8MB) | Should complete successfully |
| 1024 KB (1MB) | May crash with stack overflow |
| 512 KB | Should crash with stack overflow |

**Steps:**
1. Go to "Memory Protection" tab
2. Enable "Limit Stack Size"
3. Set to 8192 KB (8 MB)
4. Run `stack_test` - should succeed
5. Change to 512 KB and run again - should fail

---

### 3. W^X (Write XOR Execute) Protection Test

**Programs:** 
- `sample_programs/mmap_exec_test`
- `sample_programs/mprotect_test`

**Steps:**
1. Go to "Memory Protection" tab
2. Enable "W^X (Write XOR Execute)"
3. Run `mmap_exec_test`
4. **Expected:** "BLOCKED! mmap failed: Operation not permitted"
5. Run `mprotect_test`
6. **Expected:** "BLOCKED! mprotect failed: Operation not permitted"

**Without Protection:**
- Disable W^X
- Run tests again
- They should succeed (code executes)

---

### 4. Firewall Policy Tests

**Program:** `sample_programs/network_connect`

#### Test: No Network Policy
1. Go to "Firewall" tab
2. Select "No Network" policy
3. Run `network_connect`
4. **Expected:** All connections blocked or syscalls fail

#### Test: Moderate Policy
1. Select "Moderate" policy
2. Run `network_connect`
3. **Expected:** 
   - HTTP/HTTPS allowed
   - SSH may be allowed
   - Telnet (23) blocked
   - SMB (445) blocked

#### Test: Strict Policy
1. Select "Strict" policy
2. Run `network_connect`
3. **Expected:** Only localhost connections allowed

#### Test: Disabled
1. Select "Disabled" policy
2. Run `network_connect`
3. **Expected:** All connections attempt normally (may fail due to actual network)

---

### 5. Syscall Tracking Test

**Program:** `sample_programs/syscall_test`

**Steps:**
1. Go to "Syscalls" tab
2. Check "Enable Syscall Tracking"
3. Run `syscall_test`
4. Observe:
   - Syscall log shows real-time calls
   - Statistics table shows syscall counts
   - Common syscalls: open, read, write, close, mmap, etc.

---

### 6. Resource Limits Test

**Programs:** 
- `sample_programs/cpu_intensive`
- `sample_programs/memory_test`
- `sample_programs/fork_bomb`

#### CPU Limit Test
1. Go to "Resource Limits" tab
2. Enable resource limits
3. Set CPU Limit to 50%
4. Run `cpu_intensive`
5. Monitor CPU usage in "Monitoring" tab

#### Memory Limit Test
1. Set Memory Limit to 100 MB
2. Run `memory_test`
3. Process should be killed when exceeding limit

#### Process Limit Test
1. Set Max Processes to 10
2. Run `fork_bomb`
3. Fork should fail after limit reached

---

### 7. Namespace Isolation Test

**Program:** `sample_programs/print_info`

| Namespace | Effect |
|-----------|--------|
| PID | Process sees itself as PID 1 |
| UTS | Hostname shows as "sandbox" |
| Mount | Isolated filesystem view |
| Network | Isolated network stack |

**Steps:**
1. Enable only PID namespace, run `print_info`, check PID
2. Enable only UTS namespace, run `print_info`, check hostname
3. Enable all namespaces, run `print_info`, verify all isolation

---

## Expected Log Output Examples

### Successful Memory Protection
```
[Memory Protection] Applying memory protections (flags=0x13)
[Memory Protection] Stack size limited to 8192 KB
[Memory Protection] NO_NEW_PRIVS enabled
[Memory Protection] W^X seccomp filter applied
```

### Firewall Block
```
[Firewall] Policy: MODERATE
[Firewall] Rule 'Block Telnet' - DENY TCP port 23
[Firewall] Blocked connection to port 23
```

### Namespace Isolation
```
[Namespace] Setting up PID namespace
[Namespace] Process is now PID 1 in new namespace
[Namespace] Setting hostname to 'sandbox'
```

---

## Troubleshooting

### Logs not appearing in GUI
- Check the "Logs" tab
- Logs are read from `/tmp/sandbox_firewall.log`
- Console output from programs appears in terminal, not GUI

### Memory protection not working
- Requires Linux kernel with seccomp support
- Some protections require root privileges
- Check kernel config: `grep SECCOMP /boot/config-$(uname -r)`

### Firewall not blocking
- Seccomp firewall requires root for some policies
- "No Network" uses syscall blocking, others use iptables-style rules
- Check if running with sufficient privileges

### Namespace setup fails
- Most namespaces require root or specific capabilities
- PID namespace requires `CAP_SYS_ADMIN`
- Try running the sandbox engine with `sudo`

---

## Quick Test Checklist

- [ ] `print_info` shows PID 1 with PID namespace
- [ ] `stack_test` crashes with low stack limit
- [ ] `mmap_exec_test` blocked with W^X enabled
- [ ] `network_connect` blocked with "No Network" policy
- [ ] `syscall_test` shows syscalls in tracking tab
- [ ] Resource limits kill `memory_test` at limit
