# Firewall Testing Guide

## Quick Start

1. **Build the project:**
   ```bash
   make clean
   make
   ```

2. **Run the sandbox:**
   ```bash
   sudo ./main
   ```

## Testing Scenarios

### Test 1: Complete Network Isolation (NO_NETWORK)

**Setup:**
- Select firewall policy: "No Network"
- Select test program: `sample_programs/network_test`

**Expected Result:**
- ❌ Socket creation should fail with "Operation not permitted"
- ✓ Message: "Firewall is working! Network syscalls are blocked."

**Verification:**
```bash
# Check logs
cat /tmp/sandbox_firewall.log
# Should show: "Firewall initialized: NO_NETWORK mode"
```

---

### Test 2: Moderate Policy (Default)

**Setup:**
- Select firewall policy: "Moderate"
- Select test program: `sample_programs/port_scan`

**Expected Result:**
- ❌ Dangerous ports blocked (Telnet-23, FTP-21, SMB-445)
- ✓ Common ports may show as refused (no service running)
- Network syscalls should work, but connections fail

---

### Test 3: HTTP Access Test

**Setup:**
- Select firewall policy: "Moderate"
- Select test program: `sample_programs/http_request`

**Expected Result:**
- ✓ Socket creation succeeds
- ✓ DNS lookup may work (if network namespace allows)
- Result depends on actual network availability

---

### Test 4: DNS Testing

**Setup:**
- Select firewall policy: "Moderate"
- Select test program: `sample_programs/dns_lookup`

**Expected Result:**
- DNS lookups should fail if network namespace is enabled
- If network namespace is disabled, DNS may work

---

### Test 5: Custom Policy

**Setup:**
1. Select firewall policy: "Custom"
2. Click "Load Policy File"
3. Select `policies/web_only.policy`
4. Select test program: `sample_programs/port_scan`

**Expected Result:**
- Only HTTP (80), HTTPS (443), and DNS (53) should be allowed
- All other ports blocked

---

## Policy Testing Matrix

| Program | Disabled | No Network | Strict | Moderate | Custom |
|---------|----------|------------|--------|----------|--------|
| network_test | ✓ Works | ❌ Blocked | ❌ Blocked | ⚠ Partial | Depends |
| http_request | ✓ Works | ❌ Blocked | ❌ Blocked | ✓ Works | Depends |
| dns_lookup | ✓ Works | ❌ Blocked | ❌ Blocked | ✓ Works | Depends |
| port_scan | ✓ All Open | ❌ Blocked | ❌ All Blocked | ⚠ Partial | Depends |

---

## Debugging

### Check if firewall is active:
```bash
# Check logs
cat /tmp/sandbox_firewall.log

# Should show initialization and policy application
```

### Verify seccomp is working:
```bash
# Run with strace to see syscall blocking
sudo strace -f ./main 2>&1 | grep -i eperm
```

### Check namespace isolation:
```bash
# In the GUI, enable all namespaces
# Run network_test
# Should see "Network namespace isolation is working"
```

---

## Common Issues

### Issue: "Operation not permitted" when running sandbox
**Solution:** Run with sudo or set capabilities:
```bash
sudo ./main
# OR
sudo setcap cap_sys_admin,cap_net_admin+ep ./main
```

### Issue: Network tests work even with NO_NETWORK policy
**Solution:** 
- Ensure seccomp filter is being applied
- Check kernel supports seccomp (Linux 3.5+)
- Verify logs at `/tmp/sandbox_firewall.log`

### Issue: All network tests fail even with Disabled policy
**Solution:**
- Check if network namespace is enabled in GUI
- Disable network namespace for full access
- Verify actual network connectivity

---

## Expected Log Output Examples

### NO_NETWORK Mode:
```
[timestamp] Firewall initialized: NO_NETWORK mode (complete isolation)
[timestamp] Applying firewall policy: NO_NETWORK
[timestamp] Network access completely blocked
```

### MODERATE Mode:
```
[timestamp] Firewall initialized: MODERATE mode
[timestamp] Rule added: Block Telnet
[timestamp] Rule added: Block FTP
[timestamp] Rule added: Allow HTTP
[timestamp] Applying firewall policy: MODERATE
[timestamp] Firewall active with 6 rules
```

---

## Integration with Namespaces

The firewall works best when combined with namespaces:

1. **Network Namespace + NO_NETWORK:** Maximum isolation
2. **Network Namespace + MODERATE:** Isolated network stack with filtered access
3. **No Namespace + MODERATE:** System network with firewall rules

Test all combinations to understand the security layers.
