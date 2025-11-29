# Stress Test Master - User Guide

## Overview

The **Stress Test Master** is an interactive tool designed to test your sandbox's resource limits (cgroups) and isolation capabilities.

## Features

- 🧠 **Memory Stress Test** - Allocate configurable amounts of RAM (64 MB - 8 GB)
- 🧵 **Thread Stress Test** - Create configurable number of threads (1 - 500)
- 🔀 **Process Stress Test** - Fork configurable number of processes (1 - 100)
- ⚡ **CPU Stress Test** - Configurable CPU intensity (1-10 scale)
- 🌪️ **Combined Tests** - Run multiple tests simultaneously
- ⚡ **Quick Presets** - Pre-configured test scenarios

## Quick Start

### 1. Compile the Program

```bash
cd sample_programs
make stress_master
```

### 2. Run in Sandbox

Open your sandbox GUI, then:
1. Click "Select File"
2. Navigate to `sample_programs/stress_master`
3. Configure cgroup limits in the GUI
4. Click "Run"

### 3. Use the Interactive Menu

The program will display a menu:

```
═══════════════════════════════════════════════════════════════════
            🔥 STRESS TEST MASTER CONTROLLER 🔥
        Interactive Sandbox Resource Testing Tool
═══════════════════════════════════════════════════════════════════

📋 MAIN MENU:
───────────────────────────────────────────────────────────────────
1. Configure Memory Stress Test
2. Configure Thread Stress Test
3. Configure Process Stress Test
4. Configure CPU Stress Test
5. Configure Combined Stress Test
6. Quick Presets
───────────────────────────────────────────────────────────────────
7. Show Current Configuration
8. Run Stress Test
9. Reset Configuration
0. Exit
```

## Usage Examples

### Example 1: Test Memory Limits

**Goal**: Verify sandbox limits memory to 1 GB

1. In sandbox GUI: Set "Memory Limit" to `1024` MB
2. In stress_master:
   - Choose option `1` (Configure Memory Stress Test)
   - Enable: `Y`
   - Enter memory: `2048` MB (more than limit!)
   - Choose option `8` (Run Stress Test)
   - Confirm: `Y`

**Expected Result**: Program allocates ~1 GB, then gets OOM killed or limited

---

### Example 2: Test Thread Limits

**Goal**: Verify sandbox limits threads to 50

1. In sandbox GUI: Set "Max Threads" to `50`
2. In stress_master:
   - Choose option `2` (Configure Thread Stress Test)
   - Enable: `Y`
   - Enter threads: `100` (more than limit!)
   - Choose option `8` (Run Stress Test)
   - Confirm: `Y`

**Expected Result**: Can only create ~50 threads, rest fail

---

### Example 3: Test CPU Limits

**Goal**: Verify sandbox limits CPU to 25%

1. In sandbox GUI: Set "CPU Limit" to `25` %
2. In stress_master:
   - Choose option `4` (Configure CPU Stress Test)
   - Enable: `Y`
   - Enter intensity: `10` (maximum)
   - Choose option `8` (Run Stress Test)
   - Confirm: `Y`

**Expected Result**: CPU usage in monitor shows ~25%, not 100%

---

### Example 4: Combined Stress Test

**Goal**: Test all limits simultaneously

1. In sandbox GUI: 
   - CPU Limit: `50%`
   - Memory Limit: `512 MB`
   - PIDs Limit: `20`
   - Max Threads: `30`

2. In stress_master:
   - Choose option `5` (Configure Combined Stress Test)
   - Memory: `1024` MB
   - Threads: `50`
   - Processes: `10`
   - CPU Intensity: `10`
   - Choose option `8` (Run Stress Test)
   - Confirm: `Y`

**Expected Result**: All resources limited by cgroups

---

### Example 5: Quick Preset Testing

For rapid testing, use quick presets:

1. Choose option `6` (Quick Presets)
2. Select preset:
   - `1` - Light (good for initial testing)
   - `2` - Moderate (standard test)
   - `3` - Heavy (stress test)
   - `4` - Extreme (maximum stress)
3. Choose option `8` (Run Stress Test)
4. Confirm: `Y`

---

## Understanding the Output

### During Execution

The stress test shows:

```
[Phase 1] Starting memory allocation...
  [Memory] Allocating 2048 MB...
  [Memory] Allocated 512 / 2048 MB
  ⚠️ Failed after allocating 512 MB    ← Cgroup limit!

[Phase 2] Creating 100 threads...
  Created 20/100 threads...
  ✅ Created 50 threads                ← Thread limit reached

[Phase 3] Forking 10 processes...
  Fork failed: Resource temporarily unavailable  ← PID limit!
  ✅ Forked 8 processes

[Phase 4] Running stress test...
───────────────────────────────────────────────────────────────────
📊 Resource Usage:
───────────────────────────────────────────────────────────────────
VmRSS:    524288 kB     ← Memory usage
VmSize:   1048576 kB
Threads:  50             ← Thread count
Active stress threads: 50
───────────────────────────────────────────────────────────────────
```

### In Sandbox GUI

Check the **Monitoring tab** for:
- CPU usage (should match your limit)
- Memory usage (RSS)
- Thread count
- File descriptors

---

## Testing Strategy

### 1. Test Individual Limits

Test each resource limit separately:

```
Test #1: Memory only (disable others)
Test #2: Threads only
Test #3: Processes only  
Test #4: CPU only
```

### 2. Test Over-the-Limit Requests

Always try to exceed limits:
- If limit is 1 GB, request 2 GB
- If limit is 50 threads, request 100
- This verifies limits actually work

### 3. Test Combined Scenarios

Real malware uses multiple resources:
- High memory + many threads
- Many processes + high CPU
- Everything at once

### 4. Test Duration

Use different durations:
- 15 seconds - Quick check
- 30 seconds - Standard test
- 60 seconds - Extended test

---

## Troubleshooting

### Program Exits Immediately

**Cause**: Resource limits too strict, program can't even start

**Solution**: Increase limits slightly (e.g., memory limit to 256 MB minimum)

---

### "Cannot create thread" Errors

**Cause**: Thread limit reached (good! Limit is working)

**Check**: 
- Thread count in monitoring tab
- Should match your "Max Threads" setting

---

### "Out of Memory" / Killed

**Cause**: Memory limit reached (expected behavior)

**Check**:
- Memory usage before crash
- Should match your "Memory Limit"

---

### Fork() Fails

**Cause**: PID limit reached

**Check**:
- "PIDs Limit" setting in cgroups
- Number of processes created before failure

---

### CPU Not Limited

**Cause**: 
1. CPU cgroup controller not available
2. Cgroup v1 vs v2 issues

**Solution**:
- Check `/sys/fs/cgroup/cpu` exists
- Run: `cat /proc/cgroups` to verify controllers

---

## Advanced Usage

### Custom Test Scenario

1. Configure each test individually
2. Fine-tune parameters
3. Save configuration (mentally note it)
4. Run test
5. Compare actual vs expected behavior

### Automated Testing

Create a shell script:

```bash
#!/bin/bash
# Test memory limits

for limit in 256 512 1024 2048; do
    echo "Testing ${limit}MB limit..."
    # Set cgroup limit in GUI
    # Run stress_master with $limit + 512 MB
    # Record results
done
```

---

## Safety Notes

⚠️ **Always run in sandbox!** These tests can:
- Consume all system memory
- Max out CPU cores
- Create hundreds of processes/threads
- Make your system unresponsive

✅ **Safe in sandbox** because:
- Cgroups limit resource usage
- Namespaces isolate from host
- Easy to kill with "Stop Process" button

---

## Verifying Sandbox Effectiveness

### Good Signs (Sandbox Working):

✅ Memory allocation stops at limit
✅ Thread creation fails after limit
✅ Process forking fails after limit
✅ CPU usage stays at configured percentage
✅ System remains responsive

### Bad Signs (Sandbox Not Working):

❌ Unlimited memory allocation
❌ Can create unlimited threads
❌ CPU goes to 100% despite limit
❌ Host system becomes slow

---

## Quick Reference

| Test Type | Menu Option | Typical Limit | Test Value |
|-----------|-------------|---------------|------------|
| Memory    | 1           | 512 MB        | 1024 MB    |
| Threads   | 2           | 50            | 100        |
| Processes | 3           | 10            | 20         |
| CPU       | 4           | 50%           | Intensity 10 |

---

## Exit Codes

- `0` - Normal exit
- `Killed` - OOM killer (memory limit exceeded)
- `Segmentation fault` - Bug or memory corruption

---

## Further Information

- See `README.md` for sandbox configuration
- See `TESTING_FIREWALL.md` for network testing
- See sample program source code for implementation details

---

**Happy Testing!** 🔥

