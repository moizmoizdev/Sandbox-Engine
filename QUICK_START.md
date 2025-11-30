# Quick Start Guide - Sandbox Engine

## 🚀 One-Command Testing

```bash
chmod +x test_firewall.sh && ./test_firewall.sh
```

This single command will:
- ✅ Build everything
- ✅ Set up capabilities
- ✅ Run comprehensive firewall tests
- ✅ Validate all security features

---

## 📋 Basic Usage

### 1. Build and Setup

```bash
# Build the sandbox
make

# Set up Linux capabilities
./setup_capabilities.sh

# Build test programs
cd sample_programs && make && cd ..
```

### 2. Run the Sandbox

```bash
# Without sudo (if capabilities are set)
./main

# With sudo (if capabilities not working)
sudo ./main
```

### 3. Test the Firewall

```bash
# Automated testing
./test_firewall.sh

# Manual GUI testing
./main
→ Select firewall policy
→ Choose test program
→ Click Run
```

---

## 🛡️ Firewall Modes Quick Reference

| Mode | When to Use | Enforcement | Network NS Required |
|------|------------|-------------|---------------------|
| **NO_NETWORK** | Maximum security | ✅ Kernel (seccomp) | No |
| **STRICT** | Maximum security | ✅ Kernel (seccomp) | No |
| **MODERATE** | Controlled access | ⚠️ Network Namespace | Yes |
| **CUSTOM** | Custom policies | ⚠️ Network Namespace | Yes |

### Quick Decision Tree

```
Need complete network isolation?
└─ YES → Use NO_NETWORK or STRICT
└─ NO  → Need selective access?
         └─ YES → Use MODERATE/CUSTOM + Enable Network Namespace
         └─ NO  → Use DISABLED (trusted apps only)
```

---

## 🧪 Quick Tests

### Test 1: Complete Network Blocking (5 seconds)

```bash
./main
# Select: NO_NETWORK
# Run: sample_programs/network_test
# Expected: "Operation not permitted"
```

### Test 2: Network Namespace Isolation (5 seconds)

```bash
./main
# Enable: Network Namespace checkbox
# Select: MODERATE
# Run: sample_programs/network_connect
# Expected: Network isolated
```

### Test 3: Memory Protection (5 seconds)

```bash
./main
# Enable: Memory Protection
# Run: sample_programs/mmap_exec_test
# Expected: "Permission denied" or allocation failure
```

---

## 📁 Important Files

### Documentation
- `README.md` - Overview and features
- `COMPLETE_ARCHITECTURE_GUIDE.md` - Detailed architecture (1400+ lines)
- `FIREWALL_TESTING_GUIDE.md` - Testing instructions
- `FIREWALL_IMPROVEMENTS.md` - Implementation changelog

### Scripts
- `test_firewall.sh` - Comprehensive automated tests
- `setup_capabilities.sh` - Set up Linux capabilities
- `Makefile` - Build configuration

### Source Code
- `src/firewall.c` - Firewall implementation
- `src/memory_protection.c` - Memory protection
- `src/process_control.c` - Process management
- `src/namespaces.c` - Namespace isolation

### Test Programs
- `sample_programs/network_test` - Basic network test
- `sample_programs/network_connect` - Connection test
- `sample_programs/mmap_exec_test` - Memory protection test
- `sample_programs/stack_test` - Stack protection test

---

## ⚡ Common Commands

### Build Commands
```bash
make                    # Build sandbox
make clean              # Clean build files
make -C sample_programs # Build test programs only
```

### Testing Commands
```bash
./test_firewall.sh           # Full automated test
./main                       # Run GUI
sudo ./main                  # Run with sudo
getcap ./main                # Check capabilities
```

### Capability Commands
```bash
./setup_capabilities.sh                           # Setup script
sudo setcap cap_sys_admin,cap_net_admin+ep ./main # Manual setup
getcap ./main                                      # Verify
```

---

## 🔍 Troubleshooting

### Build Fails
```bash
sudo apt-get install build-essential pkg-config libgtk-4-dev libwebkitgtk-6.0-dev
make clean && make
```

### "Operation not permitted" Errors
```bash
# Option 1: Set capabilities
./setup_capabilities.sh

# Option 2: Run with sudo
sudo ./main
```

### Firewall Not Blocking
- Check firewall mode is NO_NETWORK or STRICT (not DISABLED)
- For MODERATE/CUSTOM: Enable Network Namespace
- Verify kernel has seccomp support: `zgrep CONFIG_SECCOMP /proc/config.gz`

### Network Namespace Fails
```bash
# Run with sudo or set capabilities
sudo setcap cap_sys_admin,cap_net_admin+ep ./main
```

---

## 📖 Learning Path

### Beginner (15 minutes)
1. Read: `README.md` - Overview section
2. Build: `make`
3. Run: `./main`
4. Test: Select NO_NETWORK, run network_test

### Intermediate (1 hour)
1. Read: `FIREWALL_TESTING_GUIDE.md`
2. Run: `./test_firewall.sh`
3. Try: All firewall modes
4. Understand: Enforcement differences

### Advanced (3 hours)
1. Read: `COMPLETE_ARCHITECTURE_GUIDE.md`
2. Study: Seccomp-BPF implementation in `src/firewall.c`
3. Explore: Memory protection in `src/memory_protection.c`
4. Experiment: Custom policies and configurations

---

## 🎯 Key Concepts

### Security Layers (Defense in Depth)
```
Layer 7: Monitoring & Tracking
Layer 6: GUI Controls
Layer 5: File Access Control (Landlock)
Layer 4: Resource Limits (Cgroups)
Layer 3: Memory Protection (W^X, Stack limits)
Layer 2: Firewall (Seccomp-BPF or Network Namespace)
Layer 1: Process Isolation (Namespaces)
```

### Enforcement Methods
- **Seccomp-BPF**: Kernel-level syscall filtering (NO_NETWORK, STRICT, Memory Protection)
- **Network Namespace**: Interface-level isolation (MODERATE, CUSTOM)
- **Cgroups**: Resource usage limits
- **Landlock**: Path-based file access control

---

## 💡 Best Practices

### For Maximum Security
1. ✅ Use NO_NETWORK or STRICT firewall mode
2. ✅ Enable all namespaces (PID, Mount, Network, UTS)
3. ✅ Enable memory protection (W^X, stack limits)
4. ✅ Set resource limits (CPU, memory, PIDs)
5. ✅ Enable Landlock file access control

### For Controlled Access
1. ✅ Use MODERATE firewall mode
2. ✅ Enable Network Namespace (required!)
3. ✅ Enable other namespaces
4. ✅ Configure resource limits
5. ✅ Monitor process behavior

### For Testing
1. ✅ Run `./test_firewall.sh` first
2. ✅ Start with DISABLED mode to verify program works
3. ✅ Gradually enable restrictions
4. ✅ Check logs for issues
5. ✅ Test with sample programs before real applications

---

## 🔗 External Resources

### Linux Documentation
- `man 7 namespaces` - Namespace documentation
- `man 7 cgroups` - Cgroups documentation
- `man 2 seccomp` - Seccomp documentation
- `man 2 prctl` - Process control

### Online Resources
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

---

## 📞 Help & Support

### Need Help?
1. Check `FIREWALL_TESTING_GUIDE.md` for detailed testing
2. Read `COMPLETE_ARCHITECTURE_GUIDE.md` for implementation details
3. Review `FIREWALL_IMPROVEMENTS.md` for recent changes
4. Run `./test_firewall.sh` to validate setup

### Common Questions

**Q: Which firewall mode should I use?**
A: For untrusted code → NO_NETWORK or STRICT. For controlled access → MODERATE + Network Namespace.

**Q: Do I need sudo?**
A: No if capabilities are set (`./setup_capabilities.sh`). Otherwise, yes for namespaces.

**Q: Why isn't MODERATE blocking network?**
A: MODERATE requires Network Namespace to be enabled for enforcement.

**Q: How do I verify firewall is working?**
A: Run `./test_firewall.sh` or manually test with sample_programs/network_test.

---

## ✅ Success Checklist

Before considering your sandbox configured:

- [ ] Project builds without errors (`make`)
- [ ] Capabilities set (`./setup_capabilities.sh`)
- [ ] Test programs compiled (`cd sample_programs && make`)
- [ ] GUI launches (`./main`)
- [ ] NO_NETWORK mode blocks network (test with network_test)
- [ ] STRICT mode blocks network
- [ ] MODERATE mode warns about Network Namespace
- [ ] Memory protection works (test with mmap_exec_test)
- [ ] Documentation reviewed

Run `./test_firewall.sh` to automatically verify most of these!

---

**Quick Start Version**: 1.0  
**Last Updated**: November 30, 2025  
**Status**: Production Ready  

🎉 **You're all set! Start with `./test_firewall.sh` and explore from there!**
