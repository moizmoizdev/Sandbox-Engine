# Sandboxing Engine - Project Roadmap
## Final Year Project - 1 Month Timeline

## Current Status ✅
- [x] Basic GTK 4 GUI framework
- [x] File selection dialog
- [x] Subprocess creation and control
- [x] Sample test programs (basic + intensive)
- [x] Project structure and build system

---

## Phase 1: Core Sandboxing Features (Week 1) 🔒
**Priority: CRITICAL** | **Timeline: Days 1-7**

### 1.1 Linux Namespaces (Days 1-3)
- [x] Implement PID namespace isolation
- [x] Implement mount namespace isolation
- [x] Implement network namespace isolation
- [x] Implement UTS namespace isolation
- [ ] Test namespace isolation with sample programs

**Files to create/modify:**
- `src/namespaces.c` / `src/namespaces.h`
- Update `src/process_control.c` to use namespaces

**Key functions:**
- `setup_pid_namespace()`
- `setup_mount_namespace()`
- `setup_network_namespace()`
- `setup_uts_namespace()`

### 1.2 Cgroups Integration (Days 3-5)
- [ ] Implement CPU cgroup limits
- [ ] Implement memory cgroup limits
- [ ] Implement process count limits
- [ ] Create cgroup hierarchy management
- [ ] Test resource limits with intensive programs

**Files to create/modify:**
- `src/cgroups.c` / `src/cgroups.h`
- Update `src/process_control.c` to apply cgroups

**Key functions:**
- `setup_cgroup()`
- `set_cpu_limit()`
- `set_memory_limit()`
- `set_pids_limit()`
- `cleanup_cgroup()`

### 1.3 Seccomp Filtering (Days 5-7)
- [ ] Implement basic seccomp filter
- [ ] Create syscall whitelist/blacklist
- [ ] Add syscall filtering policies
- [ ] Test syscall restrictions

**Files to create/modify:**
- `src/seccomp.c` / `src/seccomp.h`
- `src/policies/` directory for policy files

**Key functions:**
- `setup_seccomp_filter()`
- `load_seccomp_policy()`
- `install_syscall_filter()`

---

## Phase 2: Process Monitoring & Metrics (Week 2) 📊
**Priority: HIGH** | **Timeline: Days 8-14**

### 2.1 Process Monitoring Backend (Days 8-10)
- [ ] Implement process statistics collection
- [ ] CPU usage monitoring (via /proc)
- [ ] Memory usage monitoring (RSS, VMS)
- [ ] File descriptor tracking
- [ ] Network activity monitoring
- [ ] Syscall counting/interception

**Files to create/modify:**
- `src/monitor.c` / `src/monitor.h`
- `src/metrics.c` / `src/metrics.h`

**Key functions:**
- `collect_process_stats()`
- `get_cpu_usage()`
- `get_memory_usage()`
- `get_fd_count()`
- `get_network_stats()`

### 2.2 IPC Communication (Days 10-12)
- [ ] Design IPC protocol (shared memory, pipes, or sockets)
- [ ] Implement backend-to-frontend communication
- [ ] Implement real-time data streaming
- [ ] Add event logging system

**Files to create/modify:**
- `src/ipc.c` / `src/ipc.h`
- `src/events.c` / `src/events.h`

**Key functions:**
- `init_ipc_channel()`
- `send_metrics()`
- `send_event()`
- `receive_control_command()`

### 2.3 Basic Monitoring UI (Days 12-14)
- [ ] Display process status in GUI
- [ ] Show CPU usage (text/bar)
- [ ] Show memory usage (text/bar)
- [ ] Display process PID and status
- [ ] Add event log viewer

**Files to modify:**
- `src/main.c` - Add monitoring widgets
- Create monitoring UI components

---

## Phase 3: Advanced Monitoring & Visualization (Week 3) 📈
**Priority: MEDIUM** | **Timeline: Days 15-21**

### 3.1 Real-time Charts (Days 15-17)
- [ ] Integrate WebKitGTK for chart rendering
- [ ] Implement CPU usage chart (line graph)
- [ ] Implement memory usage chart (line graph)
- [ ] Add time-series data collection
- [ ] Update charts in real-time

**Files to create/modify:**
- `src/charts.c` / `src/charts.h`
- `data/chart.html` - HTML/JavaScript for charts
- Update `src/main.c` to embed WebKit view

**Technologies:**
- WebKitGTK for HTML rendering
- Chart.js or similar for visualization
- JavaScript bridge for data updates

### 3.2 Advanced Metrics (Days 17-19)
- [ ] Syscall statistics and visualization
- [ ] File I/O statistics
- [ ] Network I/O statistics
- [ ] Process tree visualization
- [ ] Resource limit indicators

**Files to modify:**
- `src/metrics.c` - Add advanced metrics
- `src/charts.c` - Add new chart types

### 3.3 Policy Management UI (Days 19-21)
- [ ] Add policy file selector
- [ ] Policy editor/viewer
- [ ] Policy validation
- [ ] Save/load policy configurations

**Files to modify:**
- `src/main.c` - Add policy UI
- `src/policies/` - Policy file format

---

## Phase 4: Polish & Documentation (Week 4) ✨
**Priority: HIGH** | **Timeline: Days 22-28**

### 4.1 Error Handling & Robustness (Days 22-23)
- [ ] Add comprehensive error handling
- [ ] Improve error messages
- [ ] Add logging system
- [ ] Handle edge cases
- [ ] Test with various failure scenarios

### 4.2 UI/UX Improvements (Days 23-25)
- [ ] Improve GUI layout and styling
- [ ] Add tooltips and help text
- [ ] Improve status indicators
- [ ] Add keyboard shortcuts
- [ ] Make UI responsive

### 4.3 Testing & Validation (Days 25-26)
- [ ] Test all sandboxing features
- [ ] Test with all sample programs
- [ ] Performance testing
- [ ] Security validation
- [ ] Bug fixes

### 4.4 Documentation (Days 26-28)
- [ ] Complete README.md
- [ ] Write user manual
- [ ] Document API/functions
- [ ] Create architecture diagram
- [ ] Write project report sections:
  - Introduction
  - Literature Review
  - System Design
  - Implementation Details
  - Testing & Results
  - Conclusion & Future Work

---

## Phase 5: Final Polish & Submission (Days 29-30) 🎯
**Priority: CRITICAL**

- [ ] Final testing and bug fixes
- [ ] Code cleanup and comments
- [ ] Finalize documentation
- [ ] Prepare demo/presentation
- [ ] Create installation guide
- [ ] Package project for submission

---

## Technical Implementation Details

### Key Linux APIs to Use:
- **Namespaces**: `clone()`, `unshare()`, `setns()`
- **Cgroups**: `/sys/fs/cgroup/` filesystem operations
- **Seccomp**: `seccomp()` syscall, `libseccomp` library
- **Capabilities**: `cap_set_proc()`, `prctl()`
- **Monitoring**: `/proc/[pid]/` filesystem

### Dependencies:
- GTK 4 (already installed)
- WebKitGTK 6.0 (already installed)
- libseccomp-dev (for seccomp)
- Standard C library

### Architecture:
```
┌─────────────────┐
│   GTK 4 GUI     │  ← Frontend (main.c)
│  (Monitoring)  │
└────────┬────────┘
         │ IPC
┌────────▼────────┐
│  Sandbox Engine │  ← Backend
│  - Namespaces   │
│  - Cgroups      │
│  - Seccomp      │
│  - Monitoring   │
└────────┬────────┘
         │
┌────────▼────────┐
│ Sandboxed       │
│ Process         │
└─────────────────┘
```

---

## Daily Checklist Template

### Morning (2-3 hours):
- [ ] Review yesterday's progress
- [ ] Plan today's tasks
- [ ] Start implementation

### Afternoon (3-4 hours):
- [ ] Continue implementation
- [ ] Test features
- [ ] Fix bugs

### Evening (1-2 hours):
- [ ] Document progress
- [ ] Commit code
- [ ] Plan next day

---

## Risk Mitigation

### Potential Challenges:
1. **Complexity of Linux APIs** → Start with simple implementations, iterate
2. **Time constraints** → Focus on core features first, polish later
3. **Testing difficulties** → Use sample programs extensively
4. **Documentation time** → Document as you code, not at the end

### Contingency Plan:
- If behind schedule, prioritize:
  1. Core sandboxing (Phase 1) - MUST HAVE
  2. Basic monitoring (Phase 2) - SHOULD HAVE
  3. Advanced features (Phase 3) - NICE TO HAVE
  4. Polish (Phase 4) - Can be minimal

---

## Success Criteria

### Minimum Viable Product (MVP):
- ✅ Basic GUI
- ✅ File selection
- ✅ Process execution
- [ ] Namespace isolation
- [ ] Cgroup limits
- [ ] Basic monitoring (CPU/Memory)
- [ ] Process termination

### Full Product:
- [ ] All MVP features
- [ ] Seccomp filtering
- [ ] Real-time charts
- [ ] Advanced metrics
- [ ] Policy management
- [ ] Complete documentation

---

## Resources & References

### Linux Documentation:
- `man 2 clone`
- `man 7 namespaces`
- `man 7 cgroups`
- `man 2 seccomp`
- `/proc/[pid]/` documentation

### GTK 4 Documentation:
- https://docs.gtk.org/gtk4/
- WebKitGTK documentation

### Sample Projects:
- Docker (for namespace/cgroup reference)
- Firejail (for seccomp reference)
- strace (for syscall monitoring)

---

**Last Updated:** [Current Date]
**Project Status:** Phase 0 Complete, Starting Phase 1

