# Linux Namespaces Explained
## A Comprehensive Guide for the Sandboxing Engine

## Table of Contents
1. [What are Namespaces?](#what-are-namespaces)
2. [Why Use Namespaces?](#why-use-namespaces)
3. [Types of Namespaces](#types-of-namespaces)
4. [How Namespaces Work](#how-namespaces-work)
5. [Our Implementation](#our-implementation)
6. [Real-World Examples](#real-world-examples)
7. [Security Benefits](#security-benefits)

---

## What are Namespaces?

**Namespaces** are a Linux kernel feature that provides **process isolation** by creating separate "views" of system resources. Think of them as **virtual walls** that separate processes from each other and from the host system.

### Simple Analogy

Imagine a **hotel building** (your Linux system):
- **Without namespaces**: All guests (processes) share the same room numbers, see the same building directory, use the same phone system, and can access each other's rooms.
- **With namespaces**: Each guest gets their own **isolated floor** with:
  - Their own room numbering system (PID namespace)
  - Their own building directory (mount namespace)
  - Their own phone system (network namespace)
  - Their own building name (UTS namespace)

Each namespace creates a **separate environment** where processes think they're running on their own system, but they're actually sharing the same physical hardware.

---

## Why Use Namespaces?

### 1. **Security**
- **Isolation**: A compromised process can't access other processes or the host system
- **Containment**: Malware or malicious code is trapped within its namespace
- **Attack Surface Reduction**: Even if a process is compromised, it can't affect the host

### 2. **Resource Management**
- **Process Isolation**: Processes can't see or interfere with each other
- **Network Isolation**: Processes can't access the host network
- **File System Isolation**: Processes can't modify host filesystem

### 3. **Testing & Development**
- **Safe Testing**: Run untrusted code without risking your system
- **Reproducible Environments**: Same environment every time
- **Clean Slate**: Each namespace starts fresh

### 4. **Multi-tenancy**
- **Shared Hosting**: Multiple users on one server, isolated from each other
- **Cloud Computing**: Containers (Docker) use namespaces extensively

---

## Types of Namespaces

Linux provides **8 types of namespaces**. We implemented **4 of them**:

### 1. PID Namespace (Process ID Namespace)
**What it does**: Creates a separate process ID space

**Example**:
```
Host System:          Sandboxed Process sees:
PID 1000 (host)  →    PID 1 (thinks it's init!)
PID 1001 (sandbox) →  PID 2
PID 1002 (sandbox) →  PID 3
```

**Benefits**:
- Sandboxed process thinks it's PID 1 (init process)
- Can't see or kill processes outside its namespace
- Process tree is isolated
- When sandboxed process dies, all its children die too

**Real-world use**: Docker containers, systemd services

---

### 2. Mount Namespace (Filesystem Namespace)
**What it does**: Creates a separate filesystem mount point view

**Example**:
```
Host System:              Sandboxed Process sees:
/ (root filesystem)  →    / (isolated view)
/home/user/data      →    (not visible)
/tmp                 →    /tmp (separate, isolated)
```

**Benefits**:
- Sandboxed process can't see host filesystem
- Can mount its own filesystems without affecting host
- File system changes are isolated
- Can create a "chroot jail" effect

**Real-world use**: Filesystem isolation, container root filesystems

---

### 3. Network Namespace (Network Namespace)
**What it does**: Creates a separate network stack

**Example**:
```
Host System:              Sandboxed Process sees:
eth0 (host network)  →   (not visible)
lo (loopback)        →   lo (separate loopback)
                      →   (no network access by default)
```

**Benefits**:
- Sandboxed process has NO network access by default
- Can't connect to internet or local network
- Can't sniff network traffic
- Can create its own virtual network interfaces
- Complete network isolation

**Real-world use**: Network isolation, VPNs, network testing

---

### 4. UTS Namespace (Unix Timesharing System Namespace)
**What it does**: Isolates hostname and domain name

**Example**:
```
Host System:              Sandboxed Process sees:
hostname: "mycomputer" →  hostname: "sandbox"
domain: "local"       →  domain: "sandbox"
```

**Benefits**:
- Process can't identify the host system
- Can set custom hostname for the sandbox
- Prevents hostname-based attacks
- Makes sandboxed process think it's on a different machine

**Real-world use**: Container hostnames, system identification

---

### Other Namespaces (Not Implemented Yet)

5. **IPC Namespace**: Isolates inter-process communication (shared memory, semaphores)
6. **User Namespace**: Maps user/group IDs (allows root in namespace without host root)
7. **Cgroup Namespace**: Isolates cgroup views
8. **Time Namespace**: Isolates system time (for time manipulation)

---

## How Namespaces Work

### The `unshare()` System Call

```c
unshare(CLONE_NEWPID);  // Create new PID namespace
unshare(CLONE_NEWNS);   // Create new mount namespace
unshare(CLONE_NEWNET);  // Create new network namespace
unshare(CLONE_NEWUTS);  // Create new UTS namespace
```

**What happens**:
1. Process calls `unshare()` with namespace flags
2. Kernel creates a new namespace
3. Current process moves into the new namespace
4. Process now sees isolated view of that resource

### PID Namespace Special Case

**Important**: PID namespace requires a **double-fork** pattern:

```c
// Step 1: Create PID namespace
unshare(CLONE_NEWPID);

// Step 2: Fork - first process becomes PID 1 (init)
pid_t pid = fork();

if (pid > 0) {
    // Parent: This is PID 1 in namespace, must wait for children
    waitpid(pid, NULL, 0);
    exit(0);
}

// Step 3: Child process is the actual sandboxed process
// This process can now run your program
```

**Why?** The first process in a PID namespace becomes PID 1 (like init). It must wait for all children. So we fork again to get the actual process we want to run.

---

## Our Implementation

### File Structure

```
src/
├── namespaces.h    # Function declarations
├── namespaces.c    # Implementation
└── process_control.c  # Uses namespaces when creating processes
```

### How We Use It

When you click "Run in Sandbox" in the GUI:

1. **Fork**: Create a new process
   ```c
   pid_t pid = fork();
   ```

2. **Setup Namespaces** (in child process):
   ```c
   setup_pid_namespace();      // Isolate process IDs
   setup_mount_namespace();     // Isolate filesystem
   setup_network_namespace();   // Isolate network
   setup_uts_namespace("sandbox"); // Set hostname
   ```

3. **Execute Program**: Run the selected program in isolated environment
   ```c
   execl(file_path, file_path, NULL);
   ```

### Code Flow

```
User clicks "Run"
    ↓
create_sandboxed_process()
    ↓
fork() - Create child process
    ↓
Child: setup_pid_namespace()
    ↓ (if successful)
fork() again - Double fork for PID namespace
    ↓
Inner child: setup_mount_namespace()
    ↓
setup_network_namespace()
    ↓
setup_uts_namespace()
    ↓
execl() - Execute target program
    ↓
Program runs in isolated namespace!
```

---

## Real-World Examples

### Example 1: Malware Analysis

**Without namespaces**:
```bash
$ ./suspicious_program
# Program can:
# - Access all your files
# - Connect to internet
# - See all running processes
# - Modify system files
# - Spread to other processes
```

**With namespaces**:
```bash
$ ./main  # (our sandbox)
# Select suspicious_program
# Program can ONLY:
# - See its own process
# - Access its own files (if we allow)
# - NO network access
# - NO access to host files
# - Trapped in its namespace
```

### Example 2: Testing Untrusted Code

**Scenario**: You downloaded a program from the internet and want to test it.

**Without sandbox**:
- Risk: Program might delete files, install malware, steal data
- Solution: Don't run it (not practical)

**With our sandbox**:
- Risk: None! Program is isolated
- Solution: Run it safely, observe behavior, terminate if needed

### Example 3: Resource Isolation

**Scenario**: Running a CPU-intensive program

**Without namespaces**:
- Program can see all processes
- Might try to kill competing processes
- Can access shared resources

**With namespaces**:
- Program only sees itself
- Can't interfere with other processes
- Isolated resource view

---

## Security Benefits

### 1. **Process Isolation**
```
Host Process Tree:          Sandboxed Process Sees:
├─ init (PID 1)            ├─ init (PID 1) - actually our wrapper
├─ systemd (PID 2)         └─ (nothing else!)
├─ browser (PID 100)
└─ sandboxed (PID 1000)    Sandboxed process thinks it's alone!
```

**Attack Prevention**:
- Can't enumerate running processes
- Can't kill other processes
- Can't access process memory

### 2. **Network Isolation**
```
Host Network:              Sandboxed Network:
├─ eth0 (internet)         └─ lo (loopback only)
├─ wlan0 (WiFi)            └─ (no internet access!)
└─ lo (loopback)           └─ (completely isolated)
```

**Attack Prevention**:
- Can't connect to internet
- Can't send data to external servers
- Can't receive commands from attackers
- Can't participate in DDoS attacks

### 3. **Filesystem Isolation**
```
Host Filesystem:           Sandboxed Filesystem:
├─ /home/user/            └─ (not visible)
├─ /etc/passwd            └─ (not accessible)
├─ /tmp                    └─ /tmp (isolated)
└─ /var/log                └─ (not visible)
```

**Attack Prevention**:
- Can't read sensitive files
- Can't modify system files
- Can't access user data
- File operations are contained

### 4. **Hostname Isolation**
```
Host System:               Sandboxed Process:
hostname: "mycomputer"    hostname: "sandbox"
```

**Attack Prevention**:
- Can't identify host system
- Can't use hostname for attacks
- Appears as different machine

---

## Limitations & Requirements

### 1. **Root Privileges Required**

Most namespaces require **root** or **capabilities**:
- `CAP_SYS_ADMIN`: For PID, mount, UTS namespaces
- `CAP_NET_ADMIN`: For network namespace

**Solutions**:
- Run with `sudo` (for testing)
- Set capabilities: `sudo setcap cap_sys_admin,cap_net_admin+ep ./main`
- Use User Namespace (allows unprivileged namespaces) - *future enhancement*

### 2. **Not Complete Isolation**

Namespaces provide **isolation**, not complete security:
- Still shares kernel with host
- Kernel vulnerabilities affect both
- Need additional layers (seccomp, cgroups) for full security

### 3. **Performance Overhead**

- Small overhead for namespace creation
- Minimal runtime overhead
- Worth it for security benefits

---

## How to Test Namespaces

### Test 1: Check Process Isolation

```bash
# Terminal 1: Run sandbox
./main
# Select and run: sample_programs/hello

# Terminal 2: Check processes
ps aux | grep hello
# You'll see the process, but from sandbox's view it's PID 1 or 2
```

### Test 2: Check Network Isolation

```bash
# Run a program that tries to connect to internet
./main
# Select: sample_programs/file_operations
# Program can't access network!
```

### Test 3: Check Filesystem Isolation

```bash
# Run a program that tries to access /etc/passwd
./main
# Program can't see host filesystem
```

---

## Summary

**Namespaces = Virtual Walls**

- **PID Namespace**: Isolates process IDs
- **Mount Namespace**: Isolates filesystem
- **Network Namespace**: Isolates network (no internet!)
- **UTS Namespace**: Isolates hostname

**Benefits**:
- ✅ Security: Malware can't escape
- ✅ Isolation: Processes can't see each other
- ✅ Containment: Attacks are trapped
- ✅ Testing: Safe to run untrusted code

**In Our Project**:
- Namespaces are automatically applied when you run a program
- Creates isolated environment for each sandboxed process
- Works with other security features (cgroups, seccomp) for complete sandbox

**Next Steps**:
- Add cgroups for resource limits (CPU, memory)
- Add seccomp for syscall filtering
- Add monitoring to see what's happening inside namespaces

---

## References

- Linux `man 7 namespaces`
- Linux `man 2 unshare`
- Linux `man 2 clone`
- Docker uses namespaces extensively
- systemd uses namespaces for service isolation

