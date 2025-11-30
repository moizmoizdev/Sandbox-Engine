# Complete Sandbox Engine Architecture Guide

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Process Isolation (Namespaces)](#process-isolation-namespaces)
5. [Firewall System (DETAILED)](#firewall-system-detailed)
6. [Memory Protection (DETAILED)](#memory-protection-detailed)
7. [Resource Control (Cgroups)](#resource-control-cgroups)
8. [File Access Control (Landlock)](#file-access-control-landlock)
9. [Process Lifecycle](#process-lifecycle)
10. [GUI Interface](#gui-interface)
11. [Monitoring & Tracking](#monitoring--tracking)
12. [Security Layers](#security-layers)

---

## Overview

The Sandbox Engine is a **Linux-based process isolation system** that creates secure environments for running untrusted applications. It uses multiple layers of Linux kernel features to provide comprehensive security.

### What is Sandboxing?

Sandboxing is the practice of running code in a restricted environment that:
- **Isolates** the process from the rest of the system
- **Limits** what resources it can access
- **Monitors** its behavior in real-time
- **Prevents** malicious activities

### Key Technologies Used
- **Linux Namespaces** - Process isolation
- **Seccomp-BPF** - System call filtering
- **Cgroups** - Resource limits
- **Landlock** - File system access control
- **GTK 4** - Graphical user interface
- **Ptrace** - System call monitoring

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        GTK 4 GUI (main.c)                       │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────────┐  │
│  │  File    │Namespaces│ Resource │ Firewall │   Memory     │  │
│  │Selection │  Config  │  Limits  │  Config  │  Protection  │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Process Control Engine (process_control.c)         │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  Namespace   │  │   Firewall   │  │   Memory     │         │
│  │   Setup      │  │    Apply     │  │  Protection  │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   Cgroups    │  │   Landlock   │  │   Execve     │         │
│  │   Setup      │  │    Apply     │  │   Program    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Sandboxed Process                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  - Isolated PID namespace (appears as PID 1)               │ │
│  │  - Isolated mount namespace (private file system view)     │ │
│  │  - Isolated network namespace (separate network stack)     │ │
│  │  - Isolated UTS namespace (custom hostname)                │ │
│  │  - Firewall active (seccomp filters network syscalls)      │ │
│  │  - Memory protection active (W^X, stack limits)            │ │
│  │  - Resource limits active (CPU, memory, PIDs)              │ │
│  │  - File access restricted (Landlock rules)                 │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Monitoring Systems                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   CPU/Mem    │  │   Syscall    │  │   Firewall   │         │
│  │  Monitoring  │  │   Tracking   │  │     Logs     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. **main.c** - GUI Application
- **Purpose**: User interface and orchestration
- **Responsibilities**:
  - Display configuration options
  - Capture user inputs (file selection, policies, limits)
  - Trigger sandbox creation
  - Display real-time monitoring data
  - Manage process lifecycle (start/stop)

### 2. **process_control.c** - Process Management
- **Purpose**: Create and manage sandboxed processes
- **Responsibilities**:
  - Fork child processes
  - Setup all security layers in correct order
  - Handle PID namespace double-fork pattern
  - Execute target program
  - Terminate processes with multiple methods

### 3. **namespaces.c** - Process Isolation
- **Purpose**: Create isolated environments
- **Functions**: Setup PID, Mount, Network, UTS namespaces

### 4. **firewall.c** - Network Security
- **Purpose**: Control network access
- **Functions**: Policy management, seccomp filtering, rule enforcement

### 5. **memory_protection.c** - Memory Security
- **Purpose**: Prevent memory exploits
- **Functions**: W^X enforcement, stack protection, seccomp filtering

### 6. **cgroups.c** - Resource Control
- **Purpose**: Limit system resource usage
- **Functions**: CPU, memory, PID limits

### 7. **landlock.c** - File Access Control
- **Purpose**: Restrict file system access
- **Functions**: Path-based access control

### 8. **syscall_tracker.c** - System Call Monitoring
- **Purpose**: Track process syscalls
- **Functions**: Ptrace-based tracking, statistics

### 9. **monitor.c** - Process Monitoring
- **Purpose**: Collect runtime statistics
- **Functions**: CPU, memory, thread tracking

---

## Process Isolation (Namespaces)

### What are Namespaces?

Namespaces are a Linux kernel feature that **partitions kernel resources** so that one set of processes sees one set of resources while another set sees a different set.

### Types of Namespaces Used

#### 1. **PID Namespace** (Process ID Isolation)
- **Purpose**: Isolate process ID number space
- **Implementation**: `unshare(CLONE_NEWPID)`
- **How it Works**:
  1. Creates a new PID namespace using `unshare()` syscall
  2. Requires double-fork pattern:
     - First fork: Creates outer child (still in parent PID namespace)
     - Second fork: Creates inner child (PID 1 in new namespace)
  3. Inner child sees itself as PID 1
  4. Cannot see or signal processes outside its namespace
  5. Parent namespace can still see and manage the child

**Code Flow**:
```c
// In process_control.c
if (ns_flags & NS_PID) {
    setup_pid_namespace();  // unshare(CLONE_NEWPID)
    pid_t inner_pid = fork(); // This becomes PID 1
    if (inner_pid == 0) {
        // Inner child - this is PID 1 in namespace
        // Setup other namespaces
        // Apply security layers
        // Execute program
    }
}
```

**Security Benefits**:
- Process cannot see or kill other system processes
- Cannot escape to parent namespace
- Acts as init process (PID 1) in its own world

#### 2. **Mount Namespace** (File System Isolation)
- **Purpose**: Isolate mount points
- **Implementation**: `unshare(CLONE_NEWNS)`
- **How it Works**:
  1. Creates copy of parent's mount table
  2. Makes mounts private (`MS_PRIVATE`)
  3. Changes to mounts don't affect parent
  4. Can create custom root file system

**Security Benefits**:
- Cannot mount/unmount system directories
- Private view of file system
- Cannot affect other processes' mounts

#### 3. **Network Namespace** (Network Stack Isolation)
- **Purpose**: Isolate network devices, IP addresses, ports, routing tables
- **Implementation**: `unshare(CLONE_NEWNET)`
- **How it Works**:
  1. Creates completely isolated network stack
  2. Starts with only loopback interface
  3. No access to host network interfaces
  4. Separate routing tables and firewall rules

**Security Benefits**:
- Complete network isolation by default
- Cannot sniff host network traffic
- Cannot bind to host ports
- Must explicitly configure networking

#### 4. **UTS Namespace** (Hostname Isolation)
- **Purpose**: Isolate hostname and domain name
- **Implementation**: `unshare(CLONE_NEWUTS)` + `sethostname()`
- **How it Works**:
  1. Creates copy of UTS information
  2. Sets custom hostname (default: "sandbox")
  3. Changes don't affect host system

**Security Benefits**:
- Process cannot change system hostname
- Provides clear indication of sandboxed environment

---

## Firewall System (DETAILED)

The firewall system is a **multi-layer network security mechanism** that controls network access for sandboxed processes.

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│            Application Layer (GUI)                  │
│  - Policy selection (Disabled/No Network/Strict...) │
│  - Custom rule creation                             │
│  - Policy file loading                              │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│         Firewall Engine (firewall.c)                │
│  ┌─────────────────────────────────────────────┐   │
│  │  Policy Management                          │   │
│  │  - firewall_init() - Initialize config      │   │
│  │  - firewall_load_policy() - Load rules      │   │
│  │  - firewall_add_rule() - Add custom rules   │   │
│  └─────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────┐   │
│  │  Rule Processing                            │   │
│  │  - firewall_apply() - Apply rules           │   │
│  │  - firewall_create_rule() - Rule creation   │   │
│  └─────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────┐   │
│  │  Seccomp Filter Generation                  │   │
│  │  - firewall_block_network_syscalls()        │   │
│  │  - BPF filter compilation                   │   │
│  └─────────────────────────────────────────────┘   │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│      Linux Kernel (Seccomp-BPF Filter)              │
│  - Intercepts syscalls before execution             │
│  - Evaluates against BPF program                    │
│  - ALLOW or DENY with EPERM error                   │
└─────────────────────────────────────────────────────┘
```

### Firewall Policies

#### 1. **DISABLED** - No Restrictions
- **Description**: Full network access, no filtering
- **Use Case**: Trusted applications only
- **Implementation**: No seccomp filters applied
- **Network Access**: 100% unrestricted

#### 2. **NO_NETWORK** - Complete Isolation
- **Description**: Blocks ALL network-related syscalls at kernel level
- **Use Case**: Maximum security for untrusted code
- **Implementation**: 
  - Uses **seccomp-BPF** (Berkeley Packet Filter)
  - Filters syscalls: `socket()`, `connect()`, `bind()`, `sendto()`, `recvfrom()`, `sendmsg()`, `recvmsg()`
  - Returns EPERM (Operation not permitted) for blocked syscalls

**How Seccomp Works for NO_NETWORK**:
```c
// Simplified seccomp filter structure
struct sock_filter filter[] = {
    // Load syscall number into accumulator
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    
    // Check if syscall is socket()
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
    // If yes, return EPERM (deny)
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    
    // Repeat for connect(), bind(), etc.
    // ...
    
    // Allow all other syscalls
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};

// Install filter
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
```

**Execution Flow**:
1. Program calls `socket()`
2. Kernel intercepts syscall
3. Runs BPF filter program
4. Filter checks syscall number
5. Matches `__NR_socket`
6. Returns `SECCOMP_RET_ERRNO | EPERM`
7. Syscall fails with errno = EPERM
8. Program receives "Operation not permitted" error

#### 3. **STRICT** - Whitelist Only (Kernel-Level Blocking)
- **Description**: Blocks ALL network syscalls at kernel level (similar to NO_NETWORK)
- **Use Case**: High-security environments requiring complete network isolation
- **Implementation**: 
  - Uses **seccomp-BPF** to block `socket()`, `connect()`, `bind()`
  - Kernel-level enforcement - no network sockets can be created
  - User can define rules for documentation, but enforcement requires Network Namespace
- **Default Behavior**: Complete network blocking via seccomp
- **Enforcement**: ✅ **Kernel-level via seccomp-BPF**

#### 4. **MODERATE** - Balanced Security (DEFAULT)
- **Description**: Rule-based filtering, best used with Network Namespace
- **Use Case**: General-purpose sandboxing with documented policies
- **Implementation**:
  - **Primary Protection**: Network Namespace isolation (recommended)
  - **Secondary**: Rules define allowed/blocked ports for documentation
  - **Defense in Depth**: Combines namespace isolation + firewall rules
- **Enforcement**: ⚠️ **Best with Network Namespace enabled**
- **Default Rules**:

```
BLOCKED PORTS:
- Port 21   (FTP)      - File Transfer (insecure)
- Port 23   (Telnet)   - Remote access (unencrypted)
- Port 445  (SMB)      - File sharing (vulnerable)
- Port 3389 (RDP)      - Remote desktop
- Port 3306 (MySQL)    - Database access
- Port 5432 (PostgreSQL) - Database access

ALLOWED PORTS:
- Port 80   (HTTP)     - Web traffic (outbound)
- Port 443  (HTTPS)    - Secure web (outbound)
- Port 53   (DNS)      - Name resolution (outbound)
- Port 123  (NTP)      - Time synchronization
```

**Rule Structure**:
```c
typedef struct {
    char name[64];              // "Block Telnet"
    NetworkProtocol protocol;   // TCP, UDP, ICMP, ALL
    TrafficDirection direction; // INBOUND, OUTBOUND, BOTH
    RuleAction action;          // ALLOW, DENY, LOG
    
    // IP filtering (optional)
    int has_ip_filter;
    struct in_addr ip_addr;     // Target IP
    struct in_addr ip_mask;     // Network mask
    
    // Port filtering (optional)
    int has_port_filter;
    uint16_t port_start;        // Port range start
    uint16_t port_end;          // Port range end
    
    int enabled;                // Is rule active?
} FirewallRule;
```

#### 5. **CUSTOM** - User-Defined Rules
- **Description**: Load rules from policy files
- **Use Case**: Custom security policies
- **Implementation**: Similar to MODERATE - best with Network Namespace
- **Enforcement**: ⚠️ **Best with Network Namespace enabled**
- **File Format**: CSV-style

```csv
# Format: name,protocol,direction,action,ip,mask,port_start,port_end
Allow HTTP,TCP,OUTBOUND,ALLOW,-,-,80,80
Block Telnet,TCP,BOTH,DENY,-,-,23,23
```

### Policy Enforcement Summary

| Policy | Enforcement Method | Network Namespace Required | Effectiveness |
|--------|-------------------|---------------------------|---------------|
| **DISABLED** | None | No | ⚠️ No protection |
| **NO_NETWORK** | Seccomp-BPF (blocks all network syscalls) | No | ✅ Complete isolation |
| **STRICT** | Seccomp-BPF (blocks all network syscalls) | No | ✅ Complete isolation |
| **MODERATE** | Network Namespace + Rule documentation | Yes (recommended) | ✅ Strong with NS |
| **CUSTOM** | Network Namespace + Custom rules | Yes (recommended) | ✅ Strong with NS |

**Key Insight**: For **NO_NETWORK** and **STRICT** modes, enforcement is done at the **kernel level using seccomp-BPF**, providing complete network isolation without requiring Network Namespace. For **MODERATE** and **CUSTOM** modes, the recommended approach is to enable **Network Namespace** for actual isolation, with firewall rules providing additional documentation and defense-in-depth.

### Seccomp-BPF Deep Dive

**BPF (Berkeley Packet Filter)** is a virtual machine in the Linux kernel that can execute small programs to make decisions about packets or syscalls.

**Seccomp-BPF** extends this to **system call filtering**.

#### BPF Program Structure

1. **Accumulator** - Holds current value
2. **Instructions** - Operations to perform
3. **Return Value** - Decision (ALLOW/DENY/ERRNO)

#### BPF Instructions

```c
// Load syscall number
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))

// Compare to __NR_socket (41 on x86_64)
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, jump_true, jump_false)

// Return EPERM error
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0xFFFF))

// Allow syscall
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
```

#### Complete Example: Blocking socket()

```c
int firewall_block_network_syscalls(void) {
    struct sock_filter filter[] = {
        // 1. Load syscall number from seccomp_data structure
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                 offsetof(struct seccomp_data, nr)),
        
        // 2. Check if syscall == __NR_socket (41)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        // If match: execute next instruction (deny)
        // If no match: skip 1 instruction
        
        // 3. Return EPERM for socket()
        BPF_STMT(BPF_RET | BPF_K, 
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        // 4. Check if syscall == __NR_connect (42)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_connect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 
                 SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        
        // ... repeat for bind, sendto, recvfrom, etc.
        
        // N. Allow all other syscalls
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter
    };
    
    // Enable no-new-privs (required for seccomp)
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    
    // Install the filter
    return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}
```

### Firewall Application Flow

```
User Clicks "Run"
    │
    ▼
GUI reads firewall_policy_combo
    │
    ▼
create_sandboxed_process(policy=FIREWALL_NO_NETWORK)
    │
    ▼
fork() child process
    │
    ▼
Child: Setup namespaces
    │
    ▼
Child: Initialize firewall
    │
    ▼
fw_config = firewall_init(FIREWALL_NO_NETWORK)
    │
    ▼
firewall_apply(fw_config)
    │
    ▼
firewall_block_network_syscalls()
    │
    ▼
prctl(PR_SET_NO_NEW_PRIVS, 1)  // Security requirement
    │
    ▼
syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)
    │
    ▼
execl(target_program)  // Execute sandboxed program
    │
    ▼
Program runs with seccomp filter active
    │
    ▼
Program calls socket()
    │
    ▼
Kernel intercepts → BPF filter → Returns EPERM
    │
    ▼
socket() fails with "Operation not permitted"
```

### Firewall Logging

All firewall events are logged to `/tmp/sandbox_firewall.log`:

```
[Sun Nov 30 16:30:45 2025] Firewall initialized: NO_NETWORK mode (complete isolation)
[Sun Nov 30 16:30:45 2025] Applying firewall policy: NO_NETWORK
[Sun Nov 30 16:30:45 2025] Network access completely blocked
```

### Network Namespace + Firewall Interaction

The sandbox provides **multiple layers of network protection** that work together:

#### Configuration Combinations

**1. NO_NETWORK Mode (Most Secure)**
```
Network Namespace: Optional (provides additional isolation)
Firewall: Seccomp-BPF blocks socket(), connect(), bind()
Result: ✅ Complete network isolation at syscall level
```

**2. STRICT Mode (Most Secure)**
```
Network Namespace: Optional
Firewall: Seccomp-BPF blocks all network syscalls
Result: ✅ Complete network isolation at syscall level
```

**3. MODERATE/CUSTOM Mode (Recommended Setup)**
```
Network Namespace: ✅ ENABLED (Required for strong protection)
Firewall: Rules define allowed/blocked connections
Result: ✅ Network isolated at interface level + documented policies
```

**4. MODERATE/CUSTOM Mode (Weak Setup)**
```
Network Namespace: ❌ DISABLED
Firewall: Rules documented but not enforced
Result: ⚠️ Limited protection - rules are advisory only
```

#### Defense in Depth Strategy

When combining **Network Namespace + Firewall**:

1. **Network Namespace** (Layer 1):
   - Isolates network stack
   - Process only has loopback interface
   - Cannot see or access host network interfaces
   - Prevents network access at interface level

2. **Firewall** (Layer 2):
   - **NO_NETWORK/STRICT**: Blocks syscalls (cannot create sockets)
   - **MODERATE/CUSTOM**: Documents allowed/blocked ports
   - Provides additional security layer

3. **Combined Effect**:
   - Network Namespace isolates the process
   - Firewall prevents network syscalls (NO_NETWORK/STRICT) OR documents policy (MODERATE/CUSTOM)
   - Even if one layer bypassed, the other protects

**Best Practice Recommendations**:
- Use **NO_NETWORK** or **STRICT** for untrusted code requiring complete isolation
- Use **Network Namespace + MODERATE** for applications needing selective network access
- Always enable **Network Namespace** when using MODERATE/CUSTOM modes
- MODERATE/CUSTOM without Network Namespace provides limited protection

---

## Memory Protection (DETAILED)

Memory protection prevents **code injection attacks** and **memory exploits** by restricting how programs can manipulate memory.

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│            Application Layer (GUI)                  │
│  - Enable/disable memory protections                │
│  - Configure stack size limits                      │
│  - Toggle W^X enforcement                           │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│    Memory Protection Engine (memory_protection.c)  │
│  ┌─────────────────────────────────────────────┐   │
│  │  Configuration Management                   │   │
│  │  - init_memory_protection_config()          │   │
│  │  - apply_memory_protection()                │   │
│  └─────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────┐   │
│  │  Stack Protection                           │   │
│  │  - set_stack_size_limit() (setrlimit)       │   │
│  │  - disable_executable_stack() (prctl)       │   │
│  └─────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────┐   │
│  │  Memory Syscall Filtering (Seccomp)        │   │
│  │  - setup_memory_seccomp_filter()            │   │
│  │  - Block dangerous mmap/mprotect calls      │   │
│  └─────────────────────────────────────────────┘   │
└──────────────────┬──────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────┐
│           Linux Kernel Enforcement                  │
│  - RLIMIT_STACK enforcement                         │
│  - Seccomp-BPF syscall filtering                    │
│  - Process memory management                        │
└─────────────────────────────────────────────────────┘
```

### Memory Protection Features

#### 1. **W^X (Write XOR Execute) Protection**

**Principle**: Memory pages should be either **writable** OR **executable**, but **NEVER BOTH**.

**Why It Matters**:
- Prevents code injection attacks
- Attacker cannot:
  1. Write shellcode to memory
  2. Mark that memory as executable
  3. Execute the shellcode

**Implementation**:
```c
// In setup_memory_seccomp_filter()
// Check for mmap with PROT_WRITE | PROT_EXEC
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 5),
// Load prot argument (protection flags)
BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
// Check if both WRITE and EXEC bits are set
BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE | PROT_EXEC),
BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_WRITE | PROT_EXEC, 0, 1),
// If both set: DENY with EPERM
BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
```

**Attack Scenario Prevented**:
```c
// Attacker code trying to inject shellcode:
char shellcode[] = "\x90\x90\x90...";

// 1. Allocate writable+executable memory
void *mem = mmap(NULL, 4096, 
                 PROT_WRITE | PROT_EXEC,  // W+X !
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// ❌ BLOCKED! mmap() returns -1, errno = EPERM

// 2. Alternative: allocate writable, then change to executable
void *mem = mmap(NULL, 4096, PROT_WRITE, ...);
memcpy(mem, shellcode, sizeof(shellcode));
mprotect(mem, 4096, PROT_EXEC);  
// ❌ BLOCKED! mprotect() denied by seccomp
```

#### 2. **Stack Size Limits**

**Purpose**: Prevent **stack overflow attacks** and **stack-based buffer overflows**.

**How It Works**:
```c
int set_stack_size_limit(size_t max_stack_kb) {
    struct rlimit rl;
    
    // Get current limits
    getrlimit(RLIMIT_STACK, &rl);
    
    // Set new soft limit
    rl.rlim_cur = max_stack_kb * 1024;  // Convert KB to bytes
    
    // Apply limit
    setrlimit(RLIMIT_STACK, &rl);
}
```

**Default Limit**: 8 MB (8192 KB)

**What Happens When Limit Exceeded**:
1. Program allocates large stack array
2. Stack grows beyond limit
3. Kernel sends **SIGSEGV** signal
4. Program crashes with "Segmentation fault"

**Attack Scenario Prevented**:
```c
// Stack overflow attack attempt
void recursive_attack(int depth) {
    char buffer[1024 * 1024];  // 1 MB per call
    recursive_attack(depth + 1);
}

// Without limit: Could consume all RAM
// With 8MB limit: Crashes after ~8 recursive calls
```

#### 3. **Executable Stack Protection**

**Purpose**: Prevent execution of code on the stack.

**Implementation**:
```c
int disable_executable_stack(void) {
    // Set NO_NEW_PRIVS flag
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    
    // This prevents:
    // - Gaining privileges through setuid binaries
    // - Bypassing security restrictions
}
```

**Combined with Compiler Flags**:
```bash
# Compile programs with non-executable stack
gcc -Wl,-z,noexecstack program.c -o program
```

**Attack Scenario Prevented**:
```c
// Classic stack buffer overflow
void vulnerable() {
    char buffer[64];
    gets(buffer);  // Dangerous! No bounds check
}

// Attacker provides input:
// "AAAA..." (64 bytes) + return_address + shellcode
// 
// Expected: Overwrite return address to point to shellcode on stack
// Actual: Stack is non-executable, shellcode crashes with SIGSEGV
```

#### 4. **Heap Protection**

**Purpose**: Prevent executable heap allocations.

**Implementation**: Same seccomp filter blocks:
- `mmap()` with `MAP_ANONYMOUS` + `PROT_EXEC`
- `mprotect()` adding `PROT_EXEC` to existing mappings

**Attack Scenario Prevented**:
```c
// Heap spray attack
for (int i = 0; i < 1000; i++) {
    char *heap = malloc(4096);
    memcpy(heap, shellcode, sizeof(shellcode));
    // Try to make heap executable
    mprotect(heap, 4096, PROT_READ | PROT_EXEC);
    // ❌ BLOCKED!
}
```

#### 5. **Executable Memory Restrictions**

**Purpose**: Prevent any executable memory outside of legitimate code sections.

**Flag**: `MEM_PROT_DISABLE_EXEC_ANON`

**Blocks**:
- Anonymous executable mappings (common in JIT compilers, exploits)
- `mmap()` with `MAP_ANONYMOUS` + `PROT_EXEC`

### Memory Protection Configuration

```c
typedef struct {
    int flags;                    // Bitmask of protection flags
    size_t max_stack_size_kb;     // Maximum stack size
    int restrict_exec_memory;     // Block ALL exec memory
} MemoryProtectionConfig;

// Flags (can be OR'd together):
#define MEM_PROT_DISABLE_EXEC_STACK     (1 << 0)  // No exec stack
#define MEM_PROT_DISABLE_EXEC_HEAP      (1 << 1)  // No exec heap
#define MEM_PROT_DISABLE_EXEC_ANON      (1 << 2)  // No anon exec maps
#define MEM_PROT_DISABLE_WRITE_EXEC     (1 << 3)  // W^X enforcement
#define MEM_PROT_LIMIT_STACK_SIZE       (1 << 4)  // Stack size limit
#define MEM_PROT_RESTRICT_MMAP          (1 << 5)  // Restrict mmap
```

### Seccomp Memory Filter Example

```c
int setup_memory_seccomp_filter(const MemoryProtectionConfig *config) {
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                 offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_SYSCALL_NR),
        
        // ===== CHECK mmap() =====
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 5),
        
        // Load 'prot' argument (args[2])
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
        
        // AND with (PROT_WRITE | PROT_EXEC) = 0x03
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE | PROT_EXEC),
        
        // If result equals 0x03, both flags are set
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_WRITE | PROT_EXEC, 0, 1),
        
        // DENY: Return EPERM
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        
        // ===== CHECK mprotect() =====
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 9),
        
        // Load 'prot' argument (args[2])
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
        
        // Check for EXEC flag
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_EXEC),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_EXEC, 0, 1),
        
        // Has EXEC, now check if also has WRITE
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, REG_ARG2),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_WRITE, 0, 1),
        
        // Both WRITE and EXEC: DENY
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        
        // Allow all other syscalls
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter
    };
    
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}
```

### Memory Protection Application Flow

```
User Enables Memory Protection
    │
    ▼
Set flags: DISABLE_EXEC_STACK | DISABLE_WRITE_EXEC
Set max_stack_size_kb = 8192
    │
    ▼
create_sandboxed_process(mem_prot_config)
    │
    ▼
fork() child process
    │
    ▼
Child: Setup namespaces
    │
    ▼
Child: apply_memory_protection(config)
    │
    ├─▶ set_stack_size_limit(8192 KB)
    │   │
    │   ▼
    │   getrlimit(RLIMIT_STACK, &rl)
    │   rl.rlim_cur = 8192 * 1024
    │   setrlimit(RLIMIT_STACK, &rl)
    │
    ├─▶ disable_executable_stack()
    │   │
    │   ▼
    │   prctl(PR_SET_NO_NEW_PRIVS, 1)
    │
    └─▶ setup_memory_seccomp_filter(config)
        │
        ▼
        Build BPF filter
        Install filter via seccomp()
        │
        ▼
execl(target_program)
    │
    ▼
Program runs with memory protections active
    │
    ▼
Program attempts: mmap(PROT_WRITE | PROT_EXEC)
    │
    ▼
Kernel intercepts → BPF filter → Returns EPERM
    │
    ▼
mmap() fails: "Cannot allocate memory"
```

### Testing Memory Protection

Test programs in `sample_programs/`:

1. **stack_test** - Tests stack size limits
```c
void stack_overflow() {
    char buffer[1024 * 1024 * 10];  // 10 MB
    // Exceeds 8 MB limit → SIGSEGV
}
```

2. **mmap_exec_test** - Tests W^X protection
```c
void *mem = mmap(NULL, 4096,
                 PROT_WRITE | PROT_EXEC,  // W+X
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
// Returns -1, errno = EPERM
```

3. **mprotect_test** - Tests mprotect() restrictions
```c
void *mem = mmap(NULL, 4096, PROT_WRITE, ...);
memcpy(mem, code, size);
mprotect(mem, 4096, PROT_READ | PROT_EXEC);
// Returns -1, errno = EPERM (if trying to add EXEC to writable)
```

---

## Resource Control (Cgroups)

### What are Cgroups?

**Control Groups (cgroups)** are a Linux kernel feature that limits, accounts for, and isolates resource usage (CPU, memory, disk I/O, network, etc.) of process groups.

### Cgroup Hierarchy

```
/sys/fs/cgroup/  (cgroup v2 unified hierarchy)
└── sandbox_engine/
    ├── cgroup.procs          (PIDs in this cgroup)
    ├── cpu.max               (CPU quota)
    ├── memory.max            (Memory limit)
    ├── memory.current        (Current usage)
    ├── pids.max              (Max processes)
    └── pids.current          (Current processes)
```

### Resource Limits

#### 1. **CPU Limiting**

**Purpose**: Prevent CPU exhaustion

**Implementation**:
```c
// Set CPU to 5% of one core
// Period = 100,000 microseconds (100ms)
// Quota = 5,000 microseconds (5ms)
echo "5000 100000" > /sys/fs/cgroup/sandbox_engine/cpu.max
```

**Effect**: Process can use maximum 5% CPU time
- Every 100ms, process gets 5ms of CPU time
- If exceeded, process is throttled

#### 2. **Memory Limiting**

**Purpose**: Prevent memory exhaustion

**Implementation**:
```c
// Limit to 256 MB
echo "268435456" > /sys/fs/cgroup/sandbox_engine/memory.max
// 256 * 1024 * 1024 = 268435456 bytes
```

**Effect**: 
- Process cannot allocate more than 256 MB
- Allocation beyond limit fails
- May trigger OOM (Out-Of-Memory) killer

#### 3. **Process Count Limiting**

**Purpose**: Prevent fork bombs

**Implementation**:
```c
// Limit to 50 processes
echo "50" > /sys/fs/cgroup/sandbox_engine/pids.max
```

**Effect**: 
- Process cannot fork more than 50 children
- `fork()` returns EAGAIN when limit reached

### Cgroup Version Detection

```c
static int read_cgroup_version(void) {
    // Check for cgroup v2
    if (access("/sys/fs/cgroup/cgroup.controllers", F_OK) == 0) {
        return 2;  // Unified hierarchy
    }
    
    // Check for cgroup v1
    if (access("/sys/fs/cgroup/cpu", F_OK) == 0) {
        return 1;  // Per-controller hierarchies
    }
    
    return 0;  // Not found
}
```

### Adding Process to Cgroup

```c
int setup_cgroup(const CgroupConfig *config, pid_t pid) {
    // Create cgroup directory
    mkdir("/sys/fs/cgroup/sandbox_engine", 0755);
    
    // Set limits
    set_cpu_limit(cgroup_path, config->cpu_limit_percent);
    set_memory_limit(cgroup_path, config->memory_limit_mb);
    set_pids_limit(cgroup_path, config->pids_limit);
    
    // Add process to cgroup
    FILE *f = fopen("/sys/fs/cgroup/sandbox_engine/cgroup.procs", "w");
    fprintf(f, "%d", pid);
    fclose(f);
}
```

---

## File Access Control (Landlock)

### What is Landlock?

**Landlock** is a Linux security module (LSM) that allows unprivileged processes to restrict their own file system access.

### How It Works

1. Create a **ruleset** with allowed access rights
2. Add **rules** for specific paths
3. **Enforce** the ruleset on current process
4. All file accesses are checked against rules

### Access Rights

```c
#define LANDLOCK_ACCESS_FS_EXECUTE      (1ULL << 0)  // Execute files
#define LANDLOCK_ACCESS_FS_WRITE_FILE   (1ULL << 1)  // Write to files
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)  // Read files
#define LANDLOCK_ACCESS_FS_READ_DIR     (1ULL << 3)  // Read directory
#define LANDLOCK_ACCESS_FS_REMOVE_DIR   (1ULL << 4)  // Remove directory
#define LANDLOCK_ACCESS_FS_REMOVE_FILE  (1ULL << 5)  // Remove file
#define LANDLOCK_ACCESS_FS_MAKE_DIR     (1ULL << 7)  // Create directory
// ... more rights
```

### Example Application

```c
// Allow read access to /usr
landlock_add_rule(config, "/usr", 
                  LANDLOCK_ACCESS_FS_READ_FILE | 
                  LANDLOCK_ACCESS_FS_READ_DIR);

// Allow read+write to /tmp
landlock_add_rule(config, "/tmp",
                  LANDLOCK_ACCESS_FS_READ_FILE |
                  LANDLOCK_ACCESS_FS_WRITE_FILE);

// Apply ruleset
landlock_apply(config);

// Now:
// open("/usr/bin/ls", O_RDONLY) → ✓ Allowed
// open("/tmp/file", O_RDWR) → ✓ Allowed
// open("/etc/passwd", O_RDONLY) → ❌ DENIED (no rule for /etc)
```

---

## Process Lifecycle

### Complete Execution Flow

```
1. USER INTERACTION
   User selects file → Configures options → Clicks "Run"
        │
        ▼
2. PROCESS CREATION
   create_sandboxed_process() called
        │
        ▼
3. FORK #1 (Parent Process)
   fork() creates child process
        │
        ├─▶ Parent continues to monitor
        │
        ▼
4. CHILD PROCESS INITIALIZATION
   Setup namespaces if PID namespace:
        │
        ├─▶ unshare(CLONE_NEWPID)
        │
        ▼
5. FORK #2 (PID Namespace Only)
   fork() again → Inner child becomes PID 1
        │
        ├─▶ Outer child waits and exits
        │
        ▼
6. INNER CHILD (Sandboxed Process)
   │
   ├─▶ Setup remaining namespaces
   │   ├─▶ Mount namespace (CLONE_NEWNS)
   │   ├─▶ Network namespace (CLONE_NEWNET)
   │   └─▶ UTS namespace (CLONE_NEWUTS)
   │
   ├─▶ Apply Landlock file access rules
   │   ├─▶ landlock_add_rule("/tmp", READ|WRITE)
   │   ├─▶ landlock_add_rule(executable_path, EXECUTE)
   │   └─▶ landlock_apply()
   │
   ├─▶ Initialize and apply firewall
   │   ├─▶ firewall_init(policy)
   │   ├─▶ firewall_load_policy(file)  [if custom]
   │   └─▶ firewall_apply()
   │       └─▶ firewall_block_network_syscalls()  [if NO_NETWORK]
   │
   ├─▶ Apply memory protection
   │   ├─▶ set_stack_size_limit(8192 KB)
   │   ├─▶ disable_executable_stack()
   │   └─▶ setup_memory_seccomp_filter()
   │
   └─▶ Execute target program
       └─▶ execl(file_path, file_path, NULL)
            │
            ▼
7. PROGRAM EXECUTION
   Target program runs with all restrictions active
        │
        ▼
8. PARENT PROCESS (Monitoring)
   │
   ├─▶ Setup cgroups (resource limits)
   │   └─▶ Add PID to cgroup
   │
   ├─▶ Start monitoring loop
   │   ├─▶ Read /proc/[pid]/stat for CPU
   │   ├─▶ Read /proc/[pid]/status for memory
   │   └─▶ Update GUI every 500ms
   │
   └─▶ Start syscall tracking (if enabled)
       └─▶ ptrace(PTRACE_ATTACH, pid)
            │
            ▼
9. PROCESS RUNNING
   Program executes in isolated environment
        │
        ▼
10. USER TERMINATION or PROGRAM EXIT
    │
    ├─▶ User clicks "Stop" → terminate_process()
    │   ├─▶ SIGTERM (soft kill)
    │   ├─▶ SIGKILL (hard kill)
    │   └─▶ Cgroup kill (all processes in cgroup)
    │
    └─▶ Program exits naturally
        │
        ▼
11. CLEANUP
    ├─▶ waitpid() collects exit status
    ├─▶ cleanup_cgroup()
    ├─▶ Stop monitoring
    └─▶ Update GUI status
```

---

## GUI Interface

### Main Window Structure

```
┌──────────────────────────────────────────────────────┐
│  Sandbox Engine                              [_][□][X] │
├──────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────┐  │
│  │ File Selection & Control                       │  │
│  │  Selected: /path/to/program                    │  │
│  │  [Select File]  [Run]  [Stop]                  │  │
│  └────────────────────────────────────────────────┘  │
│                                                        │
│  ┌─ Tabs ──────────────────────────────────────────┐ │
│  │ [Namespaces][Resources][Monitoring][Syscalls]   │ │
│  │ [Firewall][Memory Protection][Logs]             │ │
│  ├──────────────────────────────────────────────────┤ │
│  │                                                  │ │
│  │  ┌─ Firewall Configuration ──────────────────┐  │ │
│  │  │  Policy: [Moderate ▼]                     │  │ │
│  │  │  Status: ✓ Firewall Active (6 rules)      │  │ │
│  │  │                                            │  │ │
│  │  │  ┌─ Custom Rules ─────────────────────┐   │  │ │
│  │  │  │ Name     Protocol  Port   Action   │   │  │ │
│  │  │  │ Block FTP   TCP     21     DENY    │   │  │ │
│  │  │  │ Allow HTTP  TCP     80     ALLOW   │   │  │ │
│  │  │  └────────────────────────────────────┘   │  │ │
│  │  │                                            │  │ │
│  │  │  [Add Rule]  [Remove]  [Clear All]        │  │ │
│  │  │  [Load Policy]  [Save Policy]             │  │ │
│  │  └────────────────────────────────────────────┘  │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
│                                                        │
│  Status: Process running (PID: 12345)                 │
└────────────────────────────────────────────────────────┘
```

### Tab Descriptions

1. **File Selection & Control**
   - Select executable file
   - Start/stop sandbox
   - View current status

2. **Namespaces**
   - Enable/disable PID, Mount, Network, UTS namespaces
   - Configure hostname for UTS namespace
   - View namespace status

3. **Resource Limits**
   - Set CPU percentage limit
   - Set memory limit (MB)
   - Set maximum processes
   - Set maximum threads

4. **Monitoring**
   - Real-time CPU usage
   - Real-time memory usage
   - Thread count
   - File descriptor count
   - Process status

5. **Syscalls**
   - Live syscall log
   - Syscall statistics
   - Filter specific syscalls
   - Export logs

6. **Firewall**
   - Select policy (Disabled/No Network/Strict/Moderate/Custom)
   - View active rules
   - Add/remove custom rules
   - Load/save policy files

7. **Memory Protection**
   - Enable/disable protections
   - Configure stack size limit
   - Toggle W^X enforcement
   - View protection status

8. **Logs**
   - Engine logs
   - Process output
   - Error messages
   - Real-time updates

---

## Monitoring & Tracking

### Process Monitoring (monitor.c)

Collects statistics from `/proc/[pid]/`:

```c
// Read CPU usage
FILE *f = fopen("/proc/12345/stat", "r");
fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
       &utime, &stime);
cpu_percent = ((utime + stime) / total_time) * 100;

// Read memory usage
f = fopen("/proc/12345/status", "r");
// Parse "VmRSS: 12345 kB"
memory_mb = rss_kb / 1024;

// Count threads
DIR *dir = opendir("/proc/12345/task");
thread_count = count_entries(dir);

// Count file descriptors
dir = opendir("/proc/12345/fd");
fd_count = count_entries(dir);
```

### Syscall Tracking (syscall_tracker.c)

Uses **ptrace** to intercept system calls:

```c
// Attach to process
ptrace(PTRACE_ATTACH, pid, NULL, NULL);
ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

// Monitoring loop
while (1) {
    wait(&status);
    
    if (WIFSTOPPED(status) && (status >> 8) == (SIGTRAP | 0x80)) {
        // Syscall entry or exit
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        
        long syscall_num = regs.orig_rax;
        
        if (is_entry) {
            // Log syscall entry
            log_entry.syscall_number = syscall_num;
            log_entry.arg1 = regs.rdi;
            log_entry.arg2 = regs.rsi;
            // ... more args
        } else {
            // Log syscall exit
            log_entry.return_value = regs.rax;
        }
    }
    
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
}
```

---

## Security Layers

### Defense in Depth

Multiple overlapping security mechanisms:

```
┌─────────────────────────────────────────────────┐
│  Layer 7: Process Monitoring                    │
│  - Real-time behavior analysis                  │
│  - Syscall tracking                             │
│  - Anomaly detection                            │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 6: GUI Controls                          │
│  - User-defined policies                        │
│  - Manual intervention                          │
│  - Process termination                          │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 5: Landlock (File Access)                │
│  - Path-based restrictions                      │
│  - Least privilege file access                  │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 4: Cgroups (Resource Limits)             │
│  - CPU throttling                               │
│  - Memory limits                                │
│  - Process count limits                         │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 3: Memory Protection                     │
│  - W^X enforcement (seccomp)                    │
│  - Stack size limits (rlimit)                   │
│  - No executable stack (prctl)                  │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 2: Firewall                              │
│  - Network syscall blocking (seccomp)           │
│  - Port filtering                               │
│  - Connection logging                           │
└──────────────┬──────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────┐
│  Layer 1: Namespaces (Isolation)                │
│  - PID isolation (process tree)                 │
│  - Mount isolation (file system)                │
│  - Network isolation (network stack)            │
│  - UTS isolation (hostname)                     │
└─────────────────────────────────────────────────┘
```

### Attack Scenarios & Protections

#### Scenario 1: Network Exfiltration
**Attack**: Malware tries to send data to attacker's server
**Protections**:
1. Network Namespace: No physical interfaces
2. Firewall NO_NETWORK: `socket()` syscall blocked
3. Firewall MODERATE: Outbound ports filtered
4. Monitoring: Connection attempts logged

#### Scenario 2: Code Injection
**Attack**: Exploit tries to execute shellcode
**Protections**:
1. Memory W^X: Cannot create writable+executable memory
2. Stack Protection: Stack is non-executable
3. Seccomp: `mmap()` and `mprotect()` filtered
4. Syscall Tracking: Suspicious mmap calls detected

#### Scenario 3: Fork Bomb
**Attack**: Rapidly creates processes to exhaust resources
**Protections**:
1. Cgroups pids.max: Limit to 50 processes
2. PID Namespace: Isolated from system processes
3. Monitoring: Process count tracked
4. Automatic termination when limit hit

#### Scenario 4: Privilege Escalation
**Attack**: Attempts to gain root privileges
**Protections**:
1. NO_NEW_PRIVS: Cannot gain privileges via setuid
2. Namespaces: No access to host user namespace
3. Landlock: Restricted file access (no /etc/shadow)
4. Seccomp: Dangerous syscalls blocked

---

## Summary

The Sandbox Engine provides **comprehensive process isolation and security** through:

1. **Namespaces** - Isolate process from system
2. **Firewall** - Control network access via seccomp-BPF
3. **Memory Protection** - Prevent code injection via W^X, stack limits, seccomp
4. **Cgroups** - Limit resource consumption
5. **Landlock** - Restrict file system access
6. **Monitoring** - Track behavior in real-time

All layers work together to create a **secure sandbox environment** where untrusted code can run with minimal risk to the host system.

---

## File Reference

### Core Source Files
- `src/main.c` - GTK GUI (2285 lines)
- `src/process_control.c/h` - Process management
- `src/namespaces.c/h` - Namespace setup
- `src/firewall.c/h` - Firewall implementation
- `src/memory_protection.c/h` - Memory protection
- `src/cgroups.c/h` - Resource control
- `src/landlock.c/h` - File access control
- `src/syscall_tracker.c/h` - Syscall monitoring
- `src/monitor.c/h` - Process monitoring

### Configuration Files
- `policies/moderate.policy` - Default firewall rules
- `policies/strict.policy` - Strict firewall rules
- `policies/web_only.policy` - Web-only access rules

### Documentation
- `README.md` - Overview and quick start
- `TESTING_GUIDE.md` - Testing instructions
- `TESTING_FIREWALL.md` - Firewall testing
- `ROADMAP.md` - Development plan

### Build System
- `Makefile` - Compilation rules
- `sample_programs/Makefile` - Test program builds

---

**This guide provides a complete understanding of how the Sandbox Engine works, with detailed explanations of the firewall and memory protection systems as requested.**
