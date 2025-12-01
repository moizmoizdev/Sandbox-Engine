# Sandboxing Engine with Monitoring Interface

A sandboxing engine built entirely in C that securely isolates and monitors user processes using Linux kernel features.

**📋 See [ROADMAP.md](ROADMAP.md) for detailed project timeline and implementation plan.**

## Features

- **Process Isolation:** Using Linux namespaces (PID, Mount, Network, UTS)
- **Network Firewall:** Multi-layer firewall with seccomp-based syscall filtering and enhanced GUI
- **Memory Protection:** W^X enforcement, stack size limits, executable memory restrictions
- **Policy Management:** Pre-defined and custom firewall policies with improved interface
- **Real-time Monitoring:** GTK 4 interface for process control and resource monitoring
- **Syscall Tracking:** Real-time syscall monitoring and statistics
- **Resource Control:** Cgroups integration with CPU, memory, and process limits
- **Interactive Controls:** Modern GUI with enhanced file selection, policy loading, and process management
- **Comprehensive Testing:** Extensive test suite for security feature validation

## Building

### Prerequisites

- GCC compiler
- pkg-config (for finding library dependencies)
- GTK 4 development libraries
- WebKitGTK 6.0 development libraries

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libgtk-4-dev libwebkitgtk-6.0-dev
```

**Troubleshooting Installation Issues:**

If you encounter 404 errors during installation (repository mirror issues), try:

1. **Update package lists again:**
   ```bash
   sudo apt-get update --fix-missing
   ```

2. **Install with fix-missing flag:**
   ```bash
   sudo apt-get install --fix-missing build-essential pkg-config libgtk-4-dev libwebkitgtk-6.0-dev
   ```

3. **If still failing, try installing core packages first:**
   ```bash
   sudo apt-get install build-essential pkg-config
   sudo apt-get install libgtk-4-dev
   sudo apt-get install libwebkitgtk-6.0-dev
   ```

4. **Alternative: Use apt instead of apt-get:**
   ```bash
   sudo apt update
   sudo apt install build-essential pkg-config libgtk-4-dev libwebkitgtk-6.0-dev
   ```

### Compilation

```bash
make
```

The executable will be created as `main` in the root directory.

### Cleaning

```bash
make clean
```

## Usage

### Quick Start

1. **Build the project:**
   ```bash
   make
   ```

2. **Set Linux capabilities** (allows namespace operations without root):
   ```bash
   bash setup_capabilities.sh
   ```

3. **Run the application:**
   ```bash
   ./main
   ```

### Automated Testing

**Run comprehensive firewall tests** (fully automated, no manual testing required):

```bash
# Make script executable (first time only)
chmod +x run_firewall_tests.sh

# Run all tests automatically
./run_firewall_tests.sh
```

This will:
- Clean and rebuild the project
- Set up Linux capabilities
- Test all firewall enforcement modes
- Verify seccomp-BPF and namespace isolation
- Generate comprehensive test report

**See [AUTOMATED_TESTING_GUIDE.md](AUTOMATED_TESTING_GUIDE.md) for detailed testing documentation.**

## Firewall System

The sandbox includes a comprehensive network firewall with multiple security policies and **kernel-level enforcement**:

### Firewall Policies

1. **Disabled** - No firewall, full network access (use only for trusted applications)
2. **No Network** - ✅ **Complete network isolation using seccomp-BPF** to block all network syscalls at kernel level
3. **Strict** - ✅ **Kernel-level blocking** (similar to No Network); blocks all network syscalls via seccomp-BPF
4. **Moderate** (Default) - ⚠️ Rule-based filtering; **best used with Network Namespace enabled** for actual enforcement. Blocks dangerous ports (Telnet, FTP, SMB, etc.), allows HTTP/HTTPS/DNS
5. **Custom** - ⚠️ User-defined rules from policy file; **best used with Network Namespace enabled** for actual enforcement

### Policy Files

Pre-defined policy files are located in the `policies/` directory:

- `strict.policy` - Minimal access, localhost only
- `moderate.policy` - Balanced security, blocks dangerous ports
- `web_only.policy` - Only HTTP/HTTPS/DNS allowed

### Custom Policy Format

Create custom policies using this CSV format:

```
# Format: name,protocol,direction,action,ip,mask,port_start,port_end
Allow HTTP,TCP,OUTBOUND,ALLOW,-,-,80,80
Block Telnet,TCP,BOTH,DENY,-,-,23,23
```

**Fields:**
- **protocol:** TCP, UDP, ICMP, or ALL
- **direction:** INBOUND, OUTBOUND, or BOTH
- **action:** ALLOW, DENY, or LOG
- **ip/mask:** Use `-` for any IP address
- **ports:** Use 0 for any port

### How It Works

The firewall uses a **defense-in-depth multi-layer approach**:

1. **Seccomp-BPF Syscall Filtering** - Kernel-level enforcement for NO_NETWORK and STRICT modes
   - Blocks `socket()`, `connect()`, `bind()`, `sendto()`, `recvfrom()`, etc.
   - Returns EPERM (Operation not permitted) at syscall level
   - **✅ Complete isolation without Network Namespace required**

2. **Network Namespace Isolation** - Recommended for MODERATE/CUSTOM modes
   - Isolates network stack (separate from host)
   - Process only sees loopback interface
   - Prevents access to physical network interfaces

3. **Rule-Based Filtering** - Policy engine for MODERATE/CUSTOM modes
   - Defines allowed/blocked ports and protocols
   - Best used WITH Network Namespace for actual enforcement
   - Provides documentation and defense-in-depth

4. **Logging** - Connection attempts logged to `/tmp/sandbox_firewall.log`

### Enforcement Summary

| Mode | Enforcement | Network Namespace Required |
|------|------------|---------------------------|
| **NO_NETWORK** | ✅ Seccomp-BPF (kernel-level) | No |
| **STRICT** | ✅ Seccomp-BPF (kernel-level) | No |
| **MODERATE** | ⚠️ Network Namespace + Rules | Yes (recommended) |
| **CUSTOM** | ⚠️ Network Namespace + Rules | Yes (recommended) |

**Best Practices**:
- Use **NO_NETWORK** or **STRICT** for untrusted code requiring complete network isolation
- Use **MODERATE** with **Network Namespace enabled** for applications needing controlled network access
- Enable **Network Namespace** in the GUI when using MODERATE/CUSTOM modes for best protection

## Memory Protection

The sandbox includes comprehensive memory protection features to prevent code injection and memory exploits:

### Memory Protection Features

- **W^X (Write XOR Execute)** - Prevents writable memory from being executable
- **Stack Size Limits** - Enforces maximum stack size to prevent stack overflow attacks
- **Executable Stack Protection** - Disables executable stack via `prctl(PR_SET_NO_NEW_PRIVS)`
- **Memory Mapping Restrictions** - Uses seccomp filters to restrict dangerous `mmap()` and `mprotect()` calls
- **Heap Protection** - Prevents executable heap allocations

### Configuration

Memory protection can be configured through the GUI:
1. **Stack Protection Frame:**
   - Enable/disable executable stack protection
   - Set stack size limits (default: 8MB)

2. **Memory Region Protection Frame:**
   - Enable W^X enforcement
   - Restrict executable memory mappings
   - Block dangerous memory operations

## GUI Interface

The sandbox features a modern GTK4 interface with several tabs:

### Main Tabs

1. **File Selection & Control** - Choose executable and start/stop sandbox
2. **Namespaces** - Configure process isolation (PID, Mount, Network, UTS)
3. **Resource Limits** - Set CPU, memory, and process limits via cgroups
4. **Monitoring** - Real-time process statistics and resource usage
5. **Syscalls** - Live syscall tracking with statistics and filtering
6. **Firewall** - Enhanced firewall configuration with improved rule management
7. **Memory Protection** - Configure memory protection settings
8. **Logs** - View application and process logs in real-time

### Enhanced Firewall Tab

The firewall tab has been completely redesigned with modern UI principles:

#### Visual Improvements
- **Organized Layout:** Separated into clear sections with frames and headers
- **Policy Section:** Clean dropdown with real-time status updates and descriptions
- **Rules Management:** Dedicated section with rule count display and bulk operations
- **Add Rule Form:** Card-based design with logical field grouping and spacing

#### Functional Enhancements
- **Rule Counting:** Live display of active rules ("X rules" counter)
- **Bulk Operations:** "Clear All" button for quick rule management
- **Enhanced Form:** 4-column grid layout with proper labels and input validation
- **Better UX:** Styled action buttons (suggested/destructive actions)
- **Real-time Updates:** Immediate rule list refresh after modifications

#### Policy Management
- **Status Display:** Shows current policy and blocking status
- **Policy Descriptions:** Detailed explanations of each firewall mode:
  - Disabled: No firewall (full network access)
  - No Network: Complete isolation via seccomp
  - Strict: Whitelist-only mode
  - Moderate: Blocks dangerous ports, allows common services
  - Custom: User-defined rules from policy files
- **Load/Save:** Easy policy file management with file choosers

## Testing

Sample test programs are provided in the `sample_programs/` directory. To build them:

```bash
cd sample_programs
make
```

This will create several test programs:

**Basic Test Programs:**
- `hello` - Simple hello world program that runs for a few seconds
- `cpu_intensive` - CPU-intensive program for testing resource monitoring
- `memory_test` - Memory allocation and usage test
- `infinite_loop` - Long-running program that can be terminated
- `file_operations` - File creation, reading, and deletion test

**Intensive/Virus-like Behavior Tests:**
- `fork_bomb` - Rapidly creates many child processes (limited to prevent system crash)
- `file_spammer` - Creates hundreds of files rapidly to test file system limits
- `memory_bomb` - Aggressively allocates memory to exhaust system resources
- `cpu_abuse` - Spawns multiple threads to max out CPU cores
- `disk_filler` - Creates large files to fill disk space
- `resource_exhaustion` - Combines CPU, memory, and file descriptor exhaustion

**Network/Firewall Test Programs:**
- `network_test` - Attempts to create socket and connect to external server
- `http_request` - Attempts HTTP GET request to test web access
- `dns_lookup` - Tests DNS resolution capabilities
- `port_scan` - Attempts to connect to various ports to test firewall rules
- `network_connect` - Comprehensive network connectivity test for firewall validation

**Security Test Programs:**
- `stack_test` - Tests stack size limits and stack-based operations
- `mmap_exec_test` - Tests W^X protection by attempting RWX memory allocation
- `mprotect_test` - Tests if mprotect() can add EXEC permissions to writable memory
- `syscall_test` - Makes various syscalls for tracking and monitoring testing
- `print_info` - Displays sandbox environment info (PIDs, namespaces, resource limits)

**Warning:** The intensive test programs are designed to stress-test the sandbox and may consume significant system resources. Always run them within the sandbox environment.

### Testing Scenarios

**📋 For comprehensive testing instructions, see [TESTING_GUIDE.md](TESTING_GUIDE.md)**

#### Testing Firewall

1. Select a network test program (e.g., `network_connect`)
2. Choose firewall policy from dropdown
3. Run in sandbox and observe blocked/allowed connections
4. Check logs in the "Logs" tab or at `/tmp/sandbox_firewall.log`

#### Testing Memory Protection

1. Go to "Memory Protection" tab and enable desired protections
2. Select security test programs:
   - `stack_test` - Test stack size limits
   - `mmap_exec_test` - Test W^X protection
   - `mprotect_test` - Test memory protection enforcement
3. Observe protection effectiveness in process output and logs

#### Testing Process Isolation

1. Enable namespaces in "Namespaces" tab
2. Run `print_info` to verify isolation:
   - PID namespace: Process should show PID 1
   - UTS namespace: Hostname should be "sandbox"
   - Network namespace: Isolated network stack
3. Monitor resource usage in "Monitoring" tab

You can select any of these programs using the "Select File" button in the GUI.

## Project Structure

```
Sandbox-Engine/
├── src/                    # Source files
│   ├── main.c             # GTK GUI application with enhanced interface
│   ├── sandbox.c/h        # Core sandbox functionality
│   ├── process_control.c/h # Process management with memory protection
│   ├── namespaces.c/h     # Linux namespace isolation
│   ├── firewall.c/h       # Network firewall system
│   ├── memory_protection.c/h # Memory protection and W^X enforcement
│   ├── cgroups.c/h        # Resource control via cgroups
│   ├── monitoring.c/h     # Process monitoring and statistics
│   └── syscall_tracking.c/h # Real-time syscall tracking
├── policies/              # Firewall policy files
│   ├── strict.policy
│   ├── moderate.policy
│   └── web_only.policy
├── sample_programs/       # Test programs for sandboxing
│   ├── Makefile          # Build file for test programs
│   ├── Basic tests: hello, cpu_intensive, memory_test, etc.
│   ├── Security tests: stack_test, mmap_exec_test, mprotect_test
│   ├── Network tests: network_connect, http_request, dns_lookup
│   └── Info test: print_info
├── docs/                  # Documentation
├── obj/                   # Object files (generated)
├── main                   # Main executable (generated)
├── Makefile              # Build configuration
├── README.md             # This file
├── TESTING_GUIDE.md      # Comprehensive testing instructions
└── ROADMAP.md            # Development roadmap
```

## Recent Updates

### Version 2.0 Features Added:

#### Memory Protection System
- **New Files:** `memory_protection.c/h` - Complete W^X enforcement and stack protection
- **Stack Size Limits:** Configurable stack size enforcement (default 8MB)
- **W^X Protection:** Prevents writable+executable memory via seccomp filters
- **GUI Integration:** Dedicated "Memory Protection" tab with intuitive controls

#### Enhanced Firewall Interface
- **Complete Redesign:** Modern card-based layout with organized sections
- **Improved Rule Management:** Real-time rule counting, bulk operations, enhanced form
- **Better Visual Hierarchy:** Clear headers, frames, and logical information grouping  
- **Enhanced UX:** Intuitive form layout, styled buttons, immediate feedback
- **Policy Integration:** Clear status display and comprehensive policy descriptions

#### Comprehensive Test Suite
- **Security Tests:** New programs to validate memory protection effectiveness
- **Network Tests:** Enhanced connectivity testing for firewall validation
- **System Tests:** Environment and isolation verification tools
- **Build Integration:** Updated Makefile to build all test programs

#### Log System Improvements
- **GUI Integration:** Process output now appears in the "Logs" tab
- **Real-time Updates:** Live log streaming from sandboxed processes
- **Better Formatting:** Clear separation of process outputs and system messages

#### GUI Enhancements
- **Modern Layout:** Improved visual organization across all tabs
- **Real-time Updates:** Enhanced monitoring and syscall tracking displays
- **Better Navigation:** Clearer tab organization and information hierarchy

## License

[To be determined]

