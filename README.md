# Sandboxing Engine with Monitoring Interface

A sandboxing engine built entirely in C that securely isolates and monitors user processes using Linux kernel features.

**📋 See [ROADMAP.md](ROADMAP.md) for detailed project timeline and implementation plan.**

## Features

- **Process Isolation:** Using Linux namespaces (PID, Mount, Network, UTS)
- **Network Firewall:** Multi-layer firewall with seccomp-based syscall filtering
- **Policy Management:** Pre-defined and custom firewall policies
- **Real-time Monitoring:** GTK 4 interface for process control
- **Interactive Controls:** File selection, policy loading, and process management
- **Resource Control:** Cgroups and seccomp integration (planned)

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

```bash
./main
```

**Note:** Namespace isolation features (PID, mount, network, UTS) require root privileges or appropriate Linux capabilities. If you see "Operation not permitted" errors, you can either:

1. **Run with sudo** (for testing):
   ```bash
   sudo ./main
   ```

2. **Set capabilities** (for production):
   ```bash
   sudo setcap cap_sys_admin,cap_net_admin+ep ./main
   ./main
   ```

3. **Continue without namespaces**: The sandbox will still work with other isolation features (firewall, seccomp) that don't require root.

## Firewall System

The sandbox includes a comprehensive network firewall with multiple security policies:

### Firewall Policies

1. **Disabled** - No firewall, full network access (use only for trusted applications)
2. **No Network** - Complete network isolation using seccomp to block all network syscalls
3. **Strict** - Whitelist-only mode; all connections blocked by default
4. **Moderate** (Default) - Blocks dangerous ports (Telnet, FTP, SMB, etc.), allows HTTP/HTTPS/DNS
5. **Custom** - User-defined rules loaded from policy file

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

The firewall uses a multi-layer approach:

1. **Network Namespace Isolation** - Isolates network stack
2. **Seccomp Syscall Filtering** - Blocks network syscalls at kernel level (NO_NETWORK mode)
3. **Rule-Based Filtering** - Policy engine for fine-grained control
4. **Logging** - Connection attempts logged to `/tmp/sandbox_firewall.log`

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

**Warning:** The intensive test programs are designed to stress-test the sandbox and may consume significant system resources. Always run them within the sandbox environment.

### Testing Firewall

To test firewall functionality:

1. Select a network test program (e.g., `network_test`)
2. Choose firewall policy from dropdown
3. Run in sandbox and observe blocked/allowed connections
4. Check logs at `/tmp/sandbox_firewall.log`

You can select any of these programs using the "Select File" button in the GUI.

## Project Structure

```
Sandbox-Engine/
├── src/              # Source files
│   ├── main.c        # GTK GUI application
│   ├── sandbox.c/h   # Core sandbox functionality
│   ├── process_control.c/h  # Process management
│   ├── namespaces.c/h       # Linux namespace isolation
│   └── firewall.c/h         # Network firewall system
├── policies/         # Firewall policy files
│   ├── strict.policy
│   ├── moderate.policy
│   └── web_only.policy
├── sample_programs/  # Test programs for sandboxing
├── docs/            # Documentation
├── obj/             # Object files (generated)
├── main             # Executable (generated)
├── Makefile         # Build configuration
├── README.md        # This file
└── ROADMAP.md       # Development roadmap
```

## License

[To be determined]

