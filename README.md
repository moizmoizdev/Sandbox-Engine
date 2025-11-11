# Sandboxing Engine with Monitoring Interface

A sandboxing engine built entirely in C that securely isolates and monitors user processes using Linux kernel features.

**📋 See [ROADMAP.md](ROADMAP.md) for detailed project timeline and implementation plan.**

## Features

- Process isolation using namespaces, cgroups, and seccomp
- Real-time monitoring interface built with GTK 4 and WebKitGTK
- Interactive controls for file selection, policy loading, and process management
- Lightweight IPC for backend-frontend communication

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

3. **Continue without namespaces**: The sandbox will still work with other isolation features (cgroups, seccomp) that don't require root.

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

**Warning:** The intensive test programs are designed to stress-test the sandbox and may consume significant system resources. Always run them within the sandbox environment.

You can select any of these programs using the "Select File" button in the GUI.

## Project Structure

```
engine/
├── src/              # Source files
├── sample_programs/ # Test programs for sandboxing
├── obj/             # Object files (generated)
├── main             # Executable (generated)
├── Makefile         # Build configuration
└── README.md        # This file
```

## License

[To be determined]

