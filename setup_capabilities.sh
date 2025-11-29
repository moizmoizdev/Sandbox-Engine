#!/bin/bash
# Setup Linux capabilities for the sandbox binary
# This allows running without sudo while still having namespace permissions

echo "═══════════════════════════════════════════════════════════"
echo "  Sandbox Capability Setup"
echo "═══════════════════════════════════════════════════════════"
echo ""

echo "📋 Setting capabilities for namespaces and process control..."
echo ""

# Set capabilities
sudo setcap cap_sys_admin,cap_net_admin,cap_sys_ptrace,cap_sys_resource,cap_dac_override+ep ./main
# Enable cpuset in root cgroup
echo "+cpuset" | sudo tee /sys/fs/cgroup/cgroup.subtree_control

# Create and own the sandbox cgroup
sudo mkdir -p /sys/fs/cgroup/sandbox_engine
sudo chown -R $USER:$USER /sys/fs/cgroup/sandbox_engine
if [ $? -eq 0 ]; then
    echo "✅ Capabilities set successfully!"
    echo ""
    echo "Capabilities granted:"
    echo "  • CAP_SYS_ADMIN    - Namespaces (PID, Mount, UTS)"
    echo "  • CAP_NET_ADMIN    - Network namespace"
    echo "  • CAP_SYS_PTRACE   - Syscall tracking"
    echo "  • CAP_SYS_RESOURCE - Resource limits"
    echo "  • CAP_DAC_OVERRIDE - Cgroup write access"
    echo ""
    
    # Pre-create cgroup directory with proper permissions
    echo "📋 Setting up cgroup directory..."
    sudo mkdir -p /sys/fs/cgroup/sandbox_engine 2>/dev/null
    sudo chown $USER:$USER /sys/fs/cgroup/sandbox_engine 2>/dev/null
    
    if [ -d "/sys/fs/cgroup/sandbox_engine" ]; then
        echo "✅ Cgroup directory created and owned by $USER"
    else
        echo "⚠️  Cgroup directory creation failed (may already exist or cgroup v1)"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ Setup Complete!"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "You can now run: ./main"
    echo "(without sudo)"
    echo ""
    echo "Current capabilities:"
    getcap ./main
    echo ""
    echo "⚠️  NOTE: If cgroups still fail, you may need to run with sudo"
    echo "   for full cgroup support (cgroup v1 systems)"
else
    echo "❌ Failed to set capabilities"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Install libcap: sudo apt install libcap2-bin"
    echo "  2. Make sure binary exists: ls -l ./main"
    echo "  3. Try running with sudo instead: sudo ./main"
fi
