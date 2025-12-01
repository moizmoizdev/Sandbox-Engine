#!/bin/bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Installing Network Dependencies               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script needs to install packages. Please run with sudo:"
    echo "   sudo ./install_dependencies.sh"
    echo ""
    echo "Or install manually:"
    echo "   sudo apt-get update"
    echo "   sudo apt-get install -y iptables iproute2 netfilter-persistent"
    exit 1
fi

echo "📦 Updating package list..."
apt-get update -qq

echo "📦 Installing iptables..."
apt-get install -y iptables

echo "📦 Installing iproute2..."
apt-get install -y iproute2

echo "📦 Installing netfilter-persistent..."
apt-get install -y netfilter-persistent

echo ""
echo "✅ Dependencies installed successfully!"
echo ""

# Test the installations
echo "🔍 Testing installations..."

if command -v iptables >/dev/null 2>&1; then
    echo "  ✓ iptables: $(which iptables)"
else
    echo "  ❌ iptables: Not found"
fi

if command -v ip >/dev/null 2>&1; then
    echo "  ✓ ip: $(which ip)"
else
    echo "  ❌ ip: Not found"
fi

echo ""
echo "🔧 Setting up kernel modules..."
modprobe ip_tables 2>/dev/null || echo "  ⚠️  ip_tables module not available"
modprobe iptable_filter 2>/dev/null || echo "  ⚠️  iptable_filter module not available"
modprobe iptable_nat 2>/dev/null || echo "  ⚠️  iptable_nat module not available"

echo ""
echo "✅ Setup complete! You can now run:"
echo "   ./main"
echo ""
echo "If you still get errors, try:"
echo "   sudo ./main"
