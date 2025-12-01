#!/bin/bash

echo "=== Testing Network Tools ==="

echo -n "Testing ip command... "
if command -v ip >/dev/null 2>&1; then
    echo "✓ Found: $(which ip)"
else
    echo "❌ Not found"
fi

echo -n "Testing iptables command... "
if command -v iptables >/dev/null 2>&1; then
    echo "✓ Found: $(which iptables)"
else
    echo "❌ Not found"
fi

echo -n "Testing /usr/sbin/ip... "
if [ -x "/usr/sbin/ip" ]; then
    echo "✓ Found"
else
    echo "❌ Not found"
fi

echo -n "Testing /usr/sbin/iptables... "
if [ -x "/usr/sbin/iptables" ]; then
    echo "✓ Found"
else
    echo "❌ Not found"
fi

echo -n "Testing /sbin/ip... "
if [ -x "/sbin/ip" ]; then
    echo "✓ Found"
else
    echo "❌ Not found"
fi

echo -n "Testing /sbin/iptables... "
if [ -x "/sbin/iptables" ]; then
    echo "✓ Found"
else
    echo "❌ Not found"
fi

echo ""
echo "=== Network Namespace Test ==="
echo -n "Can create network namespace... "
if unshare -n echo "test" >/dev/null 2>&1; then
    echo "✓ Yes"
else
    echo "❌ No (need root or capabilities)"
fi

echo ""
echo "=== Current User ==="
echo "User: $(whoami)"
echo "UID: $(id -u)"
echo "Groups: $(id -G)"

echo ""
echo "=== Capabilities ==="
if command -v getcap >/dev/null 2>&1; then
    echo "Main binary capabilities:"
    getcap ./main 2>/dev/null || echo "No capabilities set"
else
    echo "getcap not available"
fi
