#!/bin/bash
set -u

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <iface>"
    exit 1
fi

IFACE=$1

if ip -details link show "$IFACE" 2>/dev/null | grep -q "xdp"; then
    echo "WARNING: An XDP program is STILL attached to $IFACE."
    echo "Run: sudo ip link set dev $IFACE xdp off"
else
    echo "OK: No XDP program attached to $IFACE."
fi

echo ""
echo "If you made changes to test the demo, remember to revert them:"
echo "  1. If you enabled PasswordAuthentication in sshd_config, disable it and restart sshd:"
echo "     sudo systemctl restart sshd"
echo "  2. If you opened firewall ports, close them."
