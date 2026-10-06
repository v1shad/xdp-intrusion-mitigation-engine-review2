#!/bin/bash
set -u

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <iface>"
    exit 1
fi
IFACE=$1

if [ -f /tmp/review2_http.pid ]; then
    PID=$(cat /tmp/review2_http.pid)
    kill -9 "$PID" 2>/dev/null || true
    rm -f /tmp/review2_http.pid
    echo "Killed HTTP server (PID: $PID)"
fi

if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --reload >/dev/null 2>&1
    echo "Firewall runtime rules removed."
fi

systemctl stop sshd
echo "Stopped sshd."

echo "Note: If you changed PasswordAuthentication in sshd_config, please revert it now."

if ip -details link show "$IFACE" 2>/dev/null | grep -q "xdp"; then
    echo "WARNING: An XDP program is STILL attached to $IFACE."
    echo "Fix: sudo ip link set dev $IFACE xdp off"
else
    echo "Confirmed: No XDP program attached to $IFACE."
fi
