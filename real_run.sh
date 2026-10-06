#!/bin/bash
set -u

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <iface> [extra engine args...]"
    exit 1
fi

IFACE=$1
shift

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "Error: Interface $IFACE does not exist."
    exit 1
fi

if systemctl is-active xdp-engine >/dev/null 2>&1; then
    echo "Error: xdp-engine service is currently active. Stop it first."
    exit 1
fi

if [ -f /var/log/secure ]; then
    LOGFILE="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
    LOGFILE="/var/log/auth.log"
else
    echo "Error: Could not find /var/log/secure or /var/log/auth.log."
    echo "Fix: Make sure rsyslog is installed and running."
    exit 1
fi

echo "=========================================================="
echo "                   SAFETY BANNER                          "
echo "=========================================================="
echo "Interface:       $IFACE"
echo "Log Path:        $LOGFILE"
echo "TTL:             60s (default)"
echo "Threshold:       5 (from rules.yaml, unless overridden)"
echo ""
echo "Auto-Allowlist will include:"
echo "  - 127.0.0.1"
echo "  - IPs assigned to $IFACE"
echo "  - Default Gateway"
echo "=========================================================="
read -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

exec ./engine "$IFACE" xdp_prog.bpf.o "$LOGFILE" --ttl 60 "$@"
