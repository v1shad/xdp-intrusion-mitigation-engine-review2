#!/bin/bash
set -u

echo "=== System Preflight Check ==="

echo -n "Kernel Version: "
uname -r

echo -n "BTF Present: "
if [ -f /sys/kernel/btf/vmlinux ]; then echo "Yes"; else echo "No (Fix: upgrade kernel to 5.15+ with CONFIG_DEBUG_INFO_BTF=y)"; fi

echo -n "clang Version: "
if command -v clang >/dev/null 2>&1; then clang --version | head -n1; else echo "Not found (Fix: sudo apt install clang / sudo dnf install clang)"; fi

echo -n "g++ Version: "
if command -v g++ >/dev/null 2>&1; then g++ --version | head -n1; else echo "Not found (Fix: sudo apt install g++ / sudo dnf install gcc-c++)"; fi

echo -n "sshd Running: "
if systemctl is-active sshd >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then echo "Yes"; else echo "No (Fix: sudo systemctl start sshd)"; fi

echo -n "Auth Log Readable: "
if [ -r /var/log/secure ]; then echo "/var/log/secure"; elif [ -r /var/log/auth.log ]; then echo "/var/log/auth.log"; else echo "No (Fix: ensure rsyslog is running and you have read permissions or run as root)"; fi

echo -n "PasswordAuthentication: "
if command -v sshd >/dev/null 2>&1; then sudo sshd -T 2>/dev/null | grep -i passwordauthentication || echo "Unknown"; else echo "sshd command not found"; fi

echo "Interfaces with IPv4:"
ip -4 addr show | awk '/inet / {print "  " $NF ": " $2}'

echo -n "Default Gateway: "
ip route show default | awk '{print $3 " on " $5}' || echo "None found"

echo "XDP Attachments:"
for iface in $(ip -j link show | awk -F'"' '/"ifname"/ {print $4}'); do
    if ip -details link show "$iface" 2>/dev/null | grep -q "xdp"; then
        echo "  $iface: HAS XDP ATTACHED (Fix: sudo ip link set dev $iface xdp off)"
    fi
done

echo "=== Check Complete ==="
