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

# IP Validation function for internal use
get_iface_ip() {
    ip -4 addr show "$1" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1
}

TARGET_IP=$(get_iface_ip "$IFACE")
if [ -z "$TARGET_IP" ]; then
    echo "Error: Could not find an IPv4 address for interface $IFACE."
    exit 1
fi

MISSING=0
for cmd in sshd rsyslogd python3 nmap tcpdump; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing: $cmd"
        MISSING=1
    fi
done

if [ $MISSING -eq 1 ]; then
    echo "Fix (Fedora): sudo dnf install openssh-server rsyslog python3 nmap tcpdump"
    echo "Fix (Ubuntu): sudo apt install openssh-server rsyslog python3 nmap tcpdump"
    exit 1
fi

systemctl enable --now rsyslog
systemctl enable --now sshd

PASS_AUTH=$(sshd -T 2>/dev/null | grep -i passwordauthentication | awk '{print $2}')
echo "PasswordAuthentication is: $PASS_AUTH"
if [ "$PASS_AUTH" != "yes" ]; then
    echo "To fix, edit /etc/ssh/sshd_config (or /etc/ssh/sshd_config.d/*.conf) to set 'PasswordAuthentication yes' and run 'sudo systemctl restart sshd'."
fi

if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --add-service=ssh
    firewall-cmd --add-port=8000/tcp
    echo "Firewall rules for ssh and tcp/8000 added (runtime only)."
fi

nohup python3 -m http.server 8000 --bind "$TARGET_IP" >/dev/null 2>&1 &
echo $! > /tmp/review2_http.pid
echo "HTTP server started on $TARGET_IP:8000 (PID: $(cat /tmp/review2_http.pid))"

GW=$(ip route show default | awk '{print $3}' | head -n1)
if [ -f /var/log/secure ]; then
    LOG_PATH="/var/log/secure"
else
    LOG_PATH="/var/log/auth.log"
fi

echo "----------------------------------------"
echo "Target IP: $TARGET_IP"
echo "Gateway:   $GW"
echo "Log Path:  $LOG_PATH"
echo "Target ready. Next: sudo ./real_run.sh $IFACE --dry-run"
