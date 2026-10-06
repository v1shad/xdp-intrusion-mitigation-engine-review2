#!/bin/bash
set -u

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <command> [args...]"
    echo "Commands:"
    echo "  log               - Tail sshd log for 'Failed password'"
    echo "  map               - Dump the XDP blocked_ips map"
    echo "  drops <iface> <ip>- tcpdump for drops from specific IP"
    echo "  mode <iface>      - Check if XDP is attached"
    echo "  db                - Query recent events and alerts from engine.db"
    exit 1
fi

CMD=$1
shift

is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then return 0; fi
    return 1
}

case "$CMD" in
    log)
        if [ -f /var/log/secure ]; then
            LOG_PATH="/var/log/secure"
        else
            LOG_PATH="/var/log/auth.log"
        fi
        tail -f "$LOG_PATH" | grep --line-buffered "Failed password"
        ;;
    map)
        if command -v bpftool >/dev/null 2>&1; then
            bpftool map dump name blocked_ips
        else
            echo "bpftool not installed."
        fi
        ;;
    drops)
        if [ "$#" -ne 2 ]; then
            echo "Usage: $0 drops <iface> <ip>"
            exit 1
        fi
        IFACE=$1
        IP=$2
        if ! is_valid_ip "$IP"; then
            echo "Error: Invalid IP address format."
            exit 1
        fi
        echo "Capturing 20 packets from $IP on $IFACE (will be 0 if XDP drops them)..."
        tcpdump -ni "$IFACE" host "$IP" -c 20
        ;;
    mode)
        if [ "$#" -ne 1 ]; then
            echo "Usage: $0 mode <iface>"
            exit 1
        fi
        IFACE=$1
        ip -details link show "$IFACE" | grep xdp
        ;;
    db)
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "--- Last 5 Events ---"
            sqlite3 engine.db "SELECT * FROM events ORDER BY id DESC LIMIT 5;"
            echo "--- Last 5 Alerts ---"
            sqlite3 engine.db "SELECT * FROM alerts ORDER BY id DESC LIMIT 5;"
        else
            echo "sqlite3 not installed."
        fi
        ;;
    *)
        echo "Unknown command."
        exit 1
        ;;
esac
