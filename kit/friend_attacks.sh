#!/bin/bash
set -u

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <TARGET_IP> <scenario>"
    echo "Scenarios: baseline, bruteforce, hydra, slow, aftermath, pingflood, undetected"
    exit 1
fi

TARGET_IP=$1
SCENARIO=$2

is_private_ip() {
    local ip=$1
    if [[ $ip =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then return 0; fi
    if [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+$ ]]; then return 0; fi
    if [[ $ip =~ ^192\.168\.[0-9]+\.[0-9]+$ ]]; then return 0; fi
    return 1
}

if ! is_private_ip "$TARGET_IP"; then
    echo "Error: $TARGET_IP is not a valid private IPv4 address."
    echo "This script must only be used on local networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)."
    exit 1
fi

echo "========================================="
echo "        FRIEND ATTACK SIMULATOR          "
echo "========================================="
echo "Target IP: $TARGET_IP"
echo "Scenario:  $SCENARIO"
echo "========================================="
read -p "Type YES to confirm you have consent from the target owner: " confirm
if [ "$confirm" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

case "$SCENARIO" in
    baseline)
        echo "[+] Testing ping..."
        ping -c 3 -W 2 "$TARGET_IP" && echo "Ping: REACHABLE" || echo "Ping: BLOCKED"
        echo "[+] Testing HTTP (port 8000)..."
        curl -m 5 "http://$TARGET_IP:8000" && echo -e "\nHTTP: REACHABLE" || echo -e "\nHTTP: BLOCKED"
        echo "[+] Testing SSH (port 22)..."
        ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "nosuchuser@$TARGET_IP" exit 2>/dev/null
        echo "SSH test completed."
        ;;
    bruteforce)
        echo "[+] Running 6 wrong-password SSH attempts..."
        if command -v sshpass >/dev/null 2>&1; then
            for i in {1..6}; do
                echo "Attempt $i..."
                sshpass -p "wrong" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 "nosuchuser@$TARGET_IP" 2>/dev/null || true
                sleep 2
            done
        else
            echo "sshpass not found. Run this manually 6 times:"
            echo "ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 nosuchuser@$TARGET_IP"
        fi
        ;;
    hydra)
        if command -v hydra >/dev/null 2>&1; then
            echo "[+] Running hydra with wordlist..."
            timeout 60s hydra -l nosuchuser -P kit/wordlist.txt -t 4 "ssh://$TARGET_IP" || echo "Hydra stopped or timed out."
        else
            echo "hydra not installed. Install it with: sudo apt install hydra / sudo dnf install hydra"
        fi
        ;;
    slow)
        echo "[+] Running 4 failures..."
        if command -v sshpass >/dev/null 2>&1; then
            for i in {1..4}; do
                sshpass -p "wrong" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 "nosuchuser@$TARGET_IP" 2>/dev/null || true
                sleep 1
            done
            echo "Waiting 65 seconds for the sliding window to clear..."
            sleep 65
            echo "[+] Running 4 more failures..."
            for i in {1..4}; do
                sshpass -p "wrong" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 "nosuchuser@$TARGET_IP" 2>/dev/null || true
                sleep 1
            done
        else
            echo "sshpass is required for automated slow scenario."
        fi
        ;;
    aftermath)
        echo "[+] Post-block baseline check"
        ping -c 3 -W 2 "$TARGET_IP" && echo "Ping: REACHABLE" || echo "Ping: BLOCKED"
        curl --max-time 5 "http://$TARGET_IP:8000" && echo -e "\nHTTP: REACHABLE" || echo -e "\nHTTP: BLOCKED"
        if command -v nmap >/dev/null 2>&1; then
            nmap -Pn -p 22,80,8000 --host-timeout 15s "$TARGET_IP" | grep open || echo "Nmap: BLOCKED"
        fi
        ;;
    pingflood)
        echo "[+] Flooding pings (8 seconds)..."
        if [ "$EUID" -eq 0 ]; then
            timeout 8s ping -f "$TARGET_IP" || true
        else
            timeout 8s ping -i 0.01 -c 500 "$TARGET_IP" || true
        fi
        ;;
    undetected)
        echo "Review 2 has no detector for these; no block is expected."
        if command -v nmap >/dev/null 2>&1; then
            echo "[+] Stealth scan..."
            nmap -sS -p 1-200 --host-timeout 30s "$TARGET_IP"
        fi
        if command -v hping3 >/dev/null 2>&1; then
            if [ "$EUID" -eq 0 ]; then
                echo "[+] SYN burst..."
                hping3 -S -p 80 -c 3000 -i u1000 "$TARGET_IP"
            else
                echo "hping3 requires root."
            fi
        fi
        ;;
    *)
        echo "Unknown scenario."
        exit 1
        ;;
esac
