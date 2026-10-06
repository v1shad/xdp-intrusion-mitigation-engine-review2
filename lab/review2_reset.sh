#!/bin/bash
set -u

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

systemctl stop xdp-engine 2>/dev/null || true

./teardown_lab.sh 2>/dev/null || true
./setup_lab.sh

> /tmp/fake_auth.log
chmod 666 /tmp/fake_auth.log

if [ -f "engine.db" ]; then
    mv engine.db "engine.db.bak.$(date +%s)"
fi

if ! ip netns exec attacker ping -c 1 -W 2 10.10.0.1 >/dev/null 2>&1; then
    echo "Error: Baseline ping from attacker namespace failed."
    exit 1
fi

echo "READY"
echo "Start engine with: ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log"
