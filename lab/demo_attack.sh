#!/bin/bash
set -u

IP=${1:-10.10.0.2}

if [[ ! -f /tmp/fake_auth.log || ! -w /tmp/fake_auth.log ]]; then
    echo "Error: /tmp/fake_auth.log is missing or not writable."
    echo "Fix it by running: sudo touch /tmp/fake_auth.log && sudo chmod 666 /tmp/fake_auth.log"
    exit 1
fi

if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP format"
    exit 1
fi

for octet in $(echo "$IP" | tr '.' ' '); do
    if ((octet < 0 || octet > 255)); then
        echo "Error: Invalid IP address"
        exit 1
    fi
done

writes_success=true
for N in {1..6}; do
    if ! echo "Sep 30 12:00:0${N} lab sshd[1234]: Failed password for root from ${IP} port 4000${N} ssh2" >> /tmp/fake_auth.log; then
        writes_success=false
        break
    fi
    sleep 0.5
done

if $writes_success; then
    echo "Successfully injected 6 failed login attempts for ${IP}."
fi
