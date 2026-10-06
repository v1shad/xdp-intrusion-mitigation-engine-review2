# Attack Scenarios and Showcase

This document provides a structured testing guide for evaluating the Review 2 engine on a real network interface.

## 10-Minute Live Showcase Order

1. **[TARGET]** Run `sudo ./kit/target_setup.sh <iface>`. Verify prerequisites.
2. **[TARGET]** Start the engine: `sudo ./real_run.sh <iface>`.
3. **[FRIEND]** Run baseline test: `./friend_attacks.sh <TARGET_IP> baseline`. (Expected: REACHABLE).
4. **[TARGET]** Monitor logs: `sudo ./kit/observe.sh log`.
5. **[FRIEND]** Trigger attack: `./friend_attacks.sh <TARGET_IP> bruteforce`.
6. **[TARGET]** Observe `[ALERT]` and `[BLOCKED]` in the engine console.
7. **[FRIEND]** Run aftermath: `./friend_attacks.sh <TARGET_IP> aftermath`. (Expected: BLOCKED across all protocols).
8. **[TARGET]** Verify maps: `sudo ./kit/observe.sh map` and `sudo ./kit/observe.sh drops <iface> <FRIEND_IP>`.
9. **[TARGET]** Type `unblock <FRIEND_IP>` in the engine console.
10. **[FRIEND]** Re-run baseline. (Expected: REACHABLE).
11. **[TARGET]** Cleanup: type `quit`, then `sudo ./kit/target_teardown.sh <iface>`.

## Scenario Table

| Scenario | Who | Command | Target Expected Result | Friend Expected Result |
|---|---|---|---|---|
| Baseline | Friend | `./friend_attacks.sh <IP> baseline` | Log shows no drops. | REACHABLE for Ping, HTTP, SSH. |
| Single Attacker Block (Brute-force) | Friend | `./friend_attacks.sh <IP> bruteforce` | Engine: `[ALERT]`, `[BLOCKED]`. | SSH connection times out/freezes. |
| All-protocol Block | Friend | `./friend_attacks.sh <IP> aftermath` | `tcpdump` shows 0 packets. `map` shows IP. | BLOCKED for Ping, HTTP, Nmap. |
| Sliding Window | Friend | `./friend_attacks.sh <IP> slow` | Engine sees events but NO `[BLOCKED]`. | REACHABLE (window expires before threshold). |
| Per-IP Independence | Friend 2 | Ping from a separate device (phone) | Engine passes packets from Phone. | Phone is REACHABLE, Friend 1 is BLOCKED. |
| Allowlist Test | Target | `allow <FRIEND_IP>` in console, then friend attacks | Engine: `[ALERT]` but NO `[BLOCKED]`. | REACHABLE despite brute-force. |
| TTL Recovery | Target | Wait 60s without unblocking | Engine: `[EXPIRED] <FRIEND_IP>`. | REACHABLE after 60 seconds. |
| Ping Flood (Ring Buffer) | Friend | `./friend_attacks.sh <IP> pingflood` | Engine: `[EVENT] packet_dropped` spam. | BLOCKED (100% packet loss). |
| Not Detected (Nmap SYN) | Friend | `./friend_attacks.sh <IP> undetected` | Engine does not parse SYN packets. | REACHABLE (no block triggered). |

## Windows Friends
If your friend uses Windows, they can use the PowerShell equivalent script:
1. Open PowerShell.
2. Run `.\kit\friend_attacks.ps1 -TargetIP <YOUR_IP> -Scenario baseline`
Available scenarios: `baseline`, `bruteforce` (manual prompts), `aftermath`.

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| Friend cannot ping baseline | Client Isolation / Firewalld | Check router settings (AP Isolation) or run `kit/target_setup.sh`. |
| Connection refused | sshd down / port blocked | Run `kit/target_setup.sh` to start `sshd` and open firewall. |
| No log lines appear | Log file wrong / rsyslog down | Check `/var/log/secure` or `/var/log/auth.log`. Restart `rsyslog`. |
| DHCP changed the IP | Network lease expired | Stop engine, find new IP (`ip addr`), update friend's target IP. |
| Locked out | Local IP blocked | Wait for TTL to expire (default 60s), or stop engine (`Ctrl-C`). |
| XDP program stuck | Engine crashed | Run `sudo ./kit/target_teardown.sh <iface>` or `sudo ip link set dev <iface> xdp off`. |
