# Free-form Real Attacker Mode

This document outlines how to safely demo the Review 2 engine by letting a consenting friend manually attack your laptop using their own tools.

## Rules to Agree with Your Friend

Before starting, clearly establish these boundaries to ensure a safe and controlled demonstration:
1. **Own Network Only:** Ensure both of you are connected to your personal home Wi-Fi or mobile hotspot. Do not do this on university or public networks.
2. **Only My Laptop:** They must strictly target the IP address you provide them.
3. **Time Limit:** Agree on a maximum time limit for the attacks (e.g., 5-10 minutes).
4. **Short Floods:** If they plan to use volumetric attacks (like ping floods), they should cap them at 5-10 seconds to avoid crashing the local router.
5. **Stop on Request:** They must immediately halt all tools if you say "stop."

## Review 2 Engine Detection Capabilities

| Attack Type | Detected by Engine? | Expected Outcome |
|---|---|---|
| SSH Password Guessing | **Yes** | Engine detects "Failed password" in logs, blocks IP in XDP. |
| SSH Brute-force Tools | **Yes** | Same as above. |
| Port Scans (Nmap) | No | Not detected in this milestone (no logs generated). |
| SYN Floods / UDP Floods | No | Not detected in this milestone (no specific detector). |
| Web Attacks / HTTP Probes | No | Not detected (HTTP logs are not tailed in Review 2). |
| **Any traffic AFTER block** | **Yes** | XDP drops *all* protocols (Ping, HTTP, SYN) line-rate for a blocked IP. |

**How to Explain a Miss Honestly:**
If your friend runs a port scan and asks why they weren't blocked, plainly explain that the Review 2 milestone relies purely on SSH log detection. XDP is only programmed to drop packets *after* the user-space daemon makes a block decision based on those logs. Mention that future milestones will introduce raw packet inspection for port scans.

## Suggested Session Plan for the Owner

Follow this sequence to ensure a smooth showcase:

1. **Setup:**
   [TARGET] Run `sudo ./kit/target_setup.sh <iface>`. Note the Target IP.

2. **Dry Run (Safety First):**
   [TARGET] Start the engine with a strict TTL and dry-run mode:
   ```bash
   sudo ./real_run.sh <iface> --ttl 60 --dry-run
   ```
   *The engine will auto-allowlist your default gateway. Verify this in the startup output.*

3. **Verify Observability:**
   [TARGET] In a second terminal, start the observer:
   ```bash
   sudo ./kit/observe.sh watch <iface>
   ```

4. **Live Mode:**
   [TARGET] Stop the dry-run engine (`quit`), and restart it in live mode:
   ```bash
   sudo ./real_run.sh <iface> --ttl 60
   ```

5. **The Attack:**
   Provide the Target IP to your friend. Ask them to verify baseline connectivity (ping, curl port 8000), then tell them to try guessing SSH passwords.
   [FRIEND] Runs their own SSH commands or tools against your IP.

6. **The Block:**
   Watch your `observe.sh` terminal and engine console. Once the threshold is crossed, the IP will appear in the XDP Map.
   Ask your friend to try pinging or opening the web port again. They will be completely blocked.

7. **Cleanup:**
   [TARGET] Type `quit` in the engine. Run `sudo ./kit/target_teardown.sh <iface>`.

## Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| Friend cannot ping baseline | Client Isolation / Firewalld | Check router settings (AP Isolation) or run `kit/target_setup.sh`. |
| Connection refused | sshd down / port blocked | Run `kit/target_setup.sh` to start `sshd` and open firewall. |
| No log lines appear | Password auth disabled | Ensure `PasswordAuthentication yes` in `sshd_config`. |
| DHCP changed the IP | Network lease expired | Stop engine, find new IP (`ip addr`), update friend's target IP. |
| Locked out | Local IP blocked | Wait for TTL to expire (default 60s), or stop engine (`Ctrl-C`). |
