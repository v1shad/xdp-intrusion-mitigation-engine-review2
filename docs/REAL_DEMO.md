# Real Attacker Showcase

This document outlines how to safely demo the Review 2 engine by letting a consenting friend manually attack your laptop using their own tools.

## Rules to Agree with Your Friend
Before starting, clearly establish these boundaries to ensure a safe and controlled demonstration:
1. **Own Network Only:** Ensure both of you are connected to your personal home Wi-Fi or mobile hotspot.
2. **Only My Laptop:** They must strictly target the IP address you provide them.
3. **Time Limit:** Agree on a maximum time limit for the attacks (e.g., 5-10 minutes).
4. **Short Floods:** If they plan to use volumetric attacks (like ping floods), they should cap them at 5-10 seconds to avoid crashing the local router.

## Engine Capabilities & Limitations
The Review 2 milestone focuses specifically on dynamic SSH log tailing and eBPF/XDP blocking.
* **Tested Environment:** generic XDP on Wi-Fi interfaces over IPv4.
* **No Persistence:** Blocks and settings clear when the engine is stopped.

### Detection Table
| Attack Type | Detected by Engine? | Expected Outcome |
|---|---|---|
| SSH Password Guessing | **Yes** | Engine detects "Failed password", updates event log, and eventually blocks. |
| Port Scans (Nmap) | No | Not detected in this milestone (no specific listener/logs generated). |
| SYN Floods / UDP Floods | No | Not detected in this milestone (no specific detector). |
| Web Attacks / HTTP Probes | No | Not detected (HTTP logs are not tailed in Review 2). |
| **Any traffic AFTER block** | **Yes** | XDP drops *all* protocols (Ping, HTTP, SYN) line-rate for a blocked IP. |

**How to Explain a Miss Honestly:**
If your friend runs a port scan and asks why they weren't blocked, plainly explain that the Review 2 milestone relies purely on SSH log detection. XDP drops packets line-rate *after* the user-space daemon makes a block decision based on those logs. Future milestones will introduce raw packet inspection for scans.

## Suggested Session Plan

1. **Setup & Preflight:**
   [TARGET] Run `xdpguard doctor` to ensure your SSH service and logs are working properly. Note your Interface and IP address.
   If needed, start SSH (`sudo systemctl start sshd`) and verify `/etc/ssh/sshd_config` allows password authentication.

2. **Detect Mode (Safety First):**
   [TARGET] Start the engine in the default detect mode:
   ```bash
   sudo xdpguard run <iface> --ttl 60
   ```
   *The engine auto-allowlists your default gateway. Verify this in the startup banner.*

3. **The Attack:**
   Provide the Target IP to your friend. Ask them to verify baseline connectivity (e.g., ping), then tell them to manually trigger SSH auth failures:
   [FRIEND] `ssh nosuchuser@<TARGET_IP>` (type wrong passwords)
   
   [TARGET] You will see `[AUTH]` and `[DETECTED]` tags on your screen, indicating that a block *would* have occurred.

4. **Enforce Mode:**
   [TARGET] Switch the engine to live enforce mode:
   Type `mode enforce` in the engine console.

5. **The Block:**
   Ask your friend to try SSH again.
   [TARGET] You will see a red `[BLOCKED]` tag.
   [FRIEND] Their connection will freeze or time out.
   Ask your friend to run a 5-second ping flood.
   [TARGET] You will see `[DROPPING]` tags in the event log showing the exact drop rate from the kernel.

6. **Cleanup:**
   [TARGET] Type `quit` to exit the engine.
   [TARGET] Ensure XDP is detached: `sudo xdpguard cleanup <iface>`.
