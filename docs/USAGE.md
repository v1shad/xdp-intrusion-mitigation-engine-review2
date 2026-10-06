# Usage Guide

## `xdpguard doctor`
Runs a read-only preflight check on your environment to ensure dependencies, logs, and interfaces are ready for the engine to run safely.
```bash
xdpguard doctor
```

## `xdpguard run <iface>`
Starts the intrusion engine and attaches the eBPF program to the specified interface.
```bash
sudo xdpguard run wlp2s0 --ttl 60
```
### Flags:
* `--allow <IP>`: Whitelist an IP address so it is never dropped. Can be specified multiple times.
* `--dry-run`: Evaluate logs and generate alerts, but do not actually block IPs in the kernel.
* `--ttl <S>`: Time-to-live for a block in seconds (default: 60).
* `--threshold <N>`: Override the threshold for failures before blocking.
* `--window <S>`: Override the sliding window duration in seconds.
* `--log <PATH>`: Manually specify the SSH log path instead of auto-detecting.
* `--no-tui`: Fall back to the plain text console instead of the live dashboard.

### TUI Hotkeys
* `b`: Block an IP address manually.
* `u`: Unblock an IP address.
* `a`: Allowlist an IP address.
* `d`: Toggle dry-run mode on/off on the fly.
* `q`: Safely quit the engine and detach the XDP program.

## `xdpguard cleanup <iface>`
A safety fallback command to force detach any lingering XDP programs from an interface.
```bash
sudo xdpguard cleanup wlp2s0
```

## `xdpguard report`
Reads the `engine.db` SQLite database and prints the most recent alerts and total event counts.
```bash
xdpguard report
```
