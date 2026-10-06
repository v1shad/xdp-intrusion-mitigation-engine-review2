# Tier 3 Automated Intrusion Mitigation Engine (Review 2 Demo)

## Scope
This version of the engine focuses purely on the core eBPF/XDP drop mechanics and the C++20 user-space rule evaluation on a real network interface.
**Note:** Playbooks, dashboard, engine-cli, control socket, and rate limiter are NOT present in this version.

## Demo Procedure

Please see the full demo script in **[docs/REAL_DEMO.md](docs/REAL_DEMO.md)**.

## Benchmarks
The engine filters packets effectively before the OS stack. Tested on Wi-Fi drivers which typically use generic XDP; results on high-speed physical NICs were not measured. In this environment, XDP and iptables-raw are equivalent within noise.

## Known Limits
- IPv4 only.
- Tested with one friend's laptop on a home or hotspot network, not the internet.
- DHCP can change an IP, which may affect block rules.
- No persistence across restarts.

## Troubleshooting

| Problem | Solution |
|---|---|
| `/var/log/secure` not found | Make sure `rsyslog` is installed and running, or check `/var/log/auth.log` on Ubuntu. |
| Interface down | Ensure the chosen interface is up (`ip link show`). |
| IP still blocked | Wait for the TTL to expire, or run `unblock <ip>` in the console. |
| Engine crashed | The XDP program might still be attached. Run `./real_cleanup.sh <iface>`. |
