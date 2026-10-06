# Safety Guidelines

This engine drops traffic at the lowest level of the operating system. When testing on a real network, follow these rules:

1. **Consent:** Only test with a consenting participant (e.g., a friend's laptop).
2. **Own Network Only:** Perform this demo on a home network or personal hotspot you own and control. Do NOT run this on public or university Wi-Fi where you might accidentally disrupt others.
3. **Stay Physical:** Stay physically at the laptop running the engine. Do not test this over a remote connection (like SSH), or you may lock yourself out permanently.
4. **Gateway Allowlisting:** The engine automatically allowlists your default gateway to prevent you from severing your internet connection. Do not remove the gateway from the allowlist.
5. **Short TTLs:** Always use a short TTL (Time To Live) for blocks. The default is 60 seconds, and the hard cap is 600 seconds.
6. **Dry-Run Mode:** If unsure, run the engine with `--dry-run` first. It will log "would block" alerts without actually updating the kernel map.
7. **Lockout Recovery:** If you accidentally lock out a required IP:
   - Wait for the TTL to expire.
   - Stop the engine cleanly (`quit` or `Ctrl-C`).
   - If the engine crashes and leaves the XDP program attached, run `sudo ip link set dev <interface> xdp off`.
   - If all else fails, a system reboot clears all XDP programs and memory maps.
