# Threat Model

## Assets
- **Host Server:** Network stack, CPU, memory.
- **Audit Data:** `engine.db` containing logs of threats and mitigation actions.
- **Availability:** Maintaining service availability under DoS/brute-force attacks.

## Attackers
- **External Network Attackers:** Attempting brute-force logins or volumetric flooding.
- **Malicious Packets:** Packets crafted to exploit network stack parsing vulnerabilities.

## Trust Boundaries
- **Network Interface (Untrusted):** Traffic arriving at the physical or virtual interface.
- **Kernel Space (Trusted):** eBPF/XDP program enforcing rules safely under the verifier.
- **User Space (Trusted):** The C++ daemon evaluating logs and dictating block policies.

## Mitigations Present
- **Kernel-level Drop:** XDP drops malicious packets before OS network stack overhead, mitigating CPU exhaustion from network floods.
- **Automated Detection:** Real-time log tailing responds immediately to brute-force attempts.
- **Fail-open Design:** Prevents total network isolation if the mitigation daemon fails.
- **Allowlist Mechanism:** Prevents administrative lockout.
- **Ringbuf Sampling:** Protects the daemon from being overwhelmed by event flood from XDP.

## Known Gaps (Review 2 Milestone)
- **Log Forgery/Injection:** The engine blindly parses text logs. A malicious user with local non-root access or through an application vulnerability could inject fake "Failed password" lines to trigger blocks against arbitrary IPs.
- **Log Rotation Blindness:** The engine tails the file descriptor. If `logrotate` rotates the file, the engine will stop receiving updates.
- **Invalid UTF-8:** The engine may crash if it processes malformed UTF-8 characters.
- **IPv4 Only:** Attackers can bypass mitigations by using IPv6.
- **State Loss:** No persistence of the `blocked_ips` map between restarts.
- **No IP Spoofing Mitigation:** Does not inherently block spoofed source IPs (relies on upstream RPF filtering).
