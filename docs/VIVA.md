# Technical Viva Q&A

**Q1. Why use eBPF/XDP over iptables?**
*A1:* iptables processes packets late in the Linux networking stack after sk_buff allocation. XDP operates directly at the driver level, allowing packets to be dropped with vastly less CPU overhead, significantly improving resilience against volumetric floods.

**Q2. How does the user-space daemon communicate with the kernel?**
*A2:* Through eBPF maps (HASH, PERCPU_ARRAY) using the `libbpf` syscall wrappers, and a BPF Ring Buffer for receiving events from the kernel.

**Q3. Why is the `stats` map a PERCPU_ARRAY?**
*A3:* To prevent lock contention. Each CPU increments its own counter slot without atomic operations. User-space aggregates them on read.

**Q4. What is the eBPF Verifier and how did it affect your code?**
*A4:* It's an in-kernel static analyzer ensuring the program won't crash the kernel. We had to prove pointer accesses are within `data_end` and check map lookup results for `NULL`.

**Q5. How does the engine handle timeouts/expirations?**
*A5:* The user-space daemon runs a sweeper `jthread` that periodically iterates the `blocked_ips` map and removes entries whose timestamp has expired.

**Q6. Why do you sample drop events in the kernel?**
*A6:* Emitting an event for every dropped packet during a flood would overwhelm the ring buffer and user-space CPU. Sampling (1 in 64) provides visibility efficiently.

**Q7. Is the engine fail-open or fail-closed?**
*A7:* Fail-open. If the user-space daemon crashes, the XDP link is automatically destroyed (via RAII `bpf_link__destroy`), returning the interface to standard packet processing.

**Q8. What happens if the SQLite database is locked?**
*A8:* The engine uses a mutex to protect the `sqlite3` handle, preventing concurrent access crashes from multiple threads, but heavy locking could block the event processing loop.

**Q9. What are the known limitations of this milestone?**
*A9:* IPv4 only. No state persistence across restarts. DHCP changes can affect block rules. Tested on physical Wi-Fi interfaces which typically use generic XDP (so line-rate performance isn't guaranteed). Vulnerable to invalid-UTF-8 crashes and log-rotation blindness (addressed partially via hardening).

**Q10. Why is regex parsing done in user space instead of the kernel?**
*A10:* The eBPF verifier heavily restricts loops and complexity. Text parsing and stateful time-window logic are too complex for XDP and belong in user space.

**Q11. How do you prevent blocking yourself (SSH lockout)?**
*A11:* By maintaining an `allowed_ips` map. IP `127.0.0.1` is whitelisted by default, and others can be added via the CLI or `--allow` argument. The XDP program evaluates this map first.

**Q12. What are the exact criteria for a brute-force block?**
*A12:* 5 failed authentication attempts for the same source IP within a sliding 60-second window, as defined in `rules.yaml`.
