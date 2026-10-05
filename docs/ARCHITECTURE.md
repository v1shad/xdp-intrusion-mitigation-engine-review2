# Architecture

## Data Flow
1. **Packet Arrival:** Packets arrive at the network interface and trigger the XDP hook.
2. **Kernel Enforcement:** The eBPF program (`xdp_prog.bpf.c`) reads the packet headers. It checks `allowed_ips` first, then `blocked_ips`. If a match is found in the blocklist and hasn't expired, the packet is dropped and stats are updated.
3. **Event Sampling:** For dropped packets, every 64th packet generates an event pushed to the user space via a BPF Ring Buffer.
4. **Log Processing:** A user space thread reads a target log file, extracting source IPs from failed authentication attempts.
5. **Rule Evaluation:** These events are pushed into the `RuleEngine`, which tracks sliding time windows. If a threshold is crossed, an `Alert` is generated.
6. **Map Update:** User space pushes the newly blocked IP into the eBPF `blocked_ips` map.
7. **Storage:** Alerts and Actions are committed to the SQLite database.

## Threading Model
The user space daemon (`engine.cpp`) utilizes C++20 `std::jthread` to manage concurrency:
- **Main Thread:** Handles initialization, attaching the eBPF program, command-line interface parsing, and clean detachment upon shutdown (via `SIGINT`/`SIGTERM` handlers).
- **Log Detector Thread (`SshDetector`):** Continuously tails the log file, parsing lines via regex, and executing the callback when a failure is detected.
- **Ring Buffer Poller Thread:** Continuously polls the BPF ring buffer for sampled drop events sent from the kernel.
- **Sweeper Thread (`BlockList`):** Periodically iterates over the `blocked_ips` eBPF map, removing IP entries that have passed their expiration timestamp.

## Map Layouts
Shared layouts are defined in `common.h` and the BPF program:

- **`allowed_ips`**: `BPF_MAP_TYPE_HASH`
  - Key: `__u32` (IPv4 address in network byte order)
  - Value: `__u8` (dummy value)

- **`blocked_ips`**: `BPF_MAP_TYPE_HASH`
  - Key: `__u32` (IPv4 address in network byte order)
  - Value: `struct block_record` containing `__u64 hits` and `__u64 expires_at_ns`.

- **`stats`**: `BPF_MAP_TYPE_PERCPU_ARRAY`
  - Key: `__u32` (index 0 for dropped, 1 for passed)
  - Value: `__u64` (packet count, aggregated per CPU in user space)

- **`events`**: `BPF_MAP_TYPE_RINGBUF`
  - Holds `struct drop_event` consisting of `ts_ns`, `src_ip`, `pad`, and `total_hits`.

## eBPF Verifier Rules
The Linux kernel's eBPF verifier enforces safety constraints before allowing the program to run:
- **Bounds Checking:** Pointer arithmetic (`eth + 1`, `ip + 1`) is strictly checked against the `data_end` pointer to prevent out-of-bounds memory access.
- **Null Checking:** Map lookup results (`bpf_map_lookup_elem`, `bpf_ringbuf_reserve`) must be checked for `NULL` before dereferencing.

## Design Decisions
- **User Space Decides, Kernel Enforces:** The complexity of parsing logs, stateful time windows, and regex evaluation is kept in user space, while the high-performance packet dropping logic operates in the kernel.
- **Fail-Open:** If the user space engine crashes or is shut down cleanly, the eBPF link is destroyed, detaching the program. Packets naturally fall back to passing through the standard OS network stack.
- **Sampling Drop Events:** Emitting an event from kernel to user space on every single dropped packet during a flood would overwhelm the ring buffer and CPU. We sample drops (1 in 64) to provide visibility without performance degradation.
