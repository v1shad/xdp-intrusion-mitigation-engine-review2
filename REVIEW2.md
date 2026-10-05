# Tier 3 Automated Intrusion Mitigation Engine (Review 2 Demo)

## Scope
This version of the engine focuses purely on the core eBPF/XDP drop mechanics and the C++20 user-space rule evaluation.
**Note:** Playbooks, dashboard, engine-cli, control socket, and rate limiter are NOT present in this version.

## 10-Step Demo Script

1. **Reset the Lab Environment:**
   ```bash
   sudo ./review2_reset.sh
   ```
   *Expected Result:* Prints "READY" and the exact engine start command.

2. **Start the Engine:**
   ```bash
   sudo ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log
   ```
   *Expected Result:* Engine starts, outputs initialization logs, and waits for commands.

3. **Verify Baseline Connectivity:**
   In a second terminal, start a continuous ping from the attacker namespace:
   ```bash
   sudo ip netns exec attacker ping 10.10.0.1
   ```
   *Expected Result:* Ping responses are received normally.

4. **Simulate an Attack:**
   In a third terminal, inject failed ssh logs using the attack script:
   ```bash
   ./demo_attack.sh 10.10.0.2
   ```
   *Expected Result:* Script successfully injects 6 logs and prints success message.

5. **Observe Engine Block:**
   Watch the engine terminal.
   *Expected Result:* Engine detects the threshold, outputs an ALERT, and BLOCKS `10.10.0.2`.

6. **Verify Traffic is Dropped:**
   Look at the continuous ping terminal.
   *Expected Result:* Ping responses stop immediately (XDP drops the packets).

7. **Check Engine Stats:**
   In the engine terminal, type:
   `stats`
   *Expected Result:* Prints packets dropped > 0 and packets passed.

8. **Unblock the IP:**
   In the engine terminal, type:
   `unblock 10.10.0.2`
   *Expected Result:* Engine outputs that the IP is UNBLOCKED.

9. **Verify Restored Connectivity:**
   Look back at the continuous ping terminal.
   *Expected Result:* Ping responses resume.

10. **Shutdown:**
    In the engine terminal, type:
    `quit`
    *Expected Result:* Engine cleanly detaches XDP and exits.

## Benchmarks
The engine filters packets effectively before the OS stack. Veth is virtual; results on real NICs were not measured. In this environment, XDP and iptables-raw are equivalent within noise.

## Known Limits
- The engine keeps a stale blocklist if it is not restarted between runs.
- Invalid UTF-8 logs can cause a crash.
- Log-rotation blindness (the engine won't detect if the log file is rotated).
- No persistence across reboots.

## Troubleshooting

| Problem | Solution |
|---|---|
| `/tmp/fake_auth.log` not writable | Run `sudo chmod 666 /tmp/fake_auth.log` or let `review2_reset.sh` fix it. |
| Namespace exists / Cannot create | Ignore if using `review2_reset.sh`, as it gracefully handles existing namespaces. |
| IP still blocked | Ensure you restarted the engine, or run `unblock <ip>` in the console. |
| Wrong DB file | `review2_reset.sh` will backup the old DB and let the engine start fresh. |
