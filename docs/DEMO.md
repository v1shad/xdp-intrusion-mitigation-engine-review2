# 10-Step Demo

1. **Reset the Lab Environment:**
   ```bash
   sudo ./review2_reset.sh
   ```
   *Expected Result:* Prints "READY" and provides the start command. The database and log files are cleared.

2. **Start the Engine:**
   ```bash
   sudo ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log
   ```
   *Expected Result:* Engine starts, outputs initialization logs, and waits for commands.

3. **Verify Baseline Connectivity:**
   In a second terminal:
   ```bash
   sudo ip netns exec attacker ping 10.10.0.1
   ```
   *Expected Result:* Ping responses are received normally.

4. **Simulate an Attack:**
   In a third terminal:
   ```bash
   ./demo_attack.sh 10.10.0.2
   ```
   *Expected Result:* Script injects 6 logs and prints "Successfully injected 6 failed login attempts for 10.10.0.2."

5. **Observe Engine Block:**
   Watch the engine terminal.
   *Expected Result:* Engine outputs an `[ALERT]`, a `[BLOCKED]` message for `10.10.0.2`.

6. **Verify Traffic is Dropped:**
   Look at the continuous ping terminal.
   *Expected Result:* Ping responses stop immediately.

7. **Check Engine Stats:**
   In the engine terminal:
   `stats`
   *Expected Result:* Prints `packets dropped=...` > 0.

8. **Unblock the IP:**
   In the engine terminal:
   `unblock 10.10.0.2`
   *Expected Result:* Engine outputs `[UNBLOCKED] 10.10.0.2`.

9. **Verify Restored Connectivity:**
   Look back at the continuous ping terminal.
   *Expected Result:* Ping responses resume.

10. **Shutdown:**
    In the engine terminal:
    `quit`
    *Expected Result:* Engine detaches XDP and exits cleanly.
