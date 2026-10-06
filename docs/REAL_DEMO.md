# Real-Network Demo Procedure

## 1. Preparation
1. **Enable SSH and Logging:**
   ```bash
   sudo systemctl enable --now sshd
   sudo systemctl enable --now rsyslog
   ```
2. **Check Password Authentication:**
   Verify `sshd -T | grep passwordauthentication` outputs `passwordauthentication yes`.
3. **Find IPs:**
   Determine your interface name (e.g., `wlp2s0` or `enp3s0`) and your IP address (`ip addr show`). Note your friend's laptop IP on the same network.
4. **Verify Connectivity:**
   Have your friend `ping` your IP. Ensure it replies.

## 2. Observe a Real Log Entry
Tail the log while your friend attempts a failed SSH login:
```bash
sudo tail -f /var/log/secure   # On Ubuntu, use /var/log/auth.log
```
Have your friend run: `ssh -o PubkeyAuthentication=no nosuchuser@<YOUR_IP>` and type a wrong password. You should see a "Failed password" line appear.

## 3. Run the Engine
1. **Preflight Check:**
   ```bash
   sudo ./real_check.sh
   ```
2. **Start the Engine:**
   ```bash
   sudo ./real_run.sh <your_interface>
   ```

## 4. The Attack
Have your friend rapidly execute the SSH command and enter wrong passwords (or use a script/loop) to generate 5+ failures within 60 seconds.

## 5. The Proof
- **Attacker's View:** Your friend's SSH connection will freeze. Their `ping <YOUR_IP>` will time out.
- **Your View (tcpdump):** In a separate terminal, run:
  ```bash
  sudo tcpdump -ni <your_interface> host <FRIEND_IP>
  ```
  You will see NO incoming packets from their IP because XDP drops them before `tcpdump` can see them.
- **Your View (bpftool):**
  ```bash
  sudo bpftool map dump name blocked_ips
  ```
  You will see their IP address in the kernel map.
- **Engine Console:**
  Type `list` and `stats` to see the block record and drop counter increasing as they try to ping you.

## 6. Recovery
- **Wait:** The default TTL is 60 seconds. After 60 seconds, the block will expire automatically.
- **Manual Unblock:** Type `unblock <FRIEND_IP>` in the engine console.

## 7. Allowlist Test
1. Type `allow <FRIEND_IP>` in the engine console.
2. Have your friend attack again. The engine will log an alert but refuse to block the allowlisted IP.

## 8. Cleanup
1. Type `quit` in the engine console.
2. Run cleanup to verify XDP is detached:
   ```bash
   sudo ./real_cleanup.sh <your_interface>
   ```
