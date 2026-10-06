# Usage Guide

## Starting the Engine
Start the engine by specifying the network interface, eBPF object file, log file to tail, and optional safety overrides.
```bash
sudo ./engine wlp2s0 xdp_prog.bpf.o /var/log/secure --ttl 60
```
*Expected Output:*
```text
[engine] effective TTL: 60s
[engine] XDP attached mode: generic
[engine] Commands: allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | alerts | quit
```

## Console Commands

### block `<ip>`
Manually block an IP address.
```text
block 10.10.0.2
[BLOCKED] 10.10.0.2 (manual)
```

### unblock `<ip>`
Remove an IP address from the blocklist.
```text
unblock 10.10.0.2
[UNBLOCKED] 10.10.0.2
```

### allow `<ip>`
Whitelist an IP address so it is never dropped.
```text
allow 10.10.0.2
[ALLOWED] 10.10.0.2
```

### unallow `<ip>`
Remove an IP from the whitelist.
```text
unallow 10.10.0.2
[UNALLOWED] 10.10.0.2
```

### list
Print the current contents of the blocklist.
```text
list
  10.10.0.2  dropped=450 expires in 58s
  (1 blocked IPs)
```

### stats
Print the global XDP drop and pass counters.
```text
stats
  packets dropped=450  passed=12
```

### alerts
Print the last 10 generated alerts from the SQLite database.
```text
alerts
  [2026-10-05T12:00:00Z] SSH_BRUTE_FORCE | IP: 10.10.0.2 | Action: block
```

### quit
Detach the eBPF program and shut down the engine cleanly.
```text
quit
[engine] shutting down, detaching XDP
```
