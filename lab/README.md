# Lab Environment

**OPTIONAL offline rehearsal on a virtual network; not the main demo.**

These scripts set up a local virtual network (veth pair and network namespace) for testing the engine without requiring a second physical machine or real network traffic.

## Usage
1. `sudo ./review2_reset.sh` - Resets the lab environment and provides the engine start command.
2. Start the engine using the provided command.
3. `./demo_attack.sh <ip>` - Simulates a brute-force attack by injecting fake log entries.
4. `sudo ./teardown_lab.sh` - Cleans up the virtual interfaces.
