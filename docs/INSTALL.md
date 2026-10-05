# Installation Guide

## 1. Install Dependencies

### Fedora
```bash
sudo dnf update -y
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel yaml-cpp-devel sqlite-devel gcc-c++ make
```

### Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y clang libbpf-dev libelf-dev zlib1g-dev libyaml-cpp-dev libsqlite3-dev g++ make
```

## 2. Compile the Project
From the project root directory:
```bash
make clean
make
```
This builds `xdp_prog.bpf.o` (kernel space) and `engine` (user space).

## 3. Lab Environment Setup
We use a network namespace (`attacker`) connected to the host via a virtual ethernet pair (`veth-host` and `veth-atk`).

To create the lab:
```bash
sudo ./setup_lab.sh
```
*This configures `10.10.0.1` on the host and `10.10.0.2` in the attacker namespace.*

To reset the lab state entirely, run:
```bash
sudo ./review2_reset.sh
```

## 4. Teardown
To safely tear down the lab environment and remove the interfaces:
```bash
sudo ./teardown_lab.sh
```
