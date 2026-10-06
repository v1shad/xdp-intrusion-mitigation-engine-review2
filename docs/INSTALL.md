# Installation Guide

## 1. Install Dependencies

### Fedora
```bash
sudo dnf update -y
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel yaml-cpp-devel sqlite-devel nlohmann-json-devel gcc-c++ make
```

### Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y clang libbpf-dev libelf-dev zlib1g-dev libyaml-cpp-dev libsqlite3-dev nlohmann-json3-dev g++ make
```

## 2. Compile the Project
From the project root directory:
```bash
make clean
make
```
This builds `xdp_prog.bpf.o` (kernel space) and `engine` (user space).

## 3. Verify
Run the preflight check to ensure your real environment is ready:
```bash
sudo ./real_check.sh
```

*(Note: For the optional offline lab rehearsal, refer to `lab/README.md`)*
