# Sandal

A high-performance, lightweight sandbox for running untrusted code securely.

Sandal executes commands in a hardware-isolated environment with sub-second startup, full network access, and an interactive terminal — all without requiring root privileges.

It runs on two hypervisor backends:

- **macOS** on Apple Silicon via Hypervisor.framework (software GIC, see `docs/vmm-spec.md`)
- **Linux** on arm64 via KVM (in-kernel GICv3/vtimer)

## Features

- **Fast** — launches and runs your command in under one second
- **Secure** — every execution runs in a dedicated hardware-isolated environment
- **Flexible** — run shell scripts, or any Linux binary
- **Unprivileged** — runs entirely in user space, no `sudo` required

## Quick Start

```bash
# Build
make

# Run a command
./target/release/sandal -- echo "Hello from the sandbox"

# Run sh interactively
./target/release/sandal -- sh

# Fetch a URL
./target/release/sandal -- wget http://example.com

# Disable networking
./target/release/sandal --no-network -- wget https://example.com

# Share a host directory (read/write) with the VM
./target/release/sandal --share /tmp/data:/mnt/data -- ls /mnt/data
```

## Requirements

- macOS 11.0+ on Apple Silicon (M1/M2/M3/M4), or
- Linux on arm64 with `/dev/kvm` available (user must have access, e.g. be in
  the `kvm` group). No root privileges required.

## License

MIT
