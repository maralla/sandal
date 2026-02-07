# Sandal

A high-performance, lightweight sandbox for running untrusted code securely on macOS Apple Silicon.

Sandal executes commands in a hardware-isolated environment with sub-second startup, full network access, and an interactive terminal — all without requiring root privileges.

## Features

- **Fast** — launches and runs your command in under one second
- **Secure** — every execution runs in a dedicated hardware-isolated environment; no shared kernel, no container escapes
- **Flexible** — run shell scripts, Python programs, or any Linux binary; supports interactive REPLs
- **Networked** — built-in TCP/UDP/ICMP/DNS stack with transparent internet access, no bridge or tap configuration needed
- **Portable** — single static binary, no dependencies beyond macOS and an Apple Silicon Mac
- **Unprivileged** — runs entirely in user space, no `sudo` required

## Quick Start

```bash
# Build
cargo build --release
codesign --entitlements sandal.entitlements -s - target/release/sandal --force

# Set up the default kernel and rootfs
scripts/setup-image.sh

# Run a command
./target/release/sandal -- echo "Hello from the sandbox"

# Run Python interactively
./target/release/sandal -- python3

# Fetch a URL
./target/release/sandal -- python3 -c 'import urllib.request; print(urllib.request.urlopen("http://example.com").status)'

# Disable networking
./target/release/sandal --no-network -- python3 -c 'print("offline mode")'
```

## Requirements

- macOS 11.0+ on Apple Silicon (M1/M2/M3/M4)

## License

MIT
