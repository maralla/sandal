# Sandal

A high-performance, lightweight sandbox for running untrusted code securely on macOS Apple Silicon.

Sandal executes commands in a hardware-isolated environment with sub-second startup, full network access, and an interactive terminal — all without requiring root privileges.

## Features

- **Fast** — launches and runs your command in under one second
- **Secure** — every execution runs in a dedicated hardware-isolated environment
- **Flexible** — run shell scripts, or any Linux binary
- **Networked** — built-in TCP/UDP/ICMP/DNS stack with internet access
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
```

## Requirements

- macOS 11.0+ on Apple Silicon (M1/M2/M3/M4)

## License

MIT
