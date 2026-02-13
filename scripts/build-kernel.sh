#!/usr/bin/env bash
#
# build-kernel.sh — Cross-compile the sandal kernel on a remote aarch64 machine.
#
# Usage: scripts/build-kernel.sh HOST [KERNEL_VERSION]
#
#   HOST             Remote SSH host
#   KERNEL_VERSION   Linux kernel version (auto-detected from kernel.config if omitted)
#
# The script:
#   1. Syncs scripts/kernel.config to the remote build directory
#   2. Downloads the kernel source on the remote if not present
#   3. Builds the ARM64 Image using the remote toolchain
#   4. Syncs the resulting Image back as vmlinux-sandal

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST="${1:?Usage: $0 HOST [KERNEL_VERSION]}"
REMOTE_DIR="~/sandal"
CONFIG="$SCRIPT_DIR/kernel.config"
OUTPUT="$PROJECT_DIR/vmlinux-sandal"

# Auto-detect kernel version from the config file header.
# Expects a line like: # Linux/arm64 6.12.13 Kernel Configuration
detect_kernel_version() {
    sed -n 's/^# Linux\/arm64 \([0-9.]*\) Kernel Configuration/\1/p' "$CONFIG"
}

KVER="${2:-$(detect_kernel_version)}"
if [ -z "$KVER" ]; then
    echo "Error: Could not detect kernel version from $CONFIG" >&2
    echo "Pass it explicitly: $0 $HOST 6.12.13" >&2
    exit 1
fi

KMAJOR="${KVER%%.*}"
KSRC="linux-$KVER"

info()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
error() { printf "\033[1;31mERR\033[0m %s\n" "$*" >&2; }

info "Building kernel $KVER on $HOST"

# Step 1: Sync config to remote
info "Syncing kernel config to $HOST:$REMOTE_DIR/"
ssh "$HOST" "mkdir -p $REMOTE_DIR"
rsync -az "$CONFIG" "$HOST:$REMOTE_DIR/kernel.config"

# Step 2: Download kernel source on remote if not present
info "Ensuring kernel source is available..."
ssh "$HOST" "
    cd $REMOTE_DIR
    if [ ! -d $KSRC ]; then
        echo 'Downloading linux-$KVER...'
        curl -fSL --progress-bar \
            https://cdn.kernel.org/pub/linux/kernel/v${KMAJOR}.x/${KSRC}.tar.xz \
            -o ${KSRC}.tar.xz
        tar xf ${KSRC}.tar.xz
        echo 'Source extracted.'
    else
        echo 'Source already present.'
    fi
"

# Step 3: Configure and build
info "Building kernel..."
ssh "$HOST" "
    cd $REMOTE_DIR/$KSRC
    cp ../kernel.config .config
    make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig 2>&1 | tail -1
    make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j\$(nproc) Image 2>&1 | tail -3
"

# Step 4: Sync the Image back
info "Syncing kernel to $OUTPUT"
rsync -az "$HOST:$REMOTE_DIR/$KSRC/arch/arm64/boot/Image" "$OUTPUT"

ok "Kernel $KVER built and saved to vmlinux-sandal ($(du -h "$OUTPUT" | cut -f1 | xargs))"
