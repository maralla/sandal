#!/usr/bin/env bash
#
# build-kernel.sh — Build the sandal guest kernel for one architecture.
#
# Usage:
#   scripts/build-kernel.sh aarch64 HOST [KERNEL_VERSION]
#   scripts/build-kernel.sh x86_64 [KERNEL_VERSION]
#
# Both forms write `vmlinux-sandal-<arch>` into the project root.
#
# aarch64 (alias: arm64)
#   Cross-compiles on a remote aarch64 Linux host over SSH — a macOS machine
#   cannot build an arm64 Linux kernel natively — then syncs the resulting
#   `Image` back.  HOST is the SSH target; KERNEL_VERSION is auto-detected
#   from the "# Linux/arm64 <ver> Kernel Configuration" header in
#   scripts/kernel.config when omitted.
#
# x86_64 (aliases: x86, amd64)
#   Builds locally from allnoconfig + scripts/kernel-x86.fragment (a COMPLETE
#   minimal config, not a delta) and produces a stripped ELF vmlinux with the
#   PVH 32-bit entry note, booted directly by the VMM (no firmware, no
#   bootloader).  Requires gcc, flex and bison.  KERNEL_VERSION defaults to
#   6.12.70 (keep in sync with the fragment's base).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

info()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
error() { printf "\033[1;31mERR\033[0m %s\n" "$*" >&2; }

usage() {
    cat <<'EOF'
Usage:
  scripts/build-kernel.sh aarch64 HOST [KERNEL_VERSION]
  scripts/build-kernel.sh x86_64 [KERNEL_VERSION]

Output: vmlinux-sandal-<arch> in the project root.
EOF
}

ARCH="${1:-}"
case "$ARCH" in
    aarch64|arm64)    ARCH=aarch64 ;;
    x86_64|x86|amd64) ARCH=x86_64 ;;
    -h|--help|"")     usage; exit 0 ;;
    *) error "unknown architecture: $ARCH"; usage; exit 1 ;;
esac
shift

OUTPUT="$PROJECT_DIR/vmlinux-sandal-$ARCH"

build_aarch64() {
    local host="${1:?Usage: $0 aarch64 HOST [KERNEL_VERSION]}"
    local config="$SCRIPT_DIR/kernel.config"
    local remote_dir="~/sandal"

    local kver="${2:-$(sed -n 's/^# Linux\/arm64 \([0-9.]*\) Kernel Configuration/\1/p' "$config")}"
    if [ -z "$kver" ]; then
        error "could not detect kernel version from $config"
        echo "Pass it explicitly: $0 aarch64 $host 6.12.70" >&2
        exit 1
    fi
    local kmajor="${kver%%.*}"
    local ksrc="linux-$kver"

    info "Building kernel $kver for aarch64 on $host"

    # Step 1: Sync config to remote
    info "Syncing kernel config to $host:$remote_dir/"
    ssh "$host" "mkdir -p $remote_dir"
    rsync -az "$config" "$host:$remote_dir/kernel.config"

    # Step 2: Download kernel source on remote if not present
    info "Ensuring kernel source is available..."
    ssh "$host" "
        cd $remote_dir
        if [ ! -d $ksrc ]; then
            echo 'Downloading $ksrc...'
            curl -fSL --progress-bar \
                https://cdn.kernel.org/pub/linux/kernel/v${kmajor}.x/${ksrc}.tar.xz \
                -o ${ksrc}.tar.xz
            tar xf ${ksrc}.tar.xz
            echo 'Source extracted.'
        else
            echo 'Source already present.'
        fi
    "

    # Step 3: Configure and build
    info "Building kernel..."
    ssh "$host" "
        cd $remote_dir/$ksrc
        cp ../kernel.config .config
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig 2>&1 | tail -1
        # Force-enable SP804 in case olddefconfig dropped it due to unmet deps.
        if ! grep -q '^CONFIG_ARM_TIMER_SP804=y' .config; then
            echo 'Enabling CONFIG_ARM_TIMER_SP804...'
            scripts/config --set-val HAVE_ARM_TIMER_SP804 y --set-val ARM_TIMER_SP804 y
            make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig 2>&1 | tail -1
        fi
        make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j\$(nproc) Image 2>&1 | tail -3
    "

    # Step 4: Sync the Image back
    info "Syncing kernel to $OUTPUT"
    rsync -az "$host:$remote_dir/$ksrc/arch/arm64/boot/Image" "$OUTPUT"

    ok "Kernel $kver built and saved to $(basename "$OUTPUT") ($(du -h "$OUTPUT" | cut -f1 | xargs))"
}

build_x86_64() {
    local fragment="$SCRIPT_DIR/kernel-x86.fragment"
    local kver="${1:-6.12.70}"   # keep in sync with kernel-x86.fragment's base
    local build_dir="$PROJECT_DIR/kernel-build"
    local ksrc="$build_dir/linux-$kver"

    command -v gcc >/dev/null || { error "gcc is required"; exit 1; }
    command -v flex >/dev/null || { error "flex is required"; exit 1; }
    command -v bison >/dev/null || { error "bison is required"; exit 1; }

    if [ ! -d "$ksrc" ]; then
        mkdir -p "$build_dir"
        info "Downloading linux-$kver..."
        curl -fSL --progress-bar \
            "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$kver.tar.xz" \
            -o "$build_dir/linux-$kver.tar.xz"
        tar xf "$build_dir/linux-$kver.tar.xz" -C "$build_dir"
    fi

    info "Building kernel $kver for x86_64..."
    cd "$ksrc"
    # Minimal base: allnoconfig instead of x86_64_defconfig. The defconfig
    # kernel (hundreds of drivers, ~43MB vmlinux) spends ~800ms booting; the
    # fragment below enables only what the sandal guest needs and boots in
    # tens of milliseconds. The fragment must therefore be a COMPLETE config
    # (architecture basics included), not a delta.
    make O=build allnoconfig 2>&1 | tail -1

    # Apply the fragment with scripts/config (never touches the source root; a
    # stray .config there makes O= builds refuse to run).
    while read -r line; do
        case "$line" in
            CONFIG_*=m) "$ksrc/scripts/config" --file build/.config --module "${line%%=*}" ;;
            CONFIG_*=y) "$ksrc/scripts/config" --file build/.config --enable "${line%%=*}" ;;
            "# CONFIG_"*" is not set")
                sym="${line#\# CONFIG_}"; sym="${sym%% is*}"
                "$ksrc/scripts/config" --file build/.config --disable "$sym" ;;
        esac
    done < "$fragment"
    make O=build olddefconfig 2>&1 | tail -1
    make O=build -j"$(nproc)" vmlinux 2>&1 | tail -1
    strip build/vmlinux
    cp build/vmlinux "$OUTPUT"
    ok "Kernel $kver built and saved to $(basename "$OUTPUT") ($(du -h "$OUTPUT" | cut -f1))"
}

case "$ARCH" in
    aarch64) build_aarch64 "$@" ;;
    x86_64)  build_x86_64 "$@" ;;
esac
