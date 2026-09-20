#!/usr/bin/env bash
#
# build-kernel-x86.sh — Build the x86_64 guest kernel locally.
#
# Produces `vmlinux-sandal-x86`: a stripped ELF vmlinux with the PVH
# 32-bit entry note, booted directly by the VMM (no firmware, no bootloader).
# The config is x86_64_defconfig + scripts/kernel-x86.fragment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KVER="$(sed -n 's/^# Linux\/x86 6\.\([0-9.]*\) Kernel Configuration/\1/p' \
    "$SCRIPT_DIR/kernel-x86.fragment" 2>/dev/null || true)"
KVER="${KVER:-6.12.70}"   # keep in sync with scripts/kernel-x86.fragment's base
KSRC="$PROJECT_DIR/kernel-build/linux-$KVER"
OUTPUT="$PROJECT_DIR/vmlinux-sandal-x86"

command -v gcc >/dev/null || { echo "gcc is required"; exit 1; }
command -v flex >/dev/null || { echo "flex is required"; exit 1; }
command -v bison >/dev/null || { echo "bison is required"; exit 1; }

if [ ! -d "$KSRC" ]; then
    mkdir -p "$PROJECT_DIR/kernel-build"
    echo "Downloading linux-$KVER..."
    curl -fSL --progress-bar \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz" \
        -o "$PROJECT_DIR/kernel-build/linux-$KVER.tar.xz"
    tar xf "$PROJECT_DIR/kernel-build/linux-$KVER.tar.xz" -C "$PROJECT_DIR/kernel-build"
fi

cd "$KSRC"
make O=build x86_64_defconfig 2>&1 | tail -1

# Apply the fragment with scripts/config (never touches the source root; a
# stray .config there makes O= builds refuse to run).
while read -r line; do
    case "$line" in
        CONFIG_*=m) "$KSRC/scripts/config" --file build/.config --module "${line%%=*}" ;;
        CONFIG_*=y) "$KSRC/scripts/config" --file build/.config --enable "${line%%=*}" ;;
        "# CONFIG_"*" is not set")
            sym="${line#\# CONFIG_}"; sym="${sym%% is*}"
            "$KSRC/scripts/config" --file build/.config --disable "$sym" ;;
    esac
done < "$SCRIPT_DIR/kernel-x86.fragment"
make O=build olddefconfig 2>&1 | tail -1
make O=build -j"$(nproc)" vmlinux 2>&1 | tail -1
strip build/vmlinux
cp build/vmlinux "$OUTPUT"
echo "Wrote $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
