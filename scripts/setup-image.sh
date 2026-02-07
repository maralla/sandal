#!/usr/bin/env bash
#
# setup-image.sh — Download the kernel and build a Python rootfs from pre-built packages
#
# Usage: scripts/setup-image.sh
#
# Downloads a Firecracker-compatible aarch64 kernel and creates an Alpine Linux
# rootfs with Python 3 by fetching pre-built packages from the Alpine CDN.
# No Docker or root privileges required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

KERNEL_DIR="$PROJECT_DIR/kernels"
KERNEL_PATH="$KERNEL_DIR/vmlinux"
ROOTFS_DIR="$PROJECT_DIR/rootfs"

ALPINE_VERSION="3.21"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ARCH="aarch64"
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/aarch64/kernels/vmlinux"

# Python 3 and its runtime dependencies (Alpine package names)
PYTHON_PACKAGES=(
    python3
    python3-pyc
    libffi
    gdbm
    xz-libs
    mpdecimal
    readline
    ncurses-libs
    sqlite-libs
    libbz2
    libexpat
)

# --- Helpers ---

info()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$*"; }
error() { printf "\033[1;31mERR\033[0m %s\n" "$*" >&2; }

# --- Download kernel ---

setup_kernel() {
    if [ -f "$KERNEL_PATH" ]; then
        ok "Kernel already exists at kernels/vmlinux, skipping"
        return
    fi

    info "Downloading Firecracker kernel for aarch64..."
    mkdir -p "$KERNEL_DIR"
    curl -fSL --progress-bar -o "$KERNEL_PATH" "$KERNEL_URL"
    ok "Kernel saved to kernels/vmlinux ($(du -h "$KERNEL_PATH" | cut -f1 | xargs))"
}

# --- Build rootfs from pre-built Alpine packages ---

# Parse APKINDEX to find the filename for a given package name.
# APKINDEX format: blocks separated by blank lines, P: = name, V: = version.
lookup_apk_filename() {
    local index_file="$1"
    local pkg_name="$2"

    awk -v pkg="$pkg_name" '
        /^$/ { if (found) { print name "-" ver ".apk"; done=1; exit } name=""; ver=""; found=0 }
        /^P:/ { name = substr($0, 3); if (name == pkg) found=1 }
        /^V:/ { ver = substr($0, 3) }
        END   { if (found && !done) print name "-" ver ".apk" }
    ' "$index_file"
}

setup_rootfs() {
    if [ -d "$ROOTFS_DIR" ] && [ -f "$ROOTFS_DIR/usr/bin/python3" ]; then
        ok "Rootfs already exists at rootfs/ with Python, skipping"
        return
    fi

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" EXIT

    # Step 1: Download Alpine minirootfs
    local minirootfs_url="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ARCH}.tar.gz"
    info "Downloading Alpine ${ALPINE_VERSION} minirootfs..."
    curl -fSL --progress-bar -o "$tmpdir/minirootfs.tar.gz" "$minirootfs_url"

    # Step 2: Extract minirootfs
    mkdir -p "$ROOTFS_DIR"
    tar xzf "$tmpdir/minirootfs.tar.gz" -C "$ROOTFS_DIR"
    ok "Alpine minirootfs extracted"

    # Step 3: Download APKINDEX
    info "Fetching package index..."
    curl -fsSL -o "$tmpdir/APKINDEX.tar.gz" \
        "${ALPINE_MIRROR}/v${ALPINE_VERSION}/main/${ARCH}/APKINDEX.tar.gz"
    tar xzf "$tmpdir/APKINDEX.tar.gz" -C "$tmpdir" APKINDEX

    # Step 4: Download and extract Python packages
    info "Installing Python 3 and dependencies..."
    local pkg_dir="$tmpdir/packages"
    mkdir -p "$pkg_dir"

    for pkg in "${PYTHON_PACKAGES[@]}"; do
        local filename
        filename="$(lookup_apk_filename "$tmpdir/APKINDEX" "$pkg")"
        if [ -z "$filename" ]; then
            error "Package '$pkg' not found in APKINDEX"
            exit 1
        fi

        local url="${ALPINE_MIRROR}/v${ALPINE_VERSION}/main/${ARCH}/${filename}"
        printf "  %s ... " "$pkg"
        curl -fsSL -o "$pkg_dir/$filename" "$url"

        # APK files are concatenated gzip streams; bsdtar handles them.
        # Exclude APK metadata files, extract only the actual filesystem content.
        tar xzf "$pkg_dir/$filename" -C "$ROOTFS_DIR" \
            --exclude '.PKGINFO' --exclude '.SIGN.*' --exclude '.pre-*' \
            --exclude '.post-*' --exclude '.trigger' 2>/dev/null || true
        printf "ok\n"
    done

    ok "Rootfs created at rootfs/ ($(du -sh "$ROOTFS_DIR" | cut -f1 | xargs))"
}

# --- Main ---

main() {
    info "Setting up sandal kernel and rootfs..."
    echo

    setup_kernel
    setup_rootfs

    echo
    ok "Setup complete! You can now run:"
    echo "  ./target/release/sandal -- echo 'Hello from the sandbox'"
    echo "  ./target/release/sandal -- python3"
}

main "$@"
