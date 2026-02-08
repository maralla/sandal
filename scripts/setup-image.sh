#!/usr/bin/env bash
#
# setup-image.sh — Download kernels and build a Python rootfs from pre-built packages
#
# Usage: scripts/setup-image.sh
#
# Downloads a Firecracker-compatible aarch64 kernel, a Debian 6.12 kernel (with
# virtiofs support), and creates an Alpine Linux rootfs with Python 3 by fetching
# pre-built packages from the Alpine CDN.

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

# Debian kernel (6.12, supports virtiofs)
DEBIAN_KVER="6.12.63+deb13-arm64"
DEBIAN_KERNEL_PATH="$KERNEL_DIR/vmlinux-debian"
DEBIAN_PKG="linux-image-${DEBIAN_KVER}-unsigned_6.12.63-1_arm64.deb"
DEBIAN_PKG_URL="https://deb.debian.org/debian/pool/main/l/linux/${DEBIAN_PKG}"

# Virtio modules needed from the Debian kernel (compiled as modules, not built-in)
DEBIAN_MODULES=(
    "kernel/drivers/virtio/virtio_mmio.ko"
    "kernel/drivers/net/virtio_net.ko"
    "kernel/drivers/block/virtio_blk.ko"
    "kernel/drivers/char/hw_random/virtio-rng.ko"
)

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

# --- Download Firecracker kernel ---

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

# --- Download Debian kernel + modules ---

setup_debian_kernel() {
    local need_kernel=false
    local need_modules=false

    if [ ! -f "$DEBIAN_KERNEL_PATH" ]; then
        need_kernel=true
    else
        ok "Debian kernel already exists at kernels/vmlinux-debian, skipping"
    fi

    # Check if modules are installed
    local mod_base="$ROOTFS_DIR/lib/modules/$DEBIAN_KVER"
    if [ ! -f "$mod_base/kernel/drivers/virtio/virtio_mmio.ko" ]; then
        need_modules=true
    else
        ok "Debian kernel modules already installed, skipping"
    fi

    if [ "$need_kernel" = false ] && [ "$need_modules" = false ]; then
        return
    fi

    local tmpdir
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" RETURN

    info "Downloading Debian ${DEBIAN_KVER} kernel package..."
    curl -fSL --progress-bar -o "$tmpdir/linux-image.deb" "$DEBIAN_PKG_URL"

    # Extract the deb (ar archive containing data.tar.xz)
    (cd "$tmpdir" && ar x linux-image.deb data.tar.xz)

    # Extract kernel image
    if [ "$need_kernel" = true ]; then
        info "Extracting Debian kernel..."
        mkdir -p "$KERNEL_DIR"
        tar xf "$tmpdir/data.tar.xz" -C "$tmpdir" "./boot/vmlinuz-${DEBIAN_KVER}"
        cp "$tmpdir/boot/vmlinuz-${DEBIAN_KVER}" "$DEBIAN_KERNEL_PATH"
        ok "Debian kernel saved to kernels/vmlinux-debian ($(du -h "$DEBIAN_KERNEL_PATH" | cut -f1 | xargs))"
    fi

    # Extract and install kernel modules
    if [ "$need_modules" = true ]; then
        info "Installing Debian kernel modules..."
        for mod in "${DEBIAN_MODULES[@]}"; do
            local src="./usr/lib/modules/${DEBIAN_KVER}/${mod}.xz"
            tar xf "$tmpdir/data.tar.xz" -C "$tmpdir" "$src" 2>/dev/null || {
                error "Module not found in package: $mod"
                continue
            }
            local dest_dir="$ROOTFS_DIR/lib/modules/${DEBIAN_KVER}/$(dirname "$mod")"
            mkdir -p "$dest_dir"
            xz -dk "$tmpdir/usr/lib/modules/${DEBIAN_KVER}/${mod}.xz"
            cp "$tmpdir/usr/lib/modules/${DEBIAN_KVER}/${mod}" "$dest_dir/"
            printf "  %s ... ok\n" "$(basename "$mod")"
        done
        ok "Kernel modules installed to rootfs/lib/modules/${DEBIAN_KVER}/"
    fi
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
    info "Setting up sandal kernels and rootfs..."
    echo

    setup_kernel
    setup_rootfs
    setup_debian_kernel

    echo
    ok "Setup complete! You can now run:"
    echo "  ./target/release/sandal -- echo 'Hello from the sandbox'"
    echo "  ./target/release/sandal -- python3"
    echo "  ./target/release/sandal --kernel kernels/vmlinux-debian --share /tmp:/mnt/host -- ls /mnt/host"
}

main "$@"
