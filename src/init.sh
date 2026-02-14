#!/bin/sh
# Sandal VM init — auto-generated

# Mount essential filesystems
/bin/mount -t proc proc /proc 2>/dev/null
/bin/mount -t sysfs sysfs /sys 2>/dev/null
/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/mount -t tmpfs tmpfs /tmp 2>/dev/null

# Load virtio modules if compiled as modules (needed for some kernels
# like Debian's that don't build them in).  Order matters for deps:
# failover → net_failover → virtio_net.
KVER=$(uname -r)
KMOD="/lib/modules/$KVER/kernel"
for mod in \
    drivers/virtio/virtio_mmio.ko \
    net/core/failover.ko \
    drivers/net/net_failover.ko \
    drivers/net/virtio_net.ko \
    drivers/char/hw_random/virtio-rng.ko \
    drivers/block/virtio_blk.ko \
    fs/fuse/fuse.ko \
    fs/fuse/virtiofs.ko \
; do
    [ -f "$KMOD/$mod" ] && insmod "$KMOD/$mod" 2>/dev/null
done

# Set system clock to host time (needed for TLS certificate validation)
date -s "@{now}" >/dev/null 2>&1

# Set up basic environment
export HOME=/root
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=linux
cd /
{net_setup}
# Determine controlling terminal device before BOOT_MARKER
# (reading /sys after boot-complete would show on stdout)
CTTY=/dev/$(cat /sys/class/tty/console/active 2>/dev/null)

# Disable echo BEFORE signaling boot complete, so the command
# line sent by the host is not echoed back to stdout.
stty -echo 2>/dev/null

# Signal boot complete to host (triggers direct UART output)
echo "{BOOT_MARKER}"

# Signal snapshot-ready to VMM via BRK instruction.
# sandal-signal executes BRK #0x5D1 which the VMM traps from EL0.
# At this point IRQs are enabled and no kernel locks are held,
# giving the VMM a clean, deterministic snapshot point.
/usr/sbin/sandal-signal 2>/dev/null

# --- Set up overlayfs writable root (post-snapshot) ---
# The VMM always creates a small 1MB stub at DATA_DEV during cold boot so
# the kernel probes the device.  This runs AFTER the snapshot point so the
# same snapshot is reusable regardless of --disk-size or --layer flags.
#
# Modes (set via SANDAL_DISK_MODE in the mount setup line):
#   disk  — DATA_DEV is a real ext2 overlay disk (--disk-size)
#   layer — DATA_DEV contains raw gzip-compressed tar data (--layer)
#   (empty) — default tmpfs overlay

# Mount point / device constants (values injected from Rust — see initramfs.rs)
MNT_LOWER={MNT_LOWER}
MNT_OVL={MNT_OVL}
MNT_TMP={MNT_TMP}
MNT_DISK={MNT_DISK}
DATA_DEV={DATA_DEV}

mkdir -p "$MNT_LOWER" "$MNT_OVL" "$MNT_TMP" "$MNT_DISK" 2>/dev/null
mount --bind / "$MNT_LOWER" 2>/dev/null

# Read mount setup (line 1 of UART) early — it may set SANDAL_DISK_MODE.
# Extract the disk mode without running the full eval (virtiofs mounts need
# to happen after pivot_root).
IFS= read -r SANDAL_MOUNT_SETUP
case "$SANDAL_MOUNT_SETUP" in
    *SANDAL_DISK_MODE=disk*) SANDAL_DISK_MODE=disk ;;
    *SANDAL_DISK_MODE=layer*) SANDAL_DISK_MODE=layer ;;
esac

# Wait briefly for the virtio config-change resize to complete (disk/layer).
if [ -n "$SANDAL_DISK_MODE" ] && [ -b "$DATA_DEV" ]; then
    N=0
    while [ "$N" -lt 5 ]; do
        VDB_SECTORS=$(cat "/sys/block/${{DATA_DEV#/dev/}}/size" 2>/dev/null || echo 0)
        # 4096 sectors = 2MB, larger than the initial 1MB stub
        [ "$VDB_SECTORS" -gt 4096 ] 2>/dev/null && break
        N=$((N + 1))
    done
fi

OVL_OK=0
if [ "$SANDAL_DISK_MODE" = "disk" ] && [ -b "$DATA_DEV" ]; then
    # --disk-size: DATA_DEV is a real ext2 overlay disk.
    mount -t ext2 "$DATA_DEV" "$MNT_DISK" 2>/dev/null
    mkdir -p "$MNT_DISK/upper" "$MNT_DISK/work" 2>/dev/null
    OVL_UPPER="$MNT_DISK/upper"
    OVL_WORK="$MNT_DISK/work"
else
    # tmpfs (RAM) upper layer — used for both --layer and default mode.
    mount -t tmpfs tmpfs "$MNT_TMP" 2>/dev/null
    mkdir -p "$MNT_TMP/upper" "$MNT_TMP/work" 2>/dev/null
    # --layer: extract gzip-compressed tar from DATA_DEV into the upper dir.
    # The VMM writes raw .layer (tar.gz) bytes starting at byte 0 of DATA_DEV.
    if [ "$SANDAL_DISK_MODE" = "layer" ] && [ -b "$DATA_DEV" ]; then
        gzip -d < "$DATA_DEV" 2>/dev/null | tar xf - -C "$MNT_TMP/upper" 2>/dev/null
    fi
    OVL_UPPER="$MNT_TMP/upper"
    OVL_WORK="$MNT_TMP/work"
fi
mount -t overlay overlay \
    -o "lowerdir=$MNT_LOWER,upperdir=$OVL_UPPER,workdir=$OVL_WORK" \
    "$MNT_OVL" 2>/dev/null && OVL_OK=1

if [ "$OVL_OK" = "1" ]; then
    mkdir -p "$MNT_OVL/mnt/root" 2>/dev/null
    cd "$MNT_OVL"
    pivot_root . mnt/root 2>/dev/null
    # Re-mount essential filesystems in the new overlay root
    mount -t proc proc /proc 2>/dev/null
    mount -t sysfs sysfs /sys 2>/dev/null
    mount -t devtmpfs devtmpfs /dev 2>/dev/null
    mount -t tmpfs tmpfs /tmp 2>/dev/null
    cd /
fi

# Evaluate mount setup (already read before overlay setup).
# Then read the command line (line 2 from UART).
eval "$SANDAL_MOUNT_SETUP"
IFS= read -r SANDAL_CMD_LINE

# Parse the command line back into positional parameters
eval "set -- $SANDAL_CMD_LINE"

# Re-enable echo.  The stty -echo above was only needed to suppress
# the injected command line; now that it has been read, restore echo
# so interactive programs (shells, cat, python, etc.) work properly.
stty echo 2>/dev/null

# Set up a controlling terminal.  PID 1 inherits session 0 from the
# kernel and is NOT a session leader, so open() on a TTY will not make
# it the controlling terminal.  sandal-ctty calls setsid(), opens the
# real TTY device, sets it as the controlling terminal via TIOCSCTTY,
# redirects stdio, and exec's the command.
# /dev/console itself always forces O_NOCTTY, so we use the real device.
# We also resolve the command to an absolute path because execve(2)
# does not search PATH.  `which` returns the filesystem path (not
# builtin names like `command -v` does).
SANDAL_CMD=$(which "$1" 2>/dev/null || echo "$1")
shift
if [ ! -x "$SANDAL_CMD" ]; then
    echo "Unknown command: $SANDAL_CMD" >&2
    SANDAL_RC=127
elif [ -c "$CTTY" ]; then
    /usr/sbin/sandal-ctty "$CTTY" "$SANDAL_CMD" "$@"
    SANDAL_RC=$?
else
    "$SANDAL_CMD" "$@"
    SANDAL_RC=$?
fi

# Signal exit code to host via UART.
echo "{EXIT_MARKER}$SANDAL_RC"

# Power off
exec /sbin/poweroff -f
