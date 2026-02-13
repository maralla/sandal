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
# Detect whether /dev/vdb has a usable disk (>2MB = --disk-size was given).
# The VMM always creates a small 1MB stub at /dev/vdb during cold boot so
# the kernel probes the device.  On warm restore with --disk-size, the VMM
# swaps in a real disk and triggers a config-change interrupt to resize it.
# This runs AFTER the snapshot point so the same snapshot is reusable
# regardless of whether --disk-size is supplied.
VDB_SECTORS=0
if [ -b /dev/vdb ]; then
    # Read device size in 512-byte sectors from sysfs.
    # On warm restore with --disk-size, the VMM triggers a virtio
    # config-change to resize /dev/vdb.  The kernel processes this
    # asynchronously, so retry briefly to let the resize complete.
    # Each retry forks (cat), yielding CPU to the kworker thread.
    N=0
    while [ "$N" -lt 5 ]; do
        VDB_SECTORS=$(cat /sys/block/vdb/size 2>/dev/null || echo 0)
        [ "$VDB_SECTORS" -gt 4096 ] 2>/dev/null && break
        N=$((N + 1))
    done
fi

mkdir -p /mnt/lower /mnt/overlay /mnt/tmpupper /mnt/upper_disk 2>/dev/null
mount --bind / /mnt/lower 2>/dev/null

OVL_OK=0
if [ "$VDB_SECTORS" -gt 4096 ] 2>/dev/null; then
    # /dev/vdb is larger than 2MB — use it as the overlay upper layer
    mkdir -p /mnt/upper_disk 2>/dev/null
    mount -t ext2 /dev/vdb /mnt/upper_disk 2>/dev/null
    mkdir -p /mnt/upper_disk/upper /mnt/upper_disk/work 2>/dev/null
    mount -t overlay overlay \
        -o lowerdir=/mnt/lower,upperdir=/mnt/upper_disk/upper,workdir=/mnt/upper_disk/work \
        /mnt/overlay 2>/dev/null && OVL_OK=1
else
    # Default: tmpfs (RAM) upper layer
    mount -t tmpfs tmpfs /mnt/tmpupper 2>/dev/null
    mkdir -p /mnt/tmpupper/upper /mnt/tmpupper/work 2>/dev/null
    mount -t overlay overlay \
        -o lowerdir=/mnt/lower,upperdir=/mnt/tmpupper/upper,workdir=/mnt/tmpupper/work \
        /mnt/overlay 2>/dev/null && OVL_OK=1
fi

if [ "$OVL_OK" = "1" ]; then
    mkdir -p /mnt/overlay/mnt/root 2>/dev/null
    cd /mnt/overlay
    pivot_root . mnt/root 2>/dev/null
    # Re-mount essential filesystems in the new overlay root
    mount -t proc proc /proc 2>/dev/null
    mount -t sysfs sysfs /sys 2>/dev/null
    mount -t devtmpfs devtmpfs /dev 2>/dev/null
    mount -t tmpfs tmpfs /tmp 2>/dev/null
    cd /
fi

# Read mount setup + command from the UART.  The host writes two lines:
#   1. Mount commands (or empty for no shares)
#   2. Shell-escaped command line
IFS= read -r SANDAL_MOUNT_SETUP
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
