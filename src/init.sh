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

# Signal exit code to host.
# Primary: write EXIT_MARKER via the normal UART path (works on cold boot).
# Fallback: write exit code directly to a special MMIO register at
# UART_BASE + 0x100 that the VMM intercepts.  This bypasses the
# TTY layer and works even after snapshot restore when the serial
# driver's interrupt-driven TX path may be broken.
echo "{EXIT_MARKER}$SANDAL_RC"
devmem 0x09000100 32 "$SANDAL_RC" 2>/dev/null

# Power off
exec /sbin/poweroff -f
