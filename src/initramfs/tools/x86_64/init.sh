#!/bin/sh
# sandal x86_64 guest init

# The kernel forwards unknown cmdline parameters as init argv — drop them.
set --
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
# Terminal type: the boot config passes the host's TERM through (like
# COLS/ROWS); linux (8 colors) is only the fallback. Reassignment below
# (config parse) updates the exported value.
TERM=${TERM:-linux}
export TERM
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp

# ── Parse /etc/sandal.conf (VMM-injected run configuration) ────────────
DISK_MODE=
NETWORK=0
CLOCK=0
SHARES_TEXT=
COLS=80
ROWS=24
while IFS= read -r line; do
    case $line in
        ARG=*) set -- "$@" "${line#ARG=}" ;;
        DISK_MODE=*) DISK_MODE=${line#DISK_MODE=} ;;
        NETWORK=*) NETWORK=${line#NETWORK=} ;;
        CLOCK=*) CLOCK=${line#CLOCK=} ;;
        SHARE=*) SHARES_TEXT="$SHARES_TEXT${line#SHARE=}\n" ;;
        TERM=*) TERM=${line#TERM=} ;;
        COLS=*) COLS=${line#COLS=} ;;
        ROWS=*) ROWS=${line#ROWS=} ;;
    esac
done < /etc/sandal.conf

# ── Wall clock (the VMM snapshots the host time at boot) ──────────────
[ "$CLOCK" != 0 ] && date -s @"$CLOCK" >/dev/null 2>&1

# ── Network: static NAT layout behind the user-space netstack ─────────
if [ "$NETWORK" = 1 ]; then
    ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null
    ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up
    route add default gw 10.0.2.2
    echo nameserver 10.0.2.3 > /etc/resolv.conf
fi

# ── Overlayfs root (lower = pristine rootfs, upper = tmpfs or vdb) ────
mkdir -p /mnt/lower /mnt/overlay /mnt/tmpupper /mnt/diskupper
mount --bind / /mnt/lower
if [ "$DISK_MODE" = disk ]; then
    mount -t ext2 /dev/vdb /mnt/diskupper
    mkdir -p /mnt/diskupper/upper /mnt/diskupper/work
    UPPER=/mnt/diskupper/upper
    WORK=/mnt/diskupper/work
else
    mount -t tmpfs tmpfs /mnt/tmpupper
    mkdir -p /mnt/tmpupper/upper /mnt/tmpupper/work
    UPPER=/mnt/tmpupper/upper
    WORK=/mnt/tmpupper/work
fi
mount -t overlay overlay -o lowerdir=/mnt/lower,upperdir=$UPPER,workdir=$WORK /mnt/overlay

cd /mnt/overlay
mkdir -p mnt/root
pivot_root . mnt/root

# Re-mount essentials on the new root. devtmpfs is a single instance, so
# the pre-pivot mount is MOVED; the rest are re-mounted fresh.
mount --move /mnt/root/dev /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp

# /dev/fd and /dev/std* are not provided by devtmpfs: alias them to the
# per-process /proc/self/fd entries. bash process substitution (`<(...)`) and
# many install scripts open /dev/fd explicitly.
ln -sf /proc/self/fd /dev/fd
ln -sf /proc/self/fd/0 /dev/stdin
ln -sf /proc/self/fd/1 /dev/stdout
ln -sf /proc/self/fd/2 /dev/stderr

# PTYs: tmux/screen/shells-with-job-control need the devpts mount for
# /dev/pts (devtmpfs provides /dev/ptmx but not the pts filesystem).
# newinstance: a private devpts instance whose ptmx WORKS — the pty lands
# in THIS instance, so /dev/pts/ptmx and TIOCGPTPEER give the master's
# own slave (a plain compat mount's ptmx is non-functional, and the pty
# would land in a different instance than the slave path resolves in).
mkdir -p /dev/pts
mount -t devpts devpts -o newinstance /dev/pts 2>/dev/null
# Make /dev/ptmx resolve INTO the devpts instance (the distro layout):
# devtmpfs's own ptmx node allocates ptys in a different devpts instance
# than /dev/pts resolves in, so the master and the slave path never meet.
# A symlink makes every ptmx open land in THIS instance.
rm -f /dev/ptmx 2>/dev/null
ln -sf pts/ptmx /dev/ptmx 2>/dev/null

# ── Virtiofs shares (--share host:guest) ──────────────────────────────
printf '%b' "$SHARES_TEXT" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    tag=${line%%:*}
    path=${line#*:}
    mkdir -p "$path"
    mount -t virtiofs "$tag" "$path"
done

cd /root

# ── Run the command on the session transport ──────────────────────────
# The console device is init/kernel output only — never a session: no
# console-session fallback exists anymore, so nothing here configures it.
# The crafted helper has no PATH search — resolve the command first.
#
# The session transport: the virtio-console host device port
# (/dev/vport*p1 — the chardev the multiport console device creates),
# bridged to a pty by /bin/portagent — real tty semantics (job control,
# signals, line editing) at port throughput. THE session: no fallback
# transport exists. The crafted helper has no PATH search — resolve the
# command first.
CMD="$(command -v "$1")"
[ -n "$CMD" ] || CMD="$1"
# busybox's `command -v` prints the bare applet name for shell builtins
# (true, false, echo) — a relative path execve(2) refuses (ENOENT: no cwd
# search). Force an absolute path: applet-name hits are the busybox
# symlink farm, /bin first.
case "$CMD" in
    /*) ;;
    *) CMD="/bin/$CMD" ;;
esac
shift
PORT=
for p in /dev/vport*p1; do
    [ -c "$p" ] && PORT=$p && break
done
if [ -n "$PORT" ] && [ -x /bin/portagent ]; then
    # Tell the VMM the session layout (the token-authenticated marker;
    # each stream's own filter suppresses the line like the exit protocol):
    # the WHOLE session — input, echo, and output — rides the host device
    # port (the portagent bridges a pty to it: real tty semantics at port
    # throughput). Host stdin must move to the port RX queue. ONE copy,
    # on the port: the control sequence is BATCHED (one message per posted
    # head, one pulse — see src/virtio/console.rs), so the port opened
    # during kernel boot, deterministically, BEFORE this script runs — the
    # device node above exists iff that happened. The session routing is
    # marker-free: opening the port is the signal (the kernel driver sends
    # PORT_OPEN(1) on the control queue; the VMM reads it there).
    /bin/portagent "$PORT" "$ROWS" "$COLS" "$CMD" "$@"
    STATUS=$?
else
    # No session transport (the port never opened, or the helper is
    # missing): NO session — no console-session fallback, ever. The
    # exit helper below forwards the status; the VMM tears the VM down.
    STATUS=126
fi

# The session child was a session leader on a real tty: its death
# disassociates the controlling terminal and vhangups it — every
# inherited fd on that tty is hung up with it, so a console-marker
# echo would fast-fail (EIO) and the boot would sail into `poweroff
# -f` with the status never delivered. The exit protocol needs no
# console anymore: sandal-exit is a /dev/mem MMIO store to the VMM's
# hypercall page (marker-free — no string can ever act as the
# protocol; the low half of the store selects EXIT_PORT, the high
# half carries the code). A missing helper just loses the code.
[ -x /usr/sbin/sandal-exit ] && /usr/sbin/sandal-exit "$STATUS"
poweroff -f
# Fallback if poweroff is not serviced.
sleep 5
exit $STATUS
