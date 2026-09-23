#!/bin/sh
# sandal x86_64 guest init

# The kernel forwards unknown cmdline parameters as init argv — drop them.
set --
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export TERM=linux
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
EXIT_TOKEN=
while IFS= read -r line; do
    case $line in
        ARG=*) set -- "$@" "${line#ARG=}" ;;
        DISK_MODE=*) DISK_MODE=${line#DISK_MODE=} ;;
        NETWORK=*) NETWORK=${line#NETWORK=} ;;
        CLOCK=*) CLOCK=${line#CLOCK=} ;;
        SHARE=*) SHARES_TEXT="$SHARES_TEXT${line#SHARE=}\n" ;;
        COLS=*) COLS=${line#COLS=} ;;
        ROWS=*) ROWS=${line#ROWS=} ;;
        EXIT=*) EXIT_TOKEN=${line#EXIT=} ;;
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

# PTYs: tmux/screen/shells-with-job-control need the devpts mount for
# /dev/pts (devtmpfs provides /dev/ptmx but not the pts filesystem).
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null

# ── Virtiofs shares (--share host:guest) ──────────────────────────────
printf '%b' "$SHARES_TEXT" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    tag=${line%%:*}
    path=${line#*:}
    mkdir -p "$path"
    mount -t virtiofs "$tag" "$path"
done

cd /root

# ── Run the command on the console ────────────────────────────────────
# Give the console a real window size: the virtio console does not carry
# TIOCGWINSZ, and without it the shell's line editor guesses the width and
# wraps lines incorrectly.
stty -F /dev/console rows "$ROWS" cols "$COLS" 2>/dev/null
# /bin/ctty starts a new session and claims the console as the CONTROLLING
# terminal via TIOCSCTTY (shells open redirections with O_NOCTTY, so a
# script alone can never do this). With a controlling terminal the guest
# shell has working job control and tty signals (Ctrl-C, Ctrl-Z).
# The crafted helper has no PATH search — resolve the command first.
#
# Stdin MUST be opened read-write (<>): the interactive tty fd is inherited
# by everything on the console — tmux's client passes STDIN_FILENO to the
# server as its terminal fd, and a server writing a redraw to an O_RDONLY
# fd gets EBADF on every write, so the attached pane never draws (input
# still works, which makes the hang extra confusing). `>` for stdout stays
# one-way; the console is the same file anyway.
if [ -x /bin/ctty ]; then
    CMD="$(command -v "$1")"
    [ -n "$CMD" ] || CMD="$1"
    shift
    /bin/ctty "$CMD" "$@" <> /dev/console > /dev/console 2>&1
    STATUS=$?
else
    setsid sh -c 'exec "$@"' sh "$@" <> /dev/console > /dev/console 2>&1
    STATUS=$?
fi

# Exit protocol: the VMM matches `<per-boot token><status>` — a random
# token delivered in the config, so workload output can never act as the
# protocol by echoing script text or fixed strings.
echo "${EXIT_TOKEN}${STATUS}"
poweroff -f
# Fallback if poweroff is not serviced.
sleep 5
exit $STATUS
