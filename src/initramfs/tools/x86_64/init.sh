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
MEMCAP=0
VSOCKRELAY=
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
        MEMCAP=*) MEMCAP=${line#MEMCAP=} ;;
        VSOCKRELAY=*) VSOCKRELAY=${line#VSOCKRELAY=} ;;
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

# ── The vsock relay: the SSH channel's guest-side forwarder ──────────
# /bin/vsockrelay listens on the guest's vsock (the VMM's own channel
# bridges each client connection to it) and forwards every connection to
# the guest's own TCP loopback — sshd there, unmodified: OpenSSH has no
# AF_VSOCK listen support, so the relay IS the difference. One forked
# pump child per connection (concurrent sessions are the point); SIGCHLD
# is SIG_IGN inside it (the kernel auto-reaps — no zombies), and every
# refusal funnels through one paced retry — a persistent refusal (no
# sshd: ECONNREFUSED) degrades to ten attempts a second, never a spin.
# No VSOCKRELAY line (the per-command channel, or no vsock at all):
# nothing starts, and the vsock port answers nothing.
if [ -n "$VSOCKRELAY" ] && [ -x /bin/vsockrelay ]; then
    /bin/vsockrelay "${VSOCKRELAY%%:*}" "${VSOCKRELAY##*:}" &
fi

# ── Memory hotplug: the floor is online; the cap arrives on demand ──
# The VMM maps the whole cap as one lazy slot but declares only a RAM
# floor in the boot memory map; [floor, cap) is a hole. A fixed
# headroom goes online before the session starts — an instant allocation
# (a linker's multi-GB buffer) outruns any poll, and the guest OOM path
# kills the session before a daemon could deliver the section — then a
# daemon adds one 128MB section at a time, each time MemAvailable
# descends below one section, up to the cap, for the gradual growth
# (sequential builds, caches) the headroom does not cover. A probe
# creates its section's block offline; the online is one explicit write
# per block (the auto-online policy does not apply to the probe path).
# Pages nothing touches stay lazy host zero mappings: the headroom costs
# its vmemmap and nothing else, and the host resident set still tracks
# what workloads touch, not the cap. A cap at or below the floor (the
# sandbox default) leaves nothing to add: no headroom, no daemon.
if [ "$MEMCAP" -gt 0 ] && [ -w /sys/devices/system/memory/probe ]; then
    SECTION_KB=$((128 * 1024))                   # block_size_bytes / 1024
    CAP_KB=$((MEMCAP / 1024))                    # never cross the slot
    # The next section index: one past the highest block the kernel
    # already carries (the RAM floor's own blocks). Derived from the
    # block list, not MemTotal: no arithmetic on memory totals, and
    # self-correcting against whatever the floor turns out to be.
    IDX=$(ls /sys/devices/system/memory/ \
        | sed -n 's/^memory\([0-9][0-9]*\)$/\1/p' | sort -n | tail -1)
    IDX=$((IDX + 1))
    add_section() {
        echo $((IDX * SECTION_KB * 1024)) > /sys/devices/system/memory/probe \
            && echo online > /sys/devices/system/memory/memory$IDX/state \
            && IDX=$((IDX + 1))
    }
    # Headroom: the whole cap online before the session. A partial
    # envelope loses to the linker's working set (multi-GB in one
    # allocation, far past any measured toolchain peak), and an instant
    # allocation that exceeds the envelope OOM-kills the session before
    # any poll could deliver the difference — so nothing is left to a
    # poll: the pages stay lazy host zero mappings, and the cost is the
    # vmemmap and about a second of boot time.
    while [ $((IDX * SECTION_KB)) -lt "$CAP_KB" ]; do
        add_section
    done
    (
        while :; do
            AVAIL_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
            if [ "$AVAIL_KB" -lt "$SECTION_KB" ] \
               && [ $((IDX * SECTION_KB)) -lt "$CAP_KB" ]; then
                add_section
            fi
            sleep 0.1
        done
    ) &
fi

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
