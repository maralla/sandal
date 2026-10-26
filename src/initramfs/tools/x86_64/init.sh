#!/bin/sh
# sandal x86_64 guest init

# The kernel forwards unknown cmdline parameters as init argv — drop them.
set --
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

mount -t proc proc /proc
mount -t sysfs sysfs /sys

# ── Parse /etc/sandal.conf (VMM-injected run configuration) ────────────
DISK_MODE=
NETWORK=0
CLOCK=0
SHARES_TEXT=
MEMCAP=0
VSOCKD=
HYPERCALL=
while IFS= read -r line; do
    case $line in
        DISK_MODE=*) DISK_MODE=${line#DISK_MODE=} ;;
        NETWORK=*) NETWORK=${line#NETWORK=} ;;
        CLOCK=*) CLOCK=${line#CLOCK=} ;;
        SHARE=*) SHARES_TEXT="$SHARES_TEXT${line#SHARE=}\n" ;;
        TERM=*) TERM=${line#TERM=} ;;
        MEMCAP=*) MEMCAP=${line#MEMCAP=} ;;
        VSOCKD=*) VSOCKD=${line#VSOCKD=} ;;
        HYPERCALL=*) HYPERCALL=${line#HYPERCALL=} ;;
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

# /tmp is NOT overmounted: it rides the overlay root, so in disk mode it
# shares the data disk (--disk-size) instead of a fixed half-RAM tmpfs.
# /tmp is workspace scratch — it must never leak into an exported layer
# (the VMM filters tmp/ out of every export; see handle_export_done).
chmod 1777 /tmp 2>/dev/null

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

# ── The home directory is the default ────────────────────────────────
# Every session the command execution line forks inherits THIS cwd:
# the line starts below, so the cd must come first — a cd after the
# start left the line (and every session it forked) on the pivoted
# root's `/`, and the shell's own prompt rendered it (MEASURED: `pwd`
# printed `/`, the prompt `/ # `).
cd /root

# ── The command execution line: the general command execution proxy ──
# /bin/vsockd listens on the guest's vsock (the VMM's own channel
# bridges each client connection to it) and runs what each connection
# carries: the connection's own bytes decide what runs — a command
# execution line, not a fixed forward. One forked child per connection
# (concurrent connections are the point); SIGCHLD is SIG_IGN inside it
# (the kernel auto-reaps — no zombies), and every refusal funnels
# through one paced retry — a persistent refusal degrades to ten
# attempts a second, never a spin.
# The start is UNCONDITIONAL and it is the init's OWN LAST COMMAND:
# no background child, no park — PID 1 IS the accept loop. The build
# guarantees the binary (build.rs compiles it and asserts success) and
# the VMM guarantees the port (it always creates the host on this
# architecture — the session line always registers), so a conditional
# was dead code that could only ever fail SILENTLY: the exec skipped,
# the init parked, and the port answered nothing forever (MEASURED: a
# broken injection hung every boot past every bound). Without the line
# the guest is useless — so there is no case for the condition, and a
# genuinely broken build now fails LOUDLY: the exec fails, PID 1 dies,
# the kernel panics — visible, not parked.

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

# ── The command execution line IS the init's last command ───────────
# exec, not a background child and not the wait/sleep park this once
# was: the park parked PID 1 in a blocking wait or a billion-second
# nanosleep — a vCPU-halting dead end that left the guest's deferred
# transport workers (the send worker and the receive worker — each
# scheduled only while the vCPU is executing something) with nothing
# to be scheduled around, and the transport's gates never opened. As
# the exec'd last command PID 1 IS the accept loop: the socket setup,
# the accept, the fork per connection, the paced refusal nap, every
# connection's children and their teardowns — the vCPU's own activity
# is the transport's driver, and the host's own exit kills the VM (the
# accept loop never exits; the exit helper below is for BOOT failures
# only — a failed mount, a failed overlay — and is never reached while
# the line runs).
echo VSOCKD_ABOUT_TO_EXEC
# The hypercall page's guest-physical address: vsockd stores the READY
# signal there once its listener is bound (the event the VMM's vsock
# device connects parked front ends on).
export HYPERCALL

exec /bin/vsockd "$VSOCKD"
# Unreachable while the line runs (the exec never returns); a broken
# build fails loudly here — the exec fails, PID 1 dies, the kernel
# panics — never a silent park.

# The session child was a session leader on a real tty: its death
# disassociates the controlling terminal and vhangups it — every
# inherited fd on that tty is hung up with it, so a console-marker
# echo would fast-fail (EIO) and the boot would sail into `poweroff
# -f` with the status never delivered. The exit protocol needs no
# console anymore: sandal-exit is a /dev/mem MMIO store to the VMM's
# hypercall page (marker-free — no string can ever act as the
# protocol; the low half of the store selects EXIT_PORT, the high
# half carries the code). UNCONDITIONAL, same as the command execution
# line above: the BUILD guarantees the helper (the injection is
# unconditional on this architecture), so an existence check was dead
# code that could only ever fail SILENTLY — the code lost, the boot
# sailing into poweroff with nothing delivered. A genuinely broken
# build fails loudly instead (the helper is missing, the store never
# lands, the VMM names it).
/usr/sbin/sandal-exit "$STATUS"
poweroff -f
# Fallback if poweroff is not serviced.
sleep 5
exit $STATUS
