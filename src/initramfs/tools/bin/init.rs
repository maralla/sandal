//! The guest `/init` — one compiled binary on BOTH architectures (the
//! x86_64 busybox script it replaces is gone; the flow was identical and
//! the syscalls are arch-uniform).
//!
//! The run configuration arrives as the SAME text file the script read
//! (`/etc/sandal.conf`, VMM-injected); the session transport is the vsock
//! line on every platform, so the init's last act is the same exec the
//! script made: `/bin/vsockd <port>`, PID 1 IS the accept loop, and the
//! command execution rides the session front end.
//!
//! Flow:
//!   1. mount proc/sys/devtmpfs
//!   2. parse /etc/sandal.conf (disk mode, network, clock, shares, TERM,
//!      the memory cap, the vsockd port)
//!   3. set the wall clock; bring up the network (static 10.0.2.15 NAT)
//!   4. build the overlayfs root (tmpfs or /dev/vdb upper) and pivot_root
//!   5. mount virtiofs shares
//!   6. grow the RAM floor toward the cap (x86_64's memory hotplug: the
//!      headroom online before the session, then a daemon adding more)
//!   7. exec /bin/vsockd (the accept loop IS PID 1; the session's exit
//!      code rides the EXIT signal — the hypercall store on x86_64, the
//!      BRK on aarch64 — from vsockd itself)

#![no_std]
#![no_main]

mod common;

use common::*;

// ── NUL-terminated path/format literals ─────────────────────────────

const S_PROC: &[u8] = b"proc\0";
const S_PROC_PATH: &[u8] = b"/proc\0";
const S_SYSFS: &[u8] = b"sysfs\0";
const S_SYS_PATH: &[u8] = b"/sys\0";
const S_DEVTMPFS: &[u8] = b"devtmpfs\0";
const S_DEV_PATH: &[u8] = b"/dev\0";
const S_DEVPTS: &[u8] = b"devpts\0";
const S_DEVPTS_PATH: &[u8] = b"/dev/pts\0";
const S_TMPFS: &[u8] = b"tmpfs\0";
const S_TMP_PATH: &[u8] = b"/tmp\0";
const S_SLASH: &[u8] = b"/\0";
const S_DOT: &[u8] = b".\0";
const S_MNT_LOWER: &[u8] = b"/mnt/lower\0";
const S_MNT_OVERLAY: &[u8] = b"/mnt/overlay\0";
const S_MNT_TMP: &[u8] = b"/mnt/tmpupper\0";
const S_MNT_DISK: &[u8] = b"/mnt/diskupper\0";
const S_DATA_DEV: &[u8] = b"/dev/vdb\0";
const S_EXT2: &[u8] = b"ext2\0";
const S_OVERLAY: &[u8] = b"overlay\0";
const S_MNT_DIR: &[u8] = b"mnt\0";
const S_MNT_ROOT: &[u8] = b"mnt/root\0";
const S_UPPER: &[u8] = b"upper\0";
const S_WORK: &[u8] = b"work\0";
const S_VIRTIOFS: &[u8] = b"virtiofs\0";
const S_HOME: &[u8] = b"/root\0";
const S_RESOLV_PATH: &[u8] = b"/etc/resolv.conf\0";
const S_RESOLV_DATA: &[u8] = b"nameserver 10.0.2.3\n";
const S_CONF: &[u8] = b"/etc/sandal.conf\0";
const S_VSOCKD: &[u8] = b"/bin/vsockd\0";
const S_PTMX: &[u8] = b"/dev/ptmx\0";
const S_PTMX_TARGET: &[u8] = b"pts/ptmx\0";
const S_DEVPTS_NEWINSTANCE: &[u8] = b"newinstance\0";
const S_MEMINFO: &[u8] = b"/proc/meminfo\0";
const S_MEM_PROBE: &[u8] = b"/sys/devices/system/memory/probe\0";
const S_MEM_DIR: &[u8] = b"/sys/devices/system/memory/\0";
const S_ONLINE: &[u8] = b"online\0";
const S_MEMAVAIL: &[u8] = b"MemAvailable:";

const ENV_HOME: &[u8] = b"HOME=/root\0";
const ENV_PATH: &[u8] = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
const ENV_SSL: &[u8] = b"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\0";
const ENV_SCRIPT: &[u8] = b"SCRIPT_ONLY=1\0";

// The overlay mount options (data= for the overlay fs type).
const OVL_OPTS_DISK: &[u8] =
    b"lowerdir=/mnt/lower,upperdir=/mnt/diskupper/upper,workdir=/mnt/diskupper/work\0";
const OVL_OPTS_TMP: &[u8] =
    b"lowerdir=/mnt/lower,upperdir=/mnt/tmpupper/upper,workdir=/mnt/tmpupper/work\0";

const MS_BIND: usize = 4096;

const CONF_MAX: usize = 16 * 1024;

#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! {
    exit(126)
}

/// The parsed /etc/sandal.conf (the same keys the x86_64 script reads).
struct Config {
    disk_mode: bool,
    network: bool,
    clock: u64,
    shares: [(&'static [u8], &'static [u8]); 64],
    n_shares: usize,
    term: Option<&'static [u8]>,
    /// The hotplug cap in bytes (the whole KVM slot): the RAM floor
    /// grows toward it. Zero — no hotplug (a cap at or below the floor,
    /// or the aarch64 kernel, whose slot is fully declared RAM).
    memcap: u64,
    vsockd: u32,
    hypercall: Option<&'static [u8]>,
    /// The script sandbox (--script): the line rejects command lines and
    /// serves whole script files; the VM powers off with the script's
    /// own exit status.
    script: bool,
}

/// Read and parse /etc/sandal.conf: one KEY=VALUE per line. The values'
/// slices point into the static conf buffer (the init lives for the VM's
/// whole life; one reserved page at boot is the design's own price — the
/// machine code's stack frame was the same one-page reservation).
fn config_load() -> Config {
    // The init is single-threaded up to the exec (the accept loop forks
    // children AFTER the parse) — the static borrow is sound.
    let buf: &'static mut [u8; CONF_MAX] =
        unsafe { &mut *core::ptr::addr_of_mut!(CONF_BUF) };
    let fd = open(S_CONF, O_RDONLY, 0);
    let mut n = 0usize;
    if fd >= 0 {
        loop {
            let r = read(fd, &mut buf[n..]);
            if r <= 0 {
                break;
            }
            n += r as usize;
            if n >= buf.len() {
                break;
            }
        }
        close(fd);
    }
    // NUL-terminate every line in place (\n → \0): the key/value slices
    // and the env strings (TERM=..., HYPERCALL=...) hand to execve/mount
    // verbatim — a C string ends at the line's end.
    for b in buf[..n].iter_mut() {
        if *b == b'\n' {
            *b = 0;
        }
    }
    let conf: &'static [u8] = unsafe { core::slice::from_raw_parts(buf.as_ptr(), n) };
    let mut c = Config {
        disk_mode: false,
        network: false,
        clock: 0,
        shares: [(&[], &[]); 64],
        n_shares: 0,
        term: None,
        memcap: 0,
        vsockd: 0,
        hypercall: None,
        script: false,
    };
    let mut p = 0usize;
    while p < conf.len() {
        // One line: up to the NUL this pass wrote (or the buffer's end).
        let mut e = p;
        while e < conf.len() && conf[e] != 0 {
            e += 1;
        }
        let line = &conf[p..e];
        p = e + 1;
        if line.is_empty() {
            continue;
        }
        let eq = match line.iter().position(|&b| b == b'=') {
            Some(i) => i,
            None => continue,
        };
        let (key, val) = (&line[..eq], &line[eq + 1..]);
        match key {
            b"DISK_MODE" => c.disk_mode = val == b"disk",
            b"NETWORK" => c.network = val == b"1",
            b"CLOCK" => {
                let mut v = 0u64;
                for &b in val {
                    match b {
                        b'0'..=b'9' => v = v * 10 + (b - b'0') as u64,
                        _ => break,
                    }
                }
                c.clock = v;
            }
            b"SHARE" => {
                // tag:path
                if let Some(colon) = val.iter().position(|&b| b == b':') {
                    if c.n_shares < c.shares.len() {
                        c.shares[c.n_shares] = (&val[..colon], &val[colon + 1..]);
                        c.n_shares += 1;
                    }
                }
            }
            b"TERM" => c.term = Some(val),
            b"MEMCAP" => {
                let mut v = 0u64;
                for &b in val {
                    match b {
                        b'0'..=b'9' => v = v * 10 + (b - b'0') as u64,
                        _ => break,
                    }
                }
                c.memcap = v;
            }
            b"VSOCKD" => {
                let mut v = 0u32;
                for &b in val {
                    match b {
                        b'0'..=b'9' => v = v * 10 + (b - b'0') as u32,
                        _ => break,
                    }
                }
                c.vsockd = v;
            }
            b"HYPERCALL" => c.hypercall = Some(val),
            b"SCRIPT" => c.script = true,
            _ => {}
        }
    }
    c
}

/// The config file's static home (see config_load).
static mut CONF_BUF: [u8; CONF_MAX] = [0; CONF_MAX];

/// Static NAT layout behind the user-space netstack: lo up, eth0
/// 10.0.2.15/24, the default route via 10.0.2.2, the NAT resolver.
fn network_up() {
    let fd = syscall(nr::SOCKET, [AF_INET, SOCK_DGRAM, 0, 0, 0, 0]) as i32;
    if fd < 0 {
        return;
    }
    // One scratch buffer serves struct ifreq (40 bytes) and struct
    // rtentry (~120 bytes on aarch64; the kernel copy_from_user's the
    // full struct on SIOCADDRT).
    let mut b = [0u8; 128];

    // lo: IFF_UP
    b[..2].copy_from_slice(b"lo");
    b[16..18].copy_from_slice(&IFF_UP.to_ne_bytes());
    let _ = ioctl3(fd, SIOCSIFFLAGS, b.as_mut_ptr() as usize);

    // eth0: the address 10.0.2.15
    b = [0u8; 128];
    b[..4].copy_from_slice(b"eth0");
    b[16..18].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[20..24].copy_from_slice(&[10, 0, 2, 15]);
    let _ = ioctl3(fd, SIOCSIFADDR, b.as_mut_ptr() as usize);

    // eth0: the netmask 255.255.255.0
    b = [0u8; 128];
    b[..4].copy_from_slice(b"eth0");
    b[16..18].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[20..24].copy_from_slice(&[255, 255, 255, 0]);
    let _ = ioctl3(fd, SIOCSIFNETMASK, b.as_mut_ptr() as usize);

    // eth0: IFF_UP
    b = [0u8; 128];
    b[..4].copy_from_slice(b"eth0");
    b[16..18].copy_from_slice(&IFF_UP.to_ne_bytes());
    let _ = ioctl3(fd, SIOCSIFFLAGS, b.as_mut_ptr() as usize);

    // The default route via 10.0.2.2 (struct rtentry: rt_dst sockaddr at
    // 8, rt_gateway at 24, rt_genmask at 40, rt_flags at 56).
    b = [0u8; 128];
    b[8..10].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[24..26].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[28..32].copy_from_slice(&[10, 0, 2, 2]);
    b[40..42].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[56..58].copy_from_slice(&RTF_UP_GATEWAY.to_ne_bytes());
    let _ = ioctl3(fd, SIOCADDRT, b.as_mut_ptr() as usize);

    close(fd);

    let fd = open(S_RESOLV_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if fd >= 0 {
        let _ = write(fd, S_RESOLV_DATA);
        close(fd);
    }
}

/// mkdir -p: create every component of an absolute path. Existing
/// components (EEXIST) are fine. Every syscall gets a NUL-terminated
/// copy — the syscall reads the pathname to the NUL, and a NUL-less
/// slice makes it read straight through into the conf buffer's tail
/// (`/root` + `go/pkg\0` = `/rootgo/pkg`, MEASURED: the share mounts
/// all failed with paths the guest had never heard of).
fn mkdir_p(path: &[u8]) {
    let mut buf = [0u8; 128];
    buf[..path.len()].copy_from_slice(path);
    for i in 1..path.len() {
        if path[i] == b'/' {
            buf[i] = 0;
            let _ = mkdir(&buf, 0o755); // the prefix path[..i]
            buf[i] = b'/';
        }
    }
    let _ = mkdir(&buf, 0o755); // the full path (the copy's tail is NUL)
}

/// Decimal digits of `v` into `buf`; returns the length. (no_std: no
/// fmt machinery — the probe address and the section index are the only
/// numbers this init ever prints.)
fn format_u64(buf: &mut [u8], v: u64) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = v;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[i] = tmp[n - 1 - i];
    }
    n
}

/// "/sys/devices/system/memory/memory{idx}" — the hotplug block's node.
fn format_mem_node(idx: usize) -> [u8; 80] {
    let mut out = [0u8; 80];
    let base = S_MEM_DIR.len() - 1; // without the NUL
    out[..base].copy_from_slice(&S_MEM_DIR[..base]);
    let mut at = base;
    out[at..at + 6].copy_from_slice(b"memory");
    at += 6;
    let mut num = [0u8; 20];
    let n = format_u64(&mut num, idx as u64);
    out[at..at + n].copy_from_slice(&num[..n]);
    at += n;
    out[at] = 0;
    out
}

/// "/sys/devices/system/memory/memory{idx}/state" — the online control.
fn format_mem_node_state(idx: usize) -> [u8; 80] {
    let mut out = format_mem_node(idx);
    let at = out.iter().position(|&b| b == 0).unwrap_or(78);
    out[at..at + 6].copy_from_slice(b"/state");
    out[at + 6] = 0;
    out
}

/// MemAvailable in kB, parsed from /proc/meminfo (the daemon's growth
/// trigger). Zero when the read or the parse fails — the daemon then
/// just idles until the next tick.
fn mem_available_kb() -> u64 {
    let mut buf = [0u8; 4096];
    let fd = open(S_MEMINFO, O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut n = 0usize;
    while n < buf.len() {
        let r = read(fd, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    close(fd);
    let line = &buf[..n];
    let key = S_MEMAVAIL;
    let mut at = match line.windows(key.len()).position(|w| *w == *key) {
        Some(i) => i + key.len(),
        None => return 0,
    };
    while at < line.len() && (line[at] == b' ' || line[at] == b'\t') {
        at += 1;
    }
    let mut v = 0u64;
    while at < line.len() && line[at].is_ascii_digit() {
        v = v * 10 + (line[at] - b'0') as u64;
        at += 1;
    }
    v
}

#[no_mangle]
pub extern "C" fn guest_entry(_rsp: usize) -> ! {
    // ── Phase 1: the essential mounts ────────────────────────────────
    // (No /tmp mount: /tmp rides the overlay root — in disk mode it
    // shares the data disk instead of a fixed half-RAM tmpfs.)
    let _ = mount(S_PROC, S_PROC_PATH, S_PROC, 0, 0);
    let _ = mount(S_SYSFS, S_SYS_PATH, S_SYSFS, 0, 0);
    let _ = mount(S_DEVTMPFS, S_DEV_PATH, S_DEVTMPFS, 0, 0);

    // ── The run configuration ────────────────────────────────────────
    let c = config_load();

    // ── The wall clock (the VMM snapshots the host time at boot) ────
    if c.clock > 0 {
        let _ = settimeofday_secs(c.clock);
    }

    // ── The network ──────────────────────────────────────────────────
    if c.network {
        network_up();
    }

    // ── The overlayfs root (lower = pristine rootfs, upper = disk|tmpfs)
    let _ = mkdir(S_MNT_LOWER, 0o755);
    let _ = mkdir(S_MNT_OVERLAY, 0o755);
    let _ = mkdir(S_MNT_TMP, 0o755);
    let _ = mkdir(S_MNT_DISK, 0o755);
    let _ = mount(S_SLASH, S_MNT_LOWER, S_SLASH, MS_BIND, 0);

    let (upper_base, ovl_opts) = if c.disk_mode {
        let _ = mount(S_DATA_DEV, S_MNT_DISK, S_EXT2, 0, 0);
        (S_MNT_DISK, OVL_OPTS_DISK)
    } else {
        let _ = mount(S_TMPFS, S_MNT_TMP, S_TMPFS, 0, 0);
        (S_MNT_TMP, OVL_OPTS_TMP)
    };
    // upper/ and work/ under the chosen base
    let mut up = [0u8; 64];
    let mut wk = [0u8; 64];
    let base_len = upper_base.len() - 1; // without the NUL
    up[..base_len].copy_from_slice(&upper_base[..base_len]);
    up[base_len] = b'/';
    up[base_len + 1..base_len + 1 + S_UPPER.len()].copy_from_slice(S_UPPER);
    wk[..base_len].copy_from_slice(&upper_base[..base_len]);
    wk[base_len] = b'/';
    wk[base_len + 1..base_len + 1 + S_WORK.len()].copy_from_slice(S_WORK);
    let _ = mkdir(&up[..base_len + S_UPPER.len()], 0o755);
    let _ = mkdir(&wk[..base_len + S_WORK.len()], 0o755);
    let _ = mount(S_OVERLAY, S_MNT_OVERLAY, S_OVERLAY, 0, ovl_opts.as_ptr() as usize);

    // ── pivot_root onto the overlay ──────────────────────────────────
    let _ = chdir(S_MNT_OVERLAY);
    let _ = mkdir(S_MNT_DIR, 0o755);
    let _ = mkdir(S_MNT_ROOT, 0o755);
    let _ = pivot_root(S_DOT, S_MNT_ROOT);

    // Re-mount essentials on the new root. devtmpfs is a single instance,
    // so the pre-pivot mount is superseded by this fresh one.
    let _ = mount(S_PROC, S_PROC_PATH, S_PROC, 0, 0);
    let _ = mount(S_SYSFS, S_SYS_PATH, S_SYSFS, 0, 0);
    let _ = mount(S_DEVTMPFS, S_DEV_PATH, S_DEVTMPFS, 0, 0);

    // /tmp is NOT overmounted: it rides the overlay root (the data disk
    // in disk mode). Workspace scratch — the export filters tmp/ out of
    // every layer (handle_export_done).
    let _ = chmod(S_TMP_PATH, 0o1777);

    // /dev/fd and /dev/std*: alias to the per-process /proc/self/fd.
    let _ = symlink(b"/proc/self/fd\0", b"/dev/fd\0");
    let _ = symlink(b"/proc/self/fd/0\0", b"/dev/stdin\0");
    let _ = symlink(b"/proc/self/fd/1\0", b"/dev/stdout\0");
    let _ = symlink(b"/proc/self/fd/2\0", b"/dev/stderr\0");

    // PTYs: devtmpfs provides /dev/ptmx but not the pts filesystem.
    // newinstance: a private devpts instance whose ptmx WORKS — the pty
    // lands in THIS instance, so /dev/pts/ptmx and TIOCGPTPEER give the
    // master's own slave (a plain compat mount's ptmx is non-functional,
    // and the pty would land in a different instance than the slave path
    // resolves in). The symlink makes every ptmx open land in THIS
    // instance. Both best-effort (the script's 2>/dev/null): a kernel
    // without the option keeps the compat mount's ptmx.
    let _ = mkdir(S_DEVPTS_PATH, 0o755);
    let _ = mount(S_DEVPTS, S_DEVPTS_PATH, S_DEVPTS, 0, S_DEVPTS_NEWINSTANCE.as_ptr() as usize);
    let _ = unlink(S_PTMX);
    let _ = symlink(S_PTMX_TARGET, S_PTMX);
    let _ = chdir(S_SLASH);

    // ── The virtiofs shares ──────────────────────────────────────────
    for i in 0..c.n_shares {
        let (tag, path) = c.shares[i];
        // The mount source: a NUL-terminated COPY of the tag. The tag's
        // slice points into the conf buffer, where the tag is followed by
        // ':' and the path — mount(2) reads to the NUL and would take the
        // WHOLE `tag:path` value as the virtiofs tag (MEASURED: the
        // kernel's `tag <share0:/mnt/share> not found`).
        let mut tag_buf = [0u8; 36]; // the virtiofs tag: 36 bytes max
        tag_buf[..tag.len()].copy_from_slice(tag);
        let tag_nul = &tag_buf[..tag.len() + 1];
        // mkdir -p: the share paths are multi-level (/root/go/pkg) and
        // the parents may not exist.
        mkdir_p(path);
        const MS_SILENT: usize = 0x8000;
        let _ = mount(tag_nul, path, S_VIRTIOFS, MS_SILENT, 0);
    }

    // ── The home directory is the default cwd (the session line forks
    // below it and inherits THIS cwd) ────────────────────────────────
    let _ = chdir(S_HOME);

    // ── The home directory is the default cwd (the session line forks
    // below it and inherits THIS cwd) ────────────────────────────────
    let _ = chdir(S_HOME);

    // ── Memory hotplug: the floor is online; the cap arrives on demand ──
    // x86_64's memory model: the VMM maps the whole cap as one lazy slot
    // but declares only a RAM floor in the boot memory map; [floor, cap)
    // is a hole the guest grows into. A fixed headroom goes online before
    // the session (an instant allocation outruns any poll), then a daemon
    // adds one section at a time whenever MemAvailable descends below one
    // section. Pages nothing touches stay lazy host zero mappings.
    //
    // The section index advances UNCONDITIONALLY: a refused probe is
    // permanent — the first section above the floor is where the
    // virtio-mmio blocks live (0x10000000, the kernel resource tree holds
    // it) and the kernel answers EEXIST forever; a stuck index spun the
    // boot until the probe deadline killed it (MEASURED: no READY, no
    // session line). The loop is bounded by the cap either way, and the
    // skipped sections are exactly the ones that cannot work.
    let probe_fd = open(S_MEM_PROBE, O_WRONLY, 0);
    if c.memcap > 0 && probe_fd >= 0 {
        close(probe_fd);
        const SECTION_KB: usize = 128 * 1024; // block_size_bytes / 1024
        let cap_kb = (c.memcap as usize) / 1024; // never cross the slot
        // The next section index: one past the highest block the kernel
        // already carries (the RAM floor's own blocks). Found by probing
        // the state files — the blocks are contiguous from 0.
        let mut idx = 0usize;
        loop {
            let name = format_mem_node(idx);
            if open(&name, O_RDONLY, 0) < 0 {
                break;
            }
            idx += 1;
        }
        idx += 1;
        let mut add_section = |idx: usize| -> bool {
            let mut p = [0u8; 24];
            let addr = format_u64(&mut p, (idx as u64) * (SECTION_KB as u64) * 1024);
            let fd = open(S_MEM_PROBE, O_WRONLY, 0);
            if fd < 0 {
                return false;
            }
            let ok = write(fd, &p[..addr]) > 0;
            close(fd);
            if !ok {
                return false;
            }
            let name = format_mem_node_state(idx);
            let fd = open(&name, O_WRONLY, 0);
            if fd < 0 {
                return false;
            }
            let ok = write(fd, &S_ONLINE[..S_ONLINE.len() - 1]) > 0;
            close(fd);
            ok
        };
        // The headroom: the whole cap online before the session. A partial
        // envelope loses to the linker's working set (multi-GB in one
        // allocation, far past any measured toolchain peak), and an instant
        // allocation that exceeds the envelope OOM-kills the session before
        // any poll could deliver the difference — so nothing is left to a
        // poll: the pages stay lazy host zero mappings, and the cost is the
        // vmemmap and about a second of boot time.
        while (idx as u64) * (SECTION_KB as u64) < cap_kb as u64 {
            let _ = add_section(idx);
            idx += 1;
        }
        // The daemon: one section at a time, each time MemAvailable
        // descends below one section, up to the cap. fork + loop — the
        // child IS the daemon and never returns; the parent execs below.
        let daemon = fork();
        if daemon == 0 {
            loop {
                if mem_available_kb() < SECTION_KB as u64
                    && (idx as u64) * (SECTION_KB as u64) < cap_kb as u64
                {
                    let _ = add_section(idx);
                    idx += 1;
                }
                nap100();
            }
        }
        // The daemon's death is the VM's death (PID 1's exec replaces THIS
        // image; the daemon is a child of the pre-exec image and dies with
        // the machine).
    }

    // ── The command execution line IS the init's last command ───────
    // exec, not a background child: PID 1 IS the accept loop — the
    // socket setup, the accept, the fork per connection. The vsockd
    // session's exit code rides the EXIT BRK (the code in x15) from
    // vsockd's own exit_vm. A broken build fails LOUDLY: the exec
    // fails, the park below keeps the VM addressable for diagnostics —
    // never a silent zero-code exit.
    let mut port_buf = [0u8; 12];
    let port_str = {
        let mut i = port_buf.len();
        let mut v = c.vsockd;
        if v == 0 {
            port_buf[0] = b'0';
            &port_buf[..1]
        } else {
            while v > 0 {
                i -= 1;
                port_buf[i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            &port_buf[i..]
        }
    };

    // The env: the same exports the x86_64 script makes (PATH/HOME/SSL +
    // the host terminal type + the hypercall page when the VMM provided
    // one). The session children inherit this env wholesale.
    let mut env_ptrs: [*const u8; 8] = [core::ptr::null(); 8];
    let mut n_env = 3usize; // PATH, HOME, SSL_CERT_FILE below
    env_ptrs[0] = ENV_PATH.as_ptr();
    env_ptrs[1] = ENV_HOME.as_ptr();
    env_ptrs[2] = ENV_SSL.as_ptr();
    if let Some(t) = c.term {
        // TERM=<value>\0 — the value's slice is NUL-terminated in the
        // conf buffer; the env string starts at the KEY: "TERM=" is five
        // bytes, so the 'T' sits five back from the value's start (the
        // '=' the slice's first byte backs onto is at value-1). The old
        // arithmetic (sub(5) from the '=') landed on the PREVIOUS line's
        // NUL: the guest exported an empty TERM (MEASURED).
        unsafe {
            let p = t.as_ptr().sub(1);
            if p.read() == b'=' && n_env < env_ptrs.len() - 1 {
                n_env += 1;
                env_ptrs[n_env - 1] = p.sub(4); // "TERM" + '='
            }
        }
    }
    if let Some(h) = c.hypercall {
        // HYPERCALL=<addr>\0 — "HYPERCALL=" is ten bytes: the 'H' sits
        // ten back from the value's start (sub(9) from the '='). The old
        // arithmetic (sub(10) from the '=') landed on the previous NUL:
        // vsockd saw no HYPERCALL address and never signaled the VMM —
        // no READY, no session, the boot parked forever (MEASURED).
        unsafe {
            let p = h.as_ptr().sub(1);
            if p.read() == b'=' && n_env < env_ptrs.len() - 1 {
                n_env += 1;
                env_ptrs[n_env - 1] = p.sub(9); // "HYPERCALL" + '='
            }
        }
    }
    if c.script {
        // The script sandbox's policy flag: the daemon rejects command
        // lines, serves whole script files, and powers the VM off with
        // the script's own exit status.
        if n_env < env_ptrs.len() - 1 {
            n_env += 1;
            env_ptrs[n_env - 1] = ENV_SCRIPT.as_ptr();
        }
    }

    let argv: [*const u8; 3] = [
        S_VSOCKD.as_ptr(),
        port_str.as_ptr(),
        core::ptr::null(),
    ];
    let _ = execve(S_VSOCKD, &argv, env_ptrs.as_ptr() as usize);

    // Unreachable while the line runs (the exec never returns). A broken
    // build parks here LOUDLY: the VMM's connect never completes, the
    // front ends time out with a diagnostic — never a silent park that
    // looks like success.
    loop {
        nap100();
    }
}
