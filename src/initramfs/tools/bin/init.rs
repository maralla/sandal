//! The aarch64 guest `/init`: the Rust port of the crafted machine-code
//! init (the ELF DSL that generated it is gone).
//!
//! The x86_64 guest runs a busybox shell script instead (see
//! `tools/x86_64/init.sh`); this is the same flow as a program — the
//! aarch64 has busybox too, but the init predates the script and stays
//! compiled. The run configuration arrives as the SAME text file the
//! script reads (`/etc/sandal.conf`, VMM-injected); the session transport
//! is the vsock line on every platform, so the init's last act is the
//! same exec the script makes: `/bin/vsockd <port>`, PID 1 IS the accept
//! loop, and the command execution rides the session front end.
//!
//! Flow (mirrors the x86_64 init.sh):
//!   1. mount proc/sys/devtmpfs/tmpfs
//!   2. parse /etc/sandal.conf (disk mode, network, clock, shares, TERM,
//!      the vsockd port)
//!   3. set the wall clock; bring up the network (static 10.0.2.15 NAT)
//!   4. build the overlayfs root (tmpfs or /dev/vdb upper) and pivot_root
//!   5. mount virtiofs shares
//!   6. exec /bin/vsockd (the accept loop IS PID 1; the session's exit
//!      code rides the EXIT BRK — the code in x15 — from vsockd itself)

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

const ENV_HOME: &[u8] = b"HOME=/root\0";
const ENV_PATH: &[u8] = b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
const ENV_SSL: &[u8] = b"SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\0";

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
    vsockd: u32,
    hypercall: Option<&'static [u8]>,
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
        vsockd: 0,
        hypercall: None,
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
        let _ = clock_settime(c.clock);
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
    let _ = mkdir(S_DEVPTS_PATH, 0o755);
    let _ = mount(S_DEVPTS, S_DEVPTS_PATH, S_DEVPTS, 0, 0);
    let _ = chdir(S_SLASH);

    // ── The virtiofs shares ──────────────────────────────────────────
    for i in 0..c.n_shares {
        let (tag, path) = c.shares[i];
        let _ = mkdir(path, 0o755);
        let _ = mount(tag, path, S_VIRTIOFS, 0, 0);
    }

    // ── The home directory is the default cwd (the session line forks
    // below it and inherits THIS cwd) ────────────────────────────────
    let _ = chdir(S_HOME);

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
        // conf buffer; prepend the key by pointing one byte back (the
        // conf line is "TERM=<value>\0": the '=' sits right before it).
        unsafe {
            let p = t.as_ptr().sub(1);
            if p.read() == b'=' && n_env < env_ptrs.len() - 1 {
                n_env += 1;
                env_ptrs[n_env - 1] = p.sub(5); // "TERM" + '='
            }
        }
    }
    if let Some(h) = c.hypercall {
        unsafe {
            let p = h.as_ptr().sub(1);
            if p.read() == b'=' && n_env < env_ptrs.len() - 1 {
                n_env += 1;
                env_ptrs[n_env - 1] = p.sub(10); // "HYPERCALL" + '='
            }
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
