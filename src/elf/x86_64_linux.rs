//! Linux x86_64 syscall numbers and kernel constants (for the guest init).

// The Linux/x86_64 UAPI tables is an intentionally complete reference toolkit: crafted
// guest binaries use subsets of it, and unused entries document the
// surrounding UAPI surface.
#![allow(dead_code)]
#![allow(unused_macros)]

// ── Syscall numbers (x86_64, arch/x86/entry/syscalls/syscall_64.tbl) ───
pub mod nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const POLL: u32 = 7;
    pub const CLOSE: u32 = 3;
    pub const IOCTL: u32 = 16;
    pub const SOCKET: u32 = 41;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const ACCEPT: u32 = 43;
    pub const CONNECT: u32 = 42;
    pub const CLONE: u32 = 56;
    pub const EXECVE: u32 = 59;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const KILL: u32 = 62;
    pub const GETPID: u32 = 39;
    pub const CHDIR: u32 = 80;
    pub const SETSID: u32 = 112;
    pub const NANO_SLEEP: u32 = 35;
    pub const PIVOT_ROOT: u32 = 155;
    pub const MOUNT: u32 = 165;
    pub const REBOOT: u32 = 169;
    pub const CLOCK_SETTIME: u32 = 227;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const DUP3: u32 = 292;
    /// pipe2(2) — the pipe-mode session transport's pipe pairs.
    pub const PIPE2: u32 = 293;
    /// fcntl(2) — F_GETFL/F_SETFL live here (the bridge's O_NONBLOCK).
    pub const FCNTL: u32 = 72;
    /// rt_sigaction(2) — the bridge ignores SIGPIPE (a pipe write after
    /// the session dies would kill the bridge before the reaper forwards
    /// the session's own status).
    pub const RT_SIGACTION: u32 = 13;
    pub const IOPL: u32 = 172;
    pub const LSEEK: u32 = 8;
}

// ── Filesystem limits ─────────────────────────────────────────────────
pub const NAME_MAX: usize = 255;

// ── File / mount flags ────────────────────────────────────────────────
pub const AT_FDCWD: i32 = -100;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0x40;
pub const O_TRUNC: u32 = 0x200;
pub const O_NONBLOCK: u32 = 0o4000;
/// fcntl commands (the bridge's nonblocking fds).
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
/// ioctl(FIONBIO) — set/clear O_NONBLOCK by pointer (the fds the bridge
/// touches are fresh; no F_GETFL round trip is needed).
pub const FIONBIO: u32 = 0x5421;
/// Errno values the crafted binaries compare syscalls against (a failed
/// syscall returns -errno in rax).
pub const EINTR: i64 = 4;
pub const EAGAIN: i64 = 11;
/// MAP_SHARED for the /dev/mem hypercall stores.
pub const MAP_SHARED: i32 = 1;
pub const PROT_READ_WRITE: i32 = 3;

// ── Signals ───────────────────────────────────────────────────────────
pub const SIGCHLD: u32 = 17;
pub const SIGKILL: u32 = 9;
/// SIGPIPE — ignored by the bridge (see nr::RT_SIGACTION).
pub const SIGPIPE: u32 = 13;
/// SIGTSTP — the ^Z (VSUSP) translation (the vsockd bridge: its
/// default action is STOP, which the shell's children do NOT ignore).
pub const SIGTSTP: u32 = 20;
/// SIG_IGN — the rt_sigaction handler value.
pub const SIG_IGN: u64 = 1;

// ── Terminal ──────────────────────────────────────────────────────────
/// Terminal ioctls.
pub const TIOCSCTTY: u32 = 0x540E;
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
/// Unlock the pty pair (unlockpt(0)); the slave open fails EIO without it.
pub const TIOCSPTLCK: u32 = 0x4004_5431;
/// The pty slave fd straight from the master (the flags argument IS the
/// peer fd's open flags — O_RDWR, or every session write fails EBADF).
pub const TIOCGPTPEER: u32 = 0x5441;
/// Apply a winsize {rows, cols, 0, 0} to the pair.
pub const TIOCSWINSZ: u32 = 0x5414;
/// Set the tty's foreground process group (the arg is a POINTER to the
/// pgrp — the session leader's own, so the tty's VINTR path (Ctrl-C)
/// has a target and the exec'd shell's job-control check passes).
pub const TIOCSPGRP: u32 = 0x5410;

// ── poll(2) ───────────────────────────────────────────────────────────
pub const POLLIN: u32 = 0x001;
pub const POLLOUT: u32 = 0x004;

// ── Networking ────────────────────────────────────────────────────────
pub const AF_INET: u32 = 2;
/// AF_VSOCK — the guest's vsock address family (the vsockrelay's
/// listener; see initramfs/tools/x86_64/vsockrelay.rs).
pub const AF_VSOCK: u32 = 40;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
/// INADDR_LOOPBACK — the vsockrelay's forward target (guest loopback).
pub const INADDR_LOOPBACK: u32 = 0x7F00_0001;
pub const SIOCSIFADDR: u32 = 0x8916;
pub const SIOCSIFNETMASK: u32 = 0x891C;
pub const SIOCSIFFLAGS: u32 = 0x8914;
pub const SIOCADDRT: u32 = 0x890B;
pub const IFF_UP: u32 = 0x1;
pub const RTF_UP: u32 = 0x1;
pub const RTF_GATEWAY: u32 = 0x2;

/// Clock IDs.
pub const CLOCK_REALTIME: u32 = 0;

// ── VMM hypercall ports (the x86 analog of the ARM64 BRK immediates) ──
//
// The init binary talks to the VMM through unregistered I/O ports, which
// exit KVM with KVM_EXIT_IO. The port numbers mirror the ARM64 BRK
// immediates ("SanDal 2/3/4").
pub const INIT_CONFIG_PORT: u16 = 0x5D4;
pub const EXPORT_RESIZE_PORT: u16 = 0x5D2;
pub const EXPORT_DONE_PORT: u16 = 0x5D3;
pub const EXIT_PORT: u16 = 0x5D5; // "SanDal 5": the low half selects the
                                  // signal; the high half carries the code.
/// The command execution line's readiness signal: /bin/vsockd stores
/// this once its listener is bound, and the VMM's vsock device reacts
/// by connecting every parked front end (the REQUEST goes out exactly
/// then — no retry loop, no RST cycle against a guest that cannot
/// listen yet; see virtio::vsock).
pub const VSOCKD_READY_PORT: u16 = 0x5D6;
