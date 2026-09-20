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
    pub const CLOSE: u32 = 3;
    pub const IOCTL: u32 = 16;
    pub const SOCKET: u32 = 41;
    pub const CLONE: u32 = 56;
    pub const EXECVE: u32 = 59;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const CHDIR: u32 = 80;
    pub const SETSID: u32 = 112;
    pub const PIVOT_ROOT: u32 = 155;
    pub const MOUNT: u32 = 165;
    pub const REBOOT: u32 = 169;
    pub const CLOCK_SETTIME: u32 = 227;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const DUP3: u32 = 292;
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
pub const MS_BIND: u32 = 0x1000;

// ── Signals ───────────────────────────────────────────────────────────
pub const SIGCHLD: u32 = 17;

// ── Terminal ──────────────────────────────────────────────────────────
pub const TIOCSCTTY: u32 = 0x540E;
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;

// ── Networking ────────────────────────────────────────────────────────
pub const AF_INET: u32 = 2;
pub const SOCK_DGRAM: u32 = 2;
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
