//! Linux aarch64 syscall numbers and kernel constants.

// ── Syscall numbers (aarch64) ──────────────────────────────────────────
pub mod nr {
    pub const DUP3: u32 = 24;
    pub const IOCTL: u32 = 29;
    pub const MKDIRAT: u32 = 34;
    pub const MOUNT: u32 = 40;
    pub const PIVOT_ROOT: u32 = 41;
    pub const CHDIR: u32 = 49;
    pub const OPENAT: u32 = 56;
    pub const CLOSE: u32 = 57;
    pub const READ: u32 = 63;
    pub const WRITE: u32 = 64;
    pub const EXIT: u32 = 93;
    pub const CLOCK_SETTIME: u32 = 112;
    pub const REBOOT: u32 = 142;
    pub const SETSID: u32 = 157;
    pub const UNAME: u32 = 160;
    pub const SOCKET: u32 = 198;
    pub const CLONE: u32 = 220;
    pub const EXECVE: u32 = 221;
    pub const WAIT4: u32 = 260;
    pub const FINIT_MODULE: u32 = 273;
}

// ── Filesystem limits ─────────────────────────────────────────────────
pub const NAME_MAX: usize = 255; // max filename component length

// ── File / mount flags ─────────────────────────────────────────────────
pub const AT_FDCWD_NEG: u32 = 99; // for MOVN: ~99 = -100 = AT_FDCWD
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0x40;
pub const O_TRUNC: u32 = 0x200;
pub const MS_BIND: u32 = 0x1000;

// ── Signals ────────────────────────────────────────────────────────────
pub const SIGCHLD: u32 = 17;

// ── Terminal ───────────────────────────────────────────────────────────
pub const TIOCSCTTY: u32 = 0x540E;
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;

// ── Networking ─────────────────────────────────────────────────────────
pub const AF_INET: u32 = 2;
pub const SOCK_DGRAM: u32 = 2;
pub const SIOCSIFADDR: u32 = 0x8916;
pub const SIOCSIFNETMASK: u32 = 0x891C;
pub const SIOCSIFFLAGS: u32 = 0x8914;
pub const SIOCADDRT: u32 = 0x890B;
pub const IFF_UP: u32 = 0x1;
pub const RTF_UP: u32 = 0x1;
pub const RTF_GATEWAY: u32 = 0x2;
