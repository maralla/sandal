// The guest helpers' shared platform layer: compiled as a MODULE of
// the guest binary's crate (which declares #![no_std]).

use core::arch::asm;

// ── The ABI constants (arch-uniform: both kernels use the asm-generic
//    termios/signals and the same socket families) ────────────────────

pub const AF_VSOCK: usize = 40;
pub const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
pub const SOCK_STREAM: usize = 1;
pub const AT_FDCWD: usize = usize::MAX - 99; // -100
pub const O_RDWR: usize = 2;
pub const MAP_SHARED: usize = 1;
pub const PROT_READ_WRITE: usize = 3;
pub const POLLIN: i16 = 0x001;
pub const POLLOUT: i16 = 0x004;
pub const SIGCHLD: usize = 17;
pub const SIGPIPE: usize = 13;
pub const SIGKILL: usize = 9;
pub const SIGTSTP: usize = 20;
pub const SIG_IGN: usize = 1;
pub const SIG_DFL: usize = 0;
pub const EINTR: isize = 4;
pub const EAGAIN: isize = 11;
pub const FIONBIO: usize = 0x5421;
pub const TIOCSPTLCK: usize = 0x4004_5431;
pub const TIOCGPTPEER: usize = 0x5441;
pub const TIOCSWINSZ: usize = 0x5414;
pub const TIOCSPGRP: usize = 0x5410;
pub const TIOCSCTTY: usize = 0x540E;

// ── The syscall numbers (per arch) ──────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub mod nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const POLL: usize = 7;
    pub const MMAP: usize = 9;
    pub const CLOSE: usize = 3;
    pub const IOCTL: usize = 16;
    pub const RT_SIGACTION: usize = 13;
    pub const GETPID: usize = 39;
    pub const SOCKET: usize = 41;
    pub const ACCEPT: usize = 43;
    pub const CLONE: usize = 56;
    pub const EXIT: usize = 60;
    pub const WAIT4: usize = 61;
    pub const KILL: usize = 62;
    pub const SETSID: usize = 112;
    pub const BIND: usize = 49;
    pub const LISTEN: usize = 50;
    pub const OPENAT: usize = 257;
    pub const DUP3: usize = 292;
    pub const EXECVE: usize = 59;
}

#[cfg(target_arch = "aarch64")]
pub mod nr {
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const PPOLL: usize = 73;
    pub const MMAP: usize = 222;
    pub const CLOSE: usize = 57;
    pub const IOCTL: usize = 29;
    pub const RT_SIGACTION: usize = 134;
    pub const GETPID: usize = 172;
    pub const SOCKET: usize = 198;
    pub const ACCEPT: usize = 202;
    pub const CLONE: usize = 220;
    pub const EXIT: usize = 93;
    pub const WAIT4: usize = 260;
    pub const KILL: usize = 129;
    pub const SETSID: usize = 157;
    pub const BIND: usize = 200;
    pub const LISTEN: usize = 201;
    pub const OPENAT: usize = 56;
    pub const DUP3: usize = 24;
    pub const EXECVE: usize = 221;
}

// ── The raw syscall entry (per arch) ────────────────────────────────
//
// x86_64: nr in rax, args rdi/rsi/rdx/r10/r8/r9, the return in rax,
// rcx/r11 clobbered. aarch64: nr in x8, args x0-x5, the return in x0.

#[cfg(target_arch = "x86_64")]
unsafe fn raw(nr: usize, a: &[usize; 6]) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
            in("r10") a[3], in("r8") a[4], in("r9") a[5],
            lateout("rcx") _, lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn raw(nr: usize, a: &[usize; 6]) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a[0] => ret,
            in("x1") a[1], in("x2") a[2], in("x3") a[3],
            in("x4") a[4], in("x5") a[5], in("x8") nr,
            options(nostack)
        );
    }
    ret
}

/// The uniform syscall: nr + up to 6 args, the rest zero.
pub fn syscall(nr: usize, a: [usize; 6]) -> isize {
    unsafe { raw(nr, &a) }
}

// ── The arch-uniform wrappers ───────────────────────────────────────

pub fn read(fd: i32, buf: &mut [u8]) -> isize {
    syscall(nr::READ, [fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0])
}

pub fn write(fd: i32, buf: &[u8]) -> isize {
    syscall(nr::WRITE, [fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0])
}

pub fn close(fd: i32) -> isize {
    syscall(nr::CLOSE, [fd as usize, 0, 0, 0, 0, 0])
}

pub fn ioctl3(fd: i32, cmd: usize, arg: usize) -> isize {
    syscall(nr::IOCTL, [fd as usize, cmd, arg, 0, 0, 0])
}

pub fn mmap(len: usize, fd: i32, offset: usize) -> isize {
    syscall(nr::MMAP, [0, len, PROT_READ_WRITE, MAP_SHARED, fd as usize, offset])
}

pub fn munmap(addr: usize, len: usize) -> isize {
    syscall(11, [addr, len, 0, 0, 0, 0])
}

pub fn socket() -> i32 {
    syscall(nr::SOCKET, [AF_VSOCK, SOCK_STREAM, 0, 0, 0, 0]) as i32
}

pub fn bind(fd: i32, addr: &SockAddrVm) -> isize {
    syscall(nr::BIND, [fd as usize, addr as *const SockAddrVm as usize, 16, 0, 0, 0])
}

pub fn listen(fd: i32, backlog: i32) -> isize {
    syscall(nr::LISTEN, [fd as usize, backlog as usize, 0, 0, 0, 0])
}

pub fn accept(fd: i32) -> i32 {
    syscall(nr::ACCEPT, [fd as usize, 0, 0, 0, 0, 0]) as i32
}

/// clone(SIGCHLD, 0, 0, 0, 0) — the fork() equivalent, both arches.
pub fn fork() -> i32 {
    syscall(nr::CLONE, [SIGCHLD, 0, 0, 0, 0, 0]) as i32
}

pub fn execve(path: &[u8], argv: &[*const u8], envp: usize) -> isize {
    syscall(nr::EXECVE, [
        path.as_ptr() as usize,
        argv.as_ptr() as usize,
        envp,
        0, 0, 0,
    ])
}

pub fn wait4(pid: i32, status: &mut i32) -> isize {
    syscall(nr::WAIT4, [pid as usize, status as *mut i32 as usize, 0, 0, 0, 0])
}

pub fn kill(pid: i32, sig: usize) -> isize {
    syscall(nr::KILL, [pid as usize, sig, 0, 0, 0, 0])
}

pub fn setsid() -> isize {
    syscall(nr::SETSID, [0, 0, 0, 0, 0, 0])
}

pub fn getpid() -> i32 {
    syscall(nr::GETPID, [0, 0, 0, 0, 0, 0]) as i32
}

pub fn dup3(fd: i32, newfd: i32) -> i32 {
    syscall(nr::DUP3, [fd as usize, newfd as usize, 0, 0, 0, 0]) as i32
}

pub fn exit(code: usize) -> ! {
    let _ = syscall(nr::EXIT, [code, 0, 0, 0, 0, 0]);
    unreachable!()
}

/// poll(fds, timeout): x86_64 poll(2) (the ms timeout); aarch64 has no
/// poll — ppoll(2) with the timeout as a timespec (negative: infinite).
pub fn poll(fds: &mut [PollFd], timeout_ms: i32) -> isize {
    #[cfg(target_arch = "x86_64")]
    {
        syscall(nr::POLL, [
            fds.as_mut_ptr() as usize,
            fds.len(),
            timeout_ms as isize as usize, // -1 sign-extends
            0, 0, 0,
        ])
    }
    #[cfg(target_arch = "aarch64")]
    {
        if timeout_ms < 0 {
            syscall(nr::PPOLL, [
                fds.as_mut_ptr() as usize, fds.len(), 0, 0, 0, 0,
            ])
        } else {
            let ts = [
                (timeout_ms as u64 / 1000) as usize,
                ((timeout_ms as u64 % 1000) * 1_000_000) as usize,
            ];
            syscall(nr::PPOLL, [
                fds.as_mut_ptr() as usize,
                fds.len(),
                ts.as_ptr() as usize,
                0, 0, 0,
            ])
        }
    }
}

pub fn rt_sigaction(sig: usize, handler: usize) -> isize {
    let act = SigAction { handler, flags: 0, restorer: 0, mask: 0 };
    syscall(nr::RT_SIGACTION, [
        sig,
        &act as *const SigAction as usize,
        0, // the old action: not needed
        8, // the sigset size
        0, 0,
    ])
}

// ── The ABI structs (repr(C): the kernel's own layouts) ─────────────

#[repr(C)]
pub struct SockAddrVm {
    pub family: u16,
    pub reserved: u16,
    pub port: u32,
    pub cid: u32,
    pub zero: u32,
}

#[repr(C)]
pub struct WinSize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[repr(C)]
pub struct SigAction {
    pub handler: usize, // SIG_DFL = 0, SIG_IGN = 1 (no fn: no restorer)
    pub flags: usize,
    pub restorer: usize,
    pub mask: u64,
}

// ── The environment (walked once at the entry from the initial stack) ──

static ENVP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn envp() -> usize {
    ENVP.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn capture_env(rsp: usize) {
    // [rsp] = argc, [rsp+8..] = argv[0..argc], NULL, envp[0..], NULL
    let argc = unsafe { (rsp as *const usize).read() };
    let mut p = rsp + core::mem::size_of::<usize>();
    let mut left = argc;
    while left > 0 {
        if unsafe { (p as *const usize).read() } == 0 {
            break;
        }
        p += core::mem::size_of::<usize>();
        left -= 1;
    }
    p += core::mem::size_of::<usize>(); // the argv NULL
    ENVP.store(p, core::sync::atomic::Ordering::Relaxed);
}

/// Read an env var's VALUE (the bytes after '=') as a bounded slice.
pub fn env_get(key: &[u8]) -> Option<&'static [u8]> {
    let mut p = envp() as *const usize;
    if p.is_null() {
        return None;
    }
    loop {
        let entry = unsafe { p.read() };
        if entry == 0 {
            return None;
        }
        let s = entry as *const u8;
        let mut i = 0usize;
        loop {
            let b = unsafe { (s as *const u8).add(i).read() };
            if b == b'=' {
                if i == key.len() {
                    let start = entry + i + 1;
                    let mut n = 0usize;
                    while n < 4096 && unsafe { ((start as *const u8).add(n)).read() } != 0 {
                        n += 1;
                    }
                    return Some(unsafe {
                        core::slice::from_raw_parts(start as *const u8, n)
                    });
                }
                break;
            }
            if i >= key.len() || b != key[i] {
                break;
            }
            i += 1;
        }
        p = unsafe { p.add(1) };
    }
}

/// The hypercall page's guest-physical address from the HYPERCALL env
/// var (decimal; the VMM injects it). Zero: not present.
#[cfg(target_arch = "x86_64")]
pub fn hyper_addr() -> u64 {
    match env_get(b"HYPERCALL") {
        Some(v) if !v.is_empty() => {
            let mut addr: u64 = 0;
            for &b in v {
                let d = match b {
                    b'0'..=b'9' => (b - b'0') as u64,
                    _ => break,
                };
                addr = addr.wrapping_mul(10).wrapping_add(d);
            }
            addr
        }
        _ => 0,
    }
}

// ── The VM signal channel (per arch) ────────────────────────────────
//
// The port values are shared with the VMM's dispatch: the x86_64 ports
// live in elf/x86_64_linux.rs; the aarch64 immediates in initramfs.rs
// (the same "SanDal N" numbering).

/// x86_64: the READY port constant (the value the VMM's dispatch matches).
#[cfg(target_arch = "x86_64")]
pub const VM_SIGNAL_READY: u32 = 0x5D6;
/// x86_64: the exit signal constant (the code rides the high half).
#[cfg(target_arch = "x86_64")]
pub const VM_SIGNAL_EXIT: u32 = 0x5D5;

/// The VM signal: the command execution line's readiness — the raw
/// store (the value the VMM's dispatch matches).
#[cfg(target_arch = "x86_64")]
pub fn signal_ready_store() {
    hyper_store(VM_SIGNAL_READY);
}

/// The VM signal: the command execution line's readiness (the listener
/// is bound — the VMM connects every parked front end).
pub fn signal_ready() {
    #[cfg(target_arch = "x86_64")]
    hyper_store(VM_SIGNAL_READY);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("brk #0x5d6", options(nomem, nostack));
    }
}

/// The VM signal: the session's exit (the code rides the signal: the
/// x86_64 high half / the aarch64 x15). The VM dies here whatever the
/// transport managed.
pub fn exit_vm(code: u8) {
    #[cfg(target_arch = "x86_64")]
    hyper_store((VM_SIGNAL_EXIT as u32) | ((code as u32) << 16));
    #[cfg(target_arch = "aarch64")]
    {
        let code_reg = code as usize;
        unsafe {
            asm!(
                "mov x15, {}",
                "brk #0x5d5",
                in(reg) code_reg,
                options(nomem, nostack)
            );
        }
    }
}

/// The ring-3-safe debug channel: a store to the hypercall page with an
/// unused value — the VMM's log records "unknown hypercall 0x300N" at
/// -v. (The UART's `out` instruction is privileged and GP-faults
/// userspace — the machine-code draft died on exactly that.) Off by
/// default; flip for the guest-side bisection.
pub fn debug_event(stage: u32) {
    const DEBUG_TRACE: bool = false;
    if DEBUG_TRACE {
        #[cfg(target_arch = "x86_64")]
        hyper_store(0x3000 | stage);
        #[cfg(target_arch = "aarch64")]
        unsafe {
            asm!("brk #0x3000", options(nomem, nostack));
        }
    }
}

// ── The /dev/mem store (x86_64 only; the aarch64 signals are BRKs) ──

#[cfg(target_arch = "x86_64")]
fn hyper_store(value: u32) {
    let addr = hyper_addr();
    if addr == 0 {
        return;
    }
    let path = b"/dev/mem\0";
    let fd = syscall(nr::OPENAT, [
        AT_FDCWD, path.as_ptr() as usize, O_RDWR, 0, 0, 0,
    ]) as i32;
    if fd < 0 {
        return;
    }
    let base = mmap(0x1000, fd, (addr & !0xFFF) as usize);
    close(fd);
    if base < 0 {
        return;
    }
    let ptr = (base as usize + (addr & 0xFFF) as usize) as *mut u32;
    unsafe {
        ptr.write_volatile(value);
    }
    let _ = munmap(base as usize, 0x1000);
}

// ── The entry shim (per arch): the args' rsp captured naked ────────
//
// naked_asm has no prologue: the rsp at the shim IS the kernel's exec
// stack (argc/argv/envp). The shim passes it to the binary's entry fn
// (guest_entry — defined by each binary, exported #[no_mangle]).

/// The guest entry: the args' rsp captured naked by the shim, handed
/// here as the argument (no prologue touched it).
#[no_mangle]
pub extern "C" fn guest_entry_shim(rsp: usize) -> ! {
    crate::guest_entry(rsp)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "call {}",
        sym guest_entry_shim,
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x0, sp",
        "bl {}",
        sym guest_entry_shim,
    );
}

// ── The shared protocol helpers ─────────────────────────────────────

pub const CMD_MAX: usize = 65535;
pub const HOLD_LEN: usize = 64 * 1024;
pub const GEO_MAX: u32 = 4096;
pub const BACKLOG: i32 = 64;
pub const BOUND_POLLS: u32 = 300;

pub const MAGIC: &[u8; 16] = b"VSOCKD:EXIT:01\n\0";

pub fn nap100() {
    let ts = [0usize, 100_000_000usize];
    let _ = syscall(35, [ts.as_ptr() as usize, 0, 0, 0, 0, 0]);
}

pub fn set_nonblock(fd: i32) {
    // FIONBIO with the int 1 at the arg pointer
    let one: i32 = 1;
    let _ = ioctl3(fd, FIONBIO, &one as *const i32 as usize);
}

pub fn open_dev_ptmx() -> i32 {
    let path = b"/dev/ptmx\0";
    syscall(nr::OPENAT, [AT_FDCWD, path.as_ptr() as usize, O_RDWR, 0, 0, 0]) as i32
}

pub fn signal_pgrps(skip: i32, sig: usize) {
    let mut p: i32 = 2;
    while p < 4096 {
        if p != skip {
            let _ = kill(-p, sig);
        }
        p += 1;
    }
}

pub fn status_byte(status: i32) -> u8 {
    if status & 0x7F != 0 {
        (128 + (status & 0x7F)) as u8
    } else {
        ((status >> 8) & 0xFF) as u8
    }
}

/// The trailer chunk on a NONBLOCKING fd (mode 0x02/0x03): poll POLLOUT
/// between attempts, BOUND_POLLS then give up. The chunk lands whole or
/// not at all.
pub fn write_chunk_bounded(fd: i32, mut chunk: &[u8]) -> bool {
    let mut polls = 0u32;
    while !chunk.is_empty() {
        let n = write(fd, chunk);
        if n > 0 {
            chunk = &chunk[n as usize..];
            continue;
        }
        if n == -EINTR {
            continue;
        }
        polls += 1;
        if polls > BOUND_POLLS {
            return false;
        }
        let mut pfd = [PollFd { fd, events: POLLOUT, revents: 0 }];
        let _ = poll(&mut pfd, 100);
    }
    true
}

/// The trailer chunk on a BLOCKING fd (mode 0x01): EINTR-safe, the
/// kernel's own blocking does the pacing.
pub fn write_chunk_blocking(fd: i32, mut chunk: &[u8]) -> bool {
    while !chunk.is_empty() {
        let n = write(fd, chunk);
        if n > 0 {
            chunk = &chunk[n as usize..];
            continue;
        }
        if n == -EINTR {
            continue;
        }
        return false;
    }
    true
}

pub fn write_trailer(fd: i32, bounded: bool, status: u8) -> bool {
    if bounded {
        write_chunk_bounded(fd, MAGIC) && write_chunk_bounded(fd, &[status])
    } else {
        write_chunk_blocking(fd, MAGIC) && write_chunk_blocking(fd, &[status])
    }
}

pub fn read_whole(fd: i32, buf: &mut [u8]) {
    let mut done = 0usize;
    while done < buf.len() {
        let n = read(fd, &mut buf[done..]);
        if n > 0 {
            done += n as usize;
        } else if n == -EINTR {
            continue;
        } else {
            // EOF or a hard error: nothing runs
            exit(124);
        }
    }
}
