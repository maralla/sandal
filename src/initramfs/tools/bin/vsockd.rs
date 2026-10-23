//! The vsockd guest binary: the command execution line's protocol logic.
//!
//! Architecture-agnostic: the per-arch syscall layer, the VM signal
//! channel and the entry shim live in `common.rs` (shared by the
//! binaries in this directory). Compiled by build.rs with rustc for
//! `{arch}-unknown-none`.
//!
//! The protocol (the C draft's doc IS the reference; the essentials):
//! every connection opens with one header {mode: u8, rows: u16, cols:
//! u16, cmd_len: u32} + the command line. Mode 0x01: the command runs
//! with the connection as its stdio; the child waits and writes the
//! 17-byte status trailer. Mode 0x02/0x03: a REAL pty pair, the session
//! child on the slave as its controlling terminal, and the bridge
//! pumping the connection against the pty master (nonblocking poll,
//! per-direction POLLOUT arming, 64 KiB holds, the RSZ1 strip, the
//! signal translation); the reaper: the insurance kill, the wait, the
//! bounded trailer, and — mode 0x03 only — the exit hypercall.

#![no_std]
#![no_main]

#[macro_use]
mod common;

use common::*;

/// The panic floor: no_std has no unwinding — the exit code 126 (the
/// generic failure).
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    exit(126)
}

// ── mode 0x01: the one-shot ─────────────────────────────────────────
//
// The command runs as a grandchild with the connection as its stdio;
// the child waits and writes the trailer (the BLOCKING fd: the write
// blocks until it lands — the kernel does the pacing).

fn mode_oneshot(conn: i32, cmd: &[u8], envp: usize) {
    let _ = rt_sigaction(SIGCHLD, SIG_DFL);
    let sh = b"/bin/sh\0";
    let dashc = b"-c\0";
    let argv = [sh.as_ptr(), dashc.as_ptr(), cmd.as_ptr(), core::ptr::null()];
    let pid = fork();
    if pid < 0 {
        exit(124);
    }
    if pid == 0 {
        // the grandchild: the connection IS its stdio
        let _ = dup3(conn, 0);
        let _ = dup3(conn, 1);
        let _ = dup3(conn, 2);
        if conn > 2 {
            let _ = close(conn);
        }
        let _ = execve(sh, &argv, envp);
        exit(125);
    }
    // the child: the wait, the trailer
    let mut status = 0i32;
    while wait4(pid, &mut status) == -EINTR {}
    write_trailer(conn, false, status_byte(status));
    exit(0);
}

// ── The input strip: the RSZ1 records + the signal translation ──────

fn strip_input(master: i32, session_pid: i32, input: &mut [u8]) -> usize {
    let mut used = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        match b {
            0x03 | 0x1c => {
                signal_pgrps(session_pid, SIGKILL);
                i += 1;
            }
            0x1a => {
                signal_pgrps(session_pid, SIGTSTP);
                i += 1;
            }
            _ => {
                if input.len() - i >= 8 && &input[i..i + 4] == b"RSZ1" {
                    let cols = u16::from_le_bytes([input[i + 4], input[i + 5]]);
                    let rows = u16::from_le_bytes([input[i + 6], input[i + 7]]);
                    if cols >= 1 && cols as u32 <= GEO_MAX && rows >= 1 && rows as u32 <= GEO_MAX
                    {
                        let ws = WinSize {
                            row: rows,
                            col: cols,
                            xpixel: 0,
                            ypixel: 0,
                        };
                        let _ = ioctl3(master, TIOCSWINSZ, &ws as *const WinSize as usize);
                        i += 8;
                        continue;
                    }
                }
                input[used] = b;
                used += 1;
                i += 1;
            }
        }
    }
    used
}

// ── mode 0x02/0x03: the pty bridge ──────────────────────────────────
//
// The bridge: poll({conn, master}, -1), per-direction POLLOUT arming,
// 64 KiB holds, a backed-up direction is not read from. The death paths
// (EOF or a hard error on either side) funnel into the reaper.

fn mode_pty_bridge(conn: i32, master: i32, session_pid: i32, _envp: usize,
                   own_lifetime: bool) {
    let mut in_buf = [0u8; HOLD_LEN];
    let mut out_buf = [0u8; HOLD_LEN];
    let mut in_off = 0usize;
    let mut in_len = 0usize;
    let mut out_off = 0usize;
    let mut out_len = 0usize;
    let mut pfds = [
        PollFd { fd: conn, events: POLLIN, revents: 0 },
        PollFd { fd: master, events: POLLIN, revents: 0 },
    ];

    loop {
        pfds[0].events = POLLIN | (if out_len > 0 { POLLOUT } else { 0 });
        pfds[1].events = POLLIN | (if in_len > 0 { POLLOUT } else { 0 });
        if poll(&mut pfds, -1) == -EINTR {
            continue;
        }

        // the conn side: any event, not just POLLIN (an EOF-only socket
        // reports POLLIN; relying on that bit alone loses the close)
        if pfds[0].revents != 0 && in_len == 0 {
            let r = read(conn, &mut in_buf);
            if r > 0 {
                let n = r as usize;
                in_len = strip_input(master, session_pid, &mut in_buf[..n]);
                in_off = 0;
            } else if r == 0 || (r < 0 && r != -EINTR && r != -EAGAIN) {
                break; // the transport is gone: the reaper
            }
        }

        // the master side: ANY event, never POLLIN alone (the session's
        // death reports POLLHUP without POLLIN once the queue drains)
        if pfds[1].revents != 0 && out_len == 0 {
            let r = read(master, &mut out_buf);
            if r > 0 {
                out_len = r as usize;
                out_off = 0;
            } else if r == 0 || (r < 0 && r != -EINTR && r != -EAGAIN) {
                break; // the session is dead: the reaper
            }
        }

        // flush the input hold → the master (EAGAIN: the hold waits,
        // POLLOUT armed; a hard error drains it — the master's next
        // read fails and the reaper fires)
        while in_off < in_len {
            let w = write(master, &in_buf[in_off..in_len]);
            if w > 0 {
                in_off += w as usize;
            } else if w == -EINTR {
                continue;
            } else if w == -EAGAIN {
                break;
            } else {
                in_len = 0;
                break;
            }
        }
        if in_off >= in_len {
            in_off = 0;
            in_len = 0;
        }

        // flush the output hold → the connection (the vsock's send side
        // is bounded by the credit window; the remainder waits with
        // POLLOUT armed; EPIPE: drained, the loop's next master read
        // ends it)
        while out_off < out_len {
            let w = write(conn, &out_buf[out_off..out_len]);
            if w > 0 {
                out_off += w as usize;
            } else if w == -EINTR {
                continue;
            } else if w == -EAGAIN {
                break;
            } else {
                out_len = 0;
                break;
            }
        }
        if out_off >= out_len {
            out_off = 0;
            out_len = 0;
        }
    }

    // ── the reaper: bounded phases, no spin ─────────────────────────
    let _ = kill(session_pid, SIGKILL);
    let mut status = 0i32;
    while wait4(session_pid, &mut status) == -EINTR {}
    let _ = rt_sigaction(SIGCHLD, SIG_IGN);
    write_trailer(conn, true, status_byte(status));
    if own_lifetime {
        // the exit hypercall: the status forwards deterministically,
        // the VM dies here whatever the transport managed
        exit_vm(status_byte(status));
    }
    exit(0);
}

// ── mode 0x02/0x03: the pty pair + the session child + the bridge ──

fn mode_pty(conn: i32, cmd: &[u8], envp: usize, rows: u32, cols: u32,
            own_lifetime: bool) {
    // the pty pair: openpt → unlock → the slave fd straight from the
    // master (TIOCGPTPEER's flags argument IS the peer's open flags)
    let master = open_dev_ptmx();
    if master < 0 {
        exit(124);
    }
    if ioctl3(master, TIOCSPTLCK, &0i32 as *const i32 as usize) != 0 {
        exit(124);
    }
    let slave = ioctl3(master, TIOCGPTPEER, O_RDWR) as i32;
    if slave < 0 {
        exit(124);
    }
    // the header's own geometry, applied BEFORE the fork (no session
    // exists yet, so the kernel's SIGWINCH lands on nobody)
    if rows >= 1 && rows <= GEO_MAX && cols >= 1 && cols <= GEO_MAX {
        let ws = WinSize {
            row: rows as u16,
            col: cols as u16,
            xpixel: 0,
            ypixel: 0,
        };
        let _ = ioctl3(master, TIOCSWINSZ, &ws as *const WinSize as usize);
    }
    // the bridge must WAIT for the session: SIGCHLD back to SIG_DFL
    let _ = rt_sigaction(SIGCHLD, SIG_DFL);
    let pid = fork();
    if pid < 0 {
        exit(124);
    }
    if pid == 0 {
        // ── the session child ──
        // Own session, the slave dup'd onto 0/1/2 as the controlling
        // terminal, the foreground pgrp pre-set to its own pid (the
        // shell's job-control check passes, the tty's signal path has a
        // target), then the shared exec tail.
        let _ = setsid();
        let _ = close(master);
        let _ = close(conn);
        let _ = dup3(slave, 0);
        let _ = dup3(slave, 1);
        let _ = dup3(slave, 2);
        if slave > 2 {
            let _ = close(slave);
        }
        // TIOCSCTTY: force-steal (the arg is 1, a value)
        let _ = ioctl3(0, TIOCSCTTY, 1);
        let pgrp = getpid();
        let _ = ioctl3(0, TIOCSPGRP, &pgrp as *const i32 as usize);
        let sh = b"/bin/sh\0";
        let dashc = b"-c\0";
        let argv = [sh.as_ptr(), dashc.as_ptr(), cmd.as_ptr(), core::ptr::null()];
        let _ = execve(sh, &argv, envp);
        exit(125);
    }
    // ── the bridge (the parent) ──
    let _ = close(slave); // the parent's slave copy closes
    let _ = rt_sigaction(SIGPIPE, SIG_IGN);
    set_nonblock(conn);
    set_nonblock(master);
    mode_pty_bridge(conn, master, pid, envp, own_lifetime);
    exit(124); // never reached
}

// ── The connection child: the header, the command, the dispatch ────

fn child(conn: i32, envp: usize) {
    let mut hdr = [0u8; 9];
    let mut cmd = [0u8; CMD_MAX + 1];

    debug_event(0x1);
    read_whole(conn, &mut hdr);
    let mode = hdr[0] as usize;
    let rows = u16::from_le_bytes([hdr[1], hdr[2]]) as u32;
    let cols = u16::from_le_bytes([hdr[3], hdr[4]]) as u32;
    let cmd_len = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if cmd_len == 0 || cmd_len > CMD_MAX {
        exit(124);
    }
    debug_event(0x2);
    read_whole(conn, &mut cmd[..cmd_len]);
    debug_event(0x3);
    // the NUL: the command is a C string for execve's argv
    cmd[cmd_len] = 0;

    match mode {
        1 => mode_oneshot(conn, &cmd[..cmd_len], envp),
        2 => mode_pty(conn, &cmd[..cmd_len], envp, rows, cols, false),
        3 => mode_pty(conn, &cmd[..cmd_len], envp, rows, cols, true),
        _ => exit(124),
    }
    exit(124);
}

// ── The readiness event + the stage traces ──────────────────────────

fn signal_ready() {
    debug_event(0x0);
    common::signal_ready();
}

// ── The accept loop ─────────────────────────────────────────────────

fn main_logic(port: u32, envp: usize) -> ! {
    let lfd = socket();
    if lfd < 0 {
        exit(120);
    }
    let addr = SockAddrVm {
        family: AF_VSOCK as u16,
        reserved: 0,
        port,
        cid: 0xFFFF_FFFFu32 as usize as u32,
        zero: 0,
    };
    if bind(lfd, &addr) != 0 {
        exit(121);
    }
    if listen(lfd, BACKLOG) != 0 {
        exit(122);
    }
    signal_ready();
    let _ = rt_sigaction(SIGCHLD, SIG_IGN);

    loop {
        let conn = accept(lfd);
        if conn < 0 {
            nap100();
            continue;
        }
        let pid = fork();
        if pid < 0 {
            let _ = close(conn);
            nap100();
            continue;
        }
        if pid > 0 {
            // the parent: its conn copy closes; back to the accept
            let _ = close(conn);
            continue;
        }
        // the connection child: only the conn fd; the listen fd is the
        // parent's
        let _ = close(lfd);
        child(conn, envp);
        exit(124); // never reached
    }
}

// ── The shim's call target: the args' rsp captured naked ────────────

#[no_mangle]
pub extern "C" fn guest_entry(rsp: usize) -> ! {
    capture_env(rsp);
    // argv[1]: the port (bounded parse; garbage → 0 → exit 126)
    let argc = unsafe { (rsp as *const usize).read() };
    let argv_base = rsp + core::mem::size_of::<usize>();
    let mut port: u32 = 0;
    if argc >= 2 {
        let argp =
            unsafe { ((argv_base + core::mem::size_of::<usize>()) as *const usize).read() };
        let mut i = 0usize;
        while i < 6 {
            let b = unsafe { ((argp as *const u8).add(i)).read() };
            if b == 0 {
                break;
            }
            if (b as char).is_ascii_digit() {
                port = port.wrapping_mul(10).wrapping_add((b - b'0') as u32);
            } else {
                port = 0;
                break;
            }
            i += 1;
        }
    }
    if port == 0 || port > 65535 {
        exit(126);
    }
    main_logic(port, envp())
}
