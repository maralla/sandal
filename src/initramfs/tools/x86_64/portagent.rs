//! The crafted `portagent` x86_64 guest helper: the session agent.
//!
//! Bridges the interactive session between the virtio-console host device
//! port (/dev/virtio-ports/vport0p1) and a guest pty:
//!
//!   - the session runs on the pty SLAVE — a real tty: job control,
//!     signals, line editing and the tty's own echo, all with real
//!     semantics (a pty slave is claimable as a controlling terminal,
//!     unlike the console device);
//!   - the agent pumps whole buffers between the port fd and the pty
//!     MASTER — the port's per-exit rate instead of the console device's
//!     round trip per output line;
//!   - the terminal geometry comes from the command line (the VMM's
//!     advertised window, known at boot) and, later, from resize records
//!     the VMM injects into the port input stream — stripped and applied
//!     below.
//!
//! The parent is the reaper: the session's exit status is forwarded (the
//! init script's exit marker), 128+signal for signal deaths (the shell
//! convention).
//!
//! usage: portagent <port> <rows> <cols> <command> [args...]
//! exit:  120 = the port open failed, 121 = the pty setup failed,
//!        125 = the session exec failed, 126 = bad arguments,
//!        otherwise the session's status.
//!
//! Pure machine code, built with the x86_64 DSL — no toolchain, no
//! sibling binary. The program documentation below IS the reference —
//! the flow, the frame layout, the register plan, every bound — kept in
//! lockstep with the code it describes:
//!
//! ```text
//! r15 = the initial sp ([r15]=argc, [r15+8+8i]=argv[i]), r14 = argc
//! rsp -= FRAME (16-aligned): [rsp]=pollfd[2], [rsp+16]=the winsize,
//!       [rsp+24]=the wait status, [rsp+32]=the pty slave fd,
//!       [rsp+40]=nargv[64], [rsp+552]=in_buf, [rsp+4648]=out_buf
//! r13 = openat(argv[1], O_RDWR)              < 0 → exit(120)
//! r12 = openat("/dev/ptmx", O_RDWR)          < 0 → exit(121)
//! ioctl(r12, TIOCSPTLCK, &0)                 < 0 → exit(121)  (unlockpt)
//! [rsp+32] = ioctl(r12, TIOCGPTPEER, O_RDWR) < 0 → exit(121) (the slave)
//! rows = atol(argv[2]); cols = atol(argv[3]) — the boot geometry;
//!       each valid (1..=4096) → ioctl(r12, TIOCSWINSZ, {rows, cols}),
//!       applied to the pair BEFORE the fork (no session exists yet, so
//!       the kernel's SIGWINCH lands on nobody)
//! rbx = clone(SIGCHLD)                       < 0 → exit(121)
//! rbx == 0 → the SESSION: setsid, close(r12, r13), dup3(slave, 0/1/2),
//!       close(slave), ioctl(0, TIOCSCTTY, 1) — the pty slave as the
//!       controlling terminal — then execve(argv[4], nargv, envp) with
//!       "-i" forced when argc == 5, exit(125) if the exec failed
//! rbx > 0 → the BRIDGE: close(slave), then a poll loop:
//!       poll({r13, r12}, POLLIN, -1)
//!       r13 readable → read(r13, in_buf): ≤ 0 → nanosleep(100 ms);
//!         else strip every whole "RSZ1" record (valid →
//!         ioctl(r12, TIOCSWINSZ, {rows, cols}) — the kernel SIGWINCHs
//!         the session) and pump the remainder into r12 (partial writes
//!         retried until done)
//!       r12 readable → read(r12, out_buf): ≤ 0 → break (every slave fd
//!         is closed: the session is dead); else pump it into r13
//!       the reaper: kill(rbx, SIGKILL), wait4(-1, &status) — a signal
//!       death (status & 0xff) exits 128+signal; a normal exit forwards
//!       status >> 8
//! ```

use std::sync::OnceLock;

/// The crafted `portagent` guest helper (see the module documentation).
/// Pure machine code, built with the x86_64 DSL — no toolchain.
#[cfg(target_arch = "x86_64")]
static PORTAGENT_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn portagent_helper() -> &'static [u8] {
    PORTAGENT_HELPER.get_or_init(build_portagent_elf)
}

// The stack frame (below the initial sp; 16-aligned):
//   +0     pollfd[2]        (16 bytes: fd:i32, events:i16, revents:i16 ×2)
//   +16    the winsize      (8 bytes: rows | cols<<16 — TIOCSWINSZ's arg)
//   +24    the wait status  (8 bytes: wait4's status output)
//   +32    the pty slave fd (8 bytes: survives the geometry block)
//   +40    nargv[64]        (512 bytes: the child's execve argv)
//   +552   in_buf           (4096 bytes)
//   +4648  out_buf          (4096 bytes)
//   FRAME = 8752 (rounded up to the 16-byte alignment)
//
// Register plan (the x86_64 syscall ABI clobbers rax/rcx/r11 only):
//   r15 = the initial sp (argv/envp)     r13 = the port fd
//   r14 = argc (the child only)          r12 = the pty master fd
//   rbx = the child pid (the parent) / the nargv counter (the child)
//   rbp, r14 = the parent's scratch: the strip's end pointer, the write
//   pump's moving state
#[cfg(target_arch = "x86_64")]
fn build_portagent_elf() -> Vec<u8> {
    use crate::elf::x86_64::{
        add_i, add_rr_, and_r_imm, cmp_i, cmp_rr_, lea, load64, loadb_inc, loadzx16, loadzx32,
        mov_i, mov_rr_, shl_r_imm, shr_r_imm, store64, storeb_inc, sub_i, sub_rr_, sys, xclose,
        xdup3, xexit, xfork, xioctl_imm, xreg, xsetsid, xstrings, zero, Branch, X86ElfBuilder,
    };
    use crate::elf::x86_64_linux as lx;
    use crate::elf::x86_64_linux::nr;

    const FRAME: i32 = 8752;
    const WS: i32 = 16; // the winsize (TIOCSWINSZ's arg)
    const STATUS: i32 = 24; // wait4's status output
    const SLAVE: i32 = 32; // the pty slave fd
    const NARGV: i32 = 40; // the child's execve argv[64]
    const IN_BUF: i32 = 552;
    const OUT_BUF: i32 = 4648;
    const BUF_LEN: i32 = 4096;
    /// "RSZ1" as the record's LE u32 (the resize record's magic).
    const RESIZE_MAGIC: i32 = 0x315A_5352;
    /// cols/rows sanity: beyond any real window (4096: no real display).
    const RESIZE_MAX: i32 = 4095;
    /// The paced !host_connected retry: 100 ms.
    const NAP_NSEC: u64 = 100_000_000;
    /// AT_FDCWD — openat's cwd escape.
    const AT_FDCWD: i32 = -100;
    /// SIGKILL — the reaper's insurance kill.
    const SIGKILL: i32 = 9;

    // Forward branches: (placeholder offset, branch kind) pairs, patched
    // when their target block is emitted (see X86ElfBuilder::patch_branch).
    type Fwd = Vec<(usize, Branch)>;
    let mut e = X86ElfBuilder::new();
    let fwd =
        |e: &mut X86ElfBuilder, br: Branch| -> (usize, Branch) { (e.branch_placeholder(br), br) };
    let patch = |e: &mut X86ElfBuilder, v: &mut Fwd| {
        for (at, br) in v.drain(..) {
            e.patch_branch(at, br);
        }
    };

    // The data section, addressed rip-relative (lea!): the ptmx path, the
    // forced "-i", the TIOCSPTLCK zero argument, the nanosleep timespec.
    xstrings!(e, s_ptmx = "/dev/ptmx", s_mi = "-i",);
    let s_zero = e.emit_data_bytes(&[0u8; 8]);
    let s_nap = e.emit_data_bytes(&{
        let mut b = [0u8; 16];
        b[8..].copy_from_slice(&NAP_NSEC.to_le_bytes());
        b
    });

    // ── Entry: the register plan and the frame ─────────────────────
    mov_rr_!(e, r15, rsp); // r15 = the initial sp
    load64!(e, r14, r15, 0); // r14 = argc
    mov_rr_!(e, rax, r15);
    sub_i!(e, rax, FRAME);
    mov_rr_!(e, rsp, rax); // rsp = the frame (16-aligned)

    // argc < 5 → exit(126): no port, no geometry, no command.
    cmp_i!(e, r14, 5);
    let mut p_exit126 = vec![fwd(&mut e, Branch::Jl)];

    // ── The transport: the virtio-console host device port ─────────
    // port = openat(AT_FDCWD, argv[1], O_RDWR). Manual: the path is a
    // register (argv[1]), not a data string.
    load64!(e, rsi, r15, 16); // rsi = argv[1]
    mov_i!(e, rdi, AT_FDCWD);
    mov_i!(e, rdx, lx::O_RDWR as i32);
    sys!(e, nr::OPENAT);
    mov_rr_!(e, r13, rax); // r13 = the port fd
    cmp_i!(e, r13, 0);
    let mut p_exit120 = vec![fwd(&mut e, Branch::Jl)]; // port < 0

    // ── The pty pair ──────────────────────────────────────────────
    // master = openat(AT_FDCWD, "/dev/ptmx", O_RDWR), then unlock the
    // pair (ptys are created LOCKED; without the unlock the slave open
    // fails EIO), then take the slave fd straight from the master
    // (TIOCGPTPEER's flags argument IS the peer fd's open flags — O_RDWR,
    // or every session write fails EBADF). No /dev/pts path lookup.
    let mut p_exit121: Fwd = vec![];
    lea!(e, rsi, s_ptmx);
    mov_i!(e, rdi, AT_FDCWD);
    mov_i!(e, rdx, lx::O_RDWR as i32);
    sys!(e, nr::OPENAT);
    mov_rr_!(e, r12, rax); // r12 = the pty master fd
    cmp_i!(e, r12, 0);
    p_exit121.push(fwd(&mut e, Branch::Jl)); // master < 0

    // ioctl(master, TIOCSPTLCK, &zero) — unlockpt(0).
    mov_rr_!(e, rdi, r12);
    mov_i!(e, rsi, lx::TIOCSPTLCK as i32);
    lea!(e, rdx, s_zero);
    sys!(e, nr::IOCTL);
    cmp_i!(e, rax, 0);
    p_exit121.push(fwd(&mut e, Branch::Jl)); // unlock failed

    // slave = ioctl(master, TIOCGPTPEER, O_RDWR) — parked in the frame
    // (it must survive the geometry block below).
    mov_rr_!(e, rdi, r12);
    mov_i!(e, rsi, lx::TIOCGPTPEER as i32);
    mov_i!(e, rdx, lx::O_RDWR as i32);
    sys!(e, nr::IOCTL);
    store64!(e, rsp, SLAVE, rax);
    cmp_i!(e, rax, 0);
    p_exit121.push(fwd(&mut e, Branch::Jl)); // no peer fd

    // ── The boot geometry ─────────────────────────────────────────
    // rows = atol(argv[2]), cols = atol(argv[3]) — the VMM's advertised
    // window, passed on the command line, known at boot, long before any
    // tty exists. Applied to the pair BEFORE the fork so both sides see
    // it; no session exists yet, so the SIGWINCH the kernel fires lands
    // on nobody. Valid (1..=4096 each) or skipped — never garbage.
    //
    // atol: the moving pointer rides rsi (loadb_inc advances it); the
    // accumulator rides rbx (rows) then rbp (cols) — both free until
    // the fork overwrites rbx with the pid. v*10 = (v<<3) + (v<<1);
    // the digit check is signed (the zx byte is 0..255, so jl/jg bound
    // it exactly), and a non-digit lands on the exit fall-through.
    let mut p_atol: Fwd = vec![];
    load64!(e, rsi, r15, 24); // rsi = argv[2] (rows)
    zero!(e, rbx);
    let atol_rows = e.offset();
    loadb_inc!(e, rax, rsi);
    cmp_i!(e, rax, b'0' as i32);
    p_atol.push(fwd(&mut e, Branch::Jl));
    cmp_i!(e, rax, b'9' as i32);
    p_atol.push(fwd(&mut e, Branch::Jg));
    mov_rr_!(e, rdx, rbx);
    e.emit(&shl_r_imm(xreg!(rdx), 3)); // v<<3
    mov_rr_!(e, rcx, rbx);
    e.emit(&shl_r_imm(xreg!(rcx), 1)); // v<<1
    add_rr_!(e, rdx, rcx); // v*10
    sub_i!(e, rax, b'0' as i32);
    add_rr_!(e, rdx, rax); // v*10 + digit
    mov_rr_!(e, rbx, rdx);
    e.branch_back(Branch::Jmp, atol_rows);
    patch(&mut e, &mut p_atol); // rows done (rbx); fall through

    load64!(e, rsi, r15, 32); // rsi = argv[3] (cols)
    zero!(e, rbp);
    let atol_cols = e.offset();
    loadb_inc!(e, rax, rsi);
    cmp_i!(e, rax, b'0' as i32);
    p_atol.push(fwd(&mut e, Branch::Jl));
    cmp_i!(e, rax, b'9' as i32);
    p_atol.push(fwd(&mut e, Branch::Jg));
    mov_rr_!(e, rdx, rbp);
    e.emit(&shl_r_imm(xreg!(rdx), 3));
    mov_rr_!(e, rcx, rbp);
    e.emit(&shl_r_imm(xreg!(rcx), 1));
    add_rr_!(e, rdx, rcx);
    sub_i!(e, rax, b'0' as i32);
    add_rr_!(e, rdx, rax);
    mov_rr_!(e, rbp, rdx);
    e.branch_back(Branch::Jmp, atol_cols);
    patch(&mut e, &mut p_atol); // cols done (rbp); fall through

    // The winsize qword FIRST (parked in rdx — the checks below mutate
    // rbx/rbp): rows | cols<<16 = {rows, cols, 0, 0}.
    mov_rr_!(e, rdx, rbx); // rows
    mov_rr_!(e, rax, rbp); // cols
    e.emit(&shl_r_imm(xreg!(rax), 16));
    add_rr_!(e, rdx, rax); // ws_q
                           // Validity, 1..=4096 each: a zero value (Je) or an over-4096 value
                           // (after -1, Jg) skips the ioctl — the reference does the same.
    let mut p_skip_geo: Fwd = vec![];
    cmp_i!(e, rbx, 0); // rows
    p_skip_geo.push(fwd(&mut e, Branch::Je));
    sub_i!(e, rbx, 1);
    cmp_i!(e, rbx, RESIZE_MAX);
    p_skip_geo.push(fwd(&mut e, Branch::Jg));
    cmp_i!(e, rbp, 0); // cols
    p_skip_geo.push(fwd(&mut e, Branch::Je));
    sub_i!(e, rbp, 1);
    cmp_i!(e, rbp, RESIZE_MAX);
    p_skip_geo.push(fwd(&mut e, Branch::Jg));
    // ioctl(master, TIOCSWINSZ, &ws) — apply the boot geometry.
    store64!(e, rsp, WS, rdx);
    mov_rr_!(e, rdi, r12);
    mov_i!(e, rsi, lx::TIOCSWINSZ as i32);
    mov_rr_!(e, rdx, rsp);
    add_i!(e, rdx, WS);
    sys!(e, nr::IOCTL);
    patch(&mut e, &mut p_skip_geo); // skip: fall through to the fork

    // ── fork: the session (the child) and the bridge (the parent) ──
    xfork!(e);
    mov_rr_!(e, rbx, rax); // rbx = pid
    cmp_i!(e, rbx, 0);
    p_exit121.push(fwd(&mut e, Branch::Jl)); // clone failed
    cmp_i!(e, rbx, 0);
    let mut p_child = vec![fwd(&mut e, Branch::Je)]; // 0 → the child

    // ── The bridge (the parent) ───────────────────────────────────
    // close(slave): the bridge rides the port fd and the pty MASTER.
    load64!(e, rcx, rsp, SLAVE);
    xclose!(e, rcx);

    // The poll loop: pump whole buffers port <-> pty master.
    let l_poll = e.offset();
    // pollfd[2] = {port, POLLIN, 0}, {master, POLLIN, 0} — one qword
    // each: fd:i32 | events:i16<<32 (revents starts zeroed).
    mov_rr_!(e, rax, r13);
    mov_i!(e, rdx, lx::POLLIN as i32);
    e.emit(&shl_r_imm(xreg!(rdx), 32));
    add_rr_!(e, rax, rdx);
    store64!(e, rsp, 0, rax); // pfds[0] = {port, POLLIN}
    mov_rr_!(e, rax, r12);
    mov_i!(e, rdx, lx::POLLIN as i32);
    e.emit(&shl_r_imm(xreg!(rdx), 32));
    add_rr_!(e, rax, rdx);
    store64!(e, rsp, 8, rax); // pfds[1] = {master, POLLIN}
                              // poll(pfds, 2, -1) — block until one side is ready.
    mov_rr_!(e, rdi, rsp);
    mov_i!(e, rsi, 2);
    mov_i!(e, rdx, -1);
    sys!(e, nr::POLL);
    // pfds[0].revents (the port): zero → skip to the master side.
    loadzx16!(e, rax, rsp, 6);
    cmp_i!(e, rax, 0);
    let mut p_out = vec![fwd(&mut e, Branch::Je)];

    // Host input → the pty. A failed read is the port not yet connected
    // (the control handshake): a paced retry, never a busy loop.
    mov_rr_!(e, rdi, r13);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, IN_BUF);
    mov_i!(e, rdx, BUF_LEN);
    sys!(e, nr::READ);
    cmp_i!(e, rax, 0);
    let mut p_nap = vec![fwd(&mut e, Branch::Jle)];

    // The resize-record strip: r14 = src, r15 = dst, rbp = end. Every
    // whole record (magic "RSZ1", cols/rows each 1..=4096) is applied
    // via TIOCSWINSZ — the kernel SIGWINCHs the session's foreground
    // process group, so the session re-sizes itself exactly like a real
    // terminal. The record is delivered whole or not at all, and always
    // fits whole in a read, so there is no straddle to carry.
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, IN_BUF); // r14 = src = in_buf
    mov_rr_!(e, r15, r14); // r15 = dst = in_buf
    mov_rr_!(e, rbp, r14);
    add_rr_!(e, rbp, rax); // rbp = end = in_buf + len
    let l_strip = e.offset();
    cmp_rr_!(e, r14, rbp); // src >= end → done
    let mut p_done_strip = vec![fwd(&mut e, Branch::Jge)];
    mov_rr_!(e, rax, rbp);
    sub_rr_!(e, rax, r14); // end - src
    cmp_i!(e, rax, 8); // < 8 → no whole record can start here
    let mut p_copy = vec![fwd(&mut e, Branch::Jl)];
    loadzx32!(e, rax, r14, 0); // the magic dword
    cmp_i!(e, rax, RESIZE_MAGIC);
    p_copy.push(fwd(&mut e, Branch::Jne)); // not a record → copy the byte
                                           // The record's fields: cols at +4, rows at +6 (zero-extended loads).
    loadzx16!(e, rax, r14, 4); // cols
    loadzx16!(e, rcx, r14, 6); // rows
                               // The winsize qword FIRST (parked in rdx — the checks mutate).
    mov_rr_!(e, rdx, rax); // cols
    e.emit(&shl_r_imm(xreg!(rdx), 16));
    mov_rr_!(e, rax, rcx); // rows
    add_rr_!(e, rdx, rax); // ws_q = cols<<16 | rows
    let mut p_skip_ioctl: Fwd = vec![];
    cmp_i!(e, rax, 0); // rows
    p_skip_ioctl.push(fwd(&mut e, Branch::Je));
    sub_i!(e, rax, 1);
    cmp_i!(e, rax, RESIZE_MAX);
    p_skip_ioctl.push(fwd(&mut e, Branch::Jg));
    loadzx16!(e, rax, r14, 4); // cols (again — mutated above)
    cmp_i!(e, rax, 0);
    p_skip_ioctl.push(fwd(&mut e, Branch::Je));
    sub_i!(e, rax, 1);
    cmp_i!(e, rax, RESIZE_MAX);
    p_skip_ioctl.push(fwd(&mut e, Branch::Jg));
    // ioctl(master, TIOCSWINSZ, &ws) — apply the record's geometry.
    store64!(e, rsp, WS, rdx);
    mov_rr_!(e, rdi, r12);
    mov_i!(e, rsi, lx::TIOCSWINSZ as i32);
    mov_rr_!(e, rdx, rsp);
    add_i!(e, rdx, WS);
    sys!(e, nr::IOCTL);
    // A whole record consumed: advance past it, keep scanning.
    patch(&mut e, &mut p_skip_ioctl);
    add_i!(e, r14, 8);
    e.branch_back(Branch::Jmp, l_strip);
    // Not a record (or not whole): copy the byte through, keep scanning.
    patch(&mut e, &mut p_copy);
    loadb_inc!(e, rax, r14); // c = *src; src++
    storeb_inc!(e, r15, rax); // *dst = c; dst++
    e.branch_back(Branch::Jmp, l_strip);
    // The strip is done: the remainder is the session's input.
    patch(&mut e, &mut p_done_strip);
    mov_rr_!(e, rax, r15);
    sub_rr_!(e, rax, rsp);
    sub_i!(e, rax, IN_BUF); // total = dst - in_buf
    cmp_i!(e, rax, 0);
    let mut p_skip_write_in = vec![fwd(&mut e, Branch::Jle)];
    // The write pump (partial writes retried until done): r14 = the
    // moving pointer, r15 = the remaining length.
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, IN_BUF);
    mov_rr_!(e, r15, rax);
    let l_win = e.offset();
    cmp_i!(e, r15, 0);
    let mut p_done_win = vec![fwd(&mut e, Branch::Jle)];
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, r14);
    mov_rr_!(e, rdx, r15);
    sys!(e, nr::WRITE);
    cmp_i!(e, rax, 0); // n <= 0 → the fd is gone; the loop's reader decides
    p_done_win.push(fwd(&mut e, Branch::Jle));
    add_rr_!(e, r14, rax);
    sub_rr_!(e, r15, rax);
    e.branch_back(Branch::Jmp, l_win);
    patch(&mut e, &mut p_done_win);
    // The input is done (or skipped): back to the poll loop.
    patch(&mut e, &mut p_skip_write_in);
    e.branch_back(Branch::Jmp, l_poll);
    // The paced !host_connected retry: 100 ms, then back to the poll loop.
    patch(&mut e, &mut p_nap);
    lea!(e, rdi, s_nap);
    zero!(e, rsi);
    sys!(e, nr::NANO_SLEEP);
    e.branch_back(Branch::Jmp, l_poll);

    // ── Session output/echo → the port ────────────────────────────
    patch(&mut e, &mut p_out);
    // pfds[1].revents (the pty master): zero → nothing to read.
    loadzx16!(e, rax, rsp, 14);
    cmp_i!(e, rax, 0);
    e.branch_back(Branch::Je, l_poll); // skip → the poll loop
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, OUT_BUF);
    mov_i!(e, rdx, BUF_LEN);
    sys!(e, nr::READ);
    cmp_i!(e, rax, 0);
    let mut p_reap = vec![fwd(&mut e, Branch::Jle)]; // ≤ 0 → the session is dead
                                                     // The write pump into the port (same shape as the input side).
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, OUT_BUF);
    mov_rr_!(e, r15, rax);
    let l_wout = e.offset();
    cmp_i!(e, r15, 0);
    let mut p_done_wout = vec![fwd(&mut e, Branch::Jle)];
    mov_rr_!(e, rdi, r13);
    mov_rr_!(e, rsi, r14);
    mov_rr_!(e, rdx, r15);
    sys!(e, nr::WRITE);
    cmp_i!(e, rax, 0);
    p_done_wout.push(fwd(&mut e, Branch::Jle));
    add_rr_!(e, r14, rax);
    sub_rr_!(e, r15, rax);
    e.branch_back(Branch::Jmp, l_wout);
    patch(&mut e, &mut p_done_wout);
    e.branch_back(Branch::Jmp, l_poll); // pumped → the poll loop

    // ── The reaper ────────────────────────────────────────────────
    // The session is gone (or its transport is). Forward the status:
    // a signal death (status & 0xff != 0) exits 128+signal (the shell
    // convention); a normal exit forwards status >> 8.
    patch(&mut e, &mut p_reap);
    mov_rr_!(e, rdi, rbx);
    mov_i!(e, rsi, SIGKILL);
    sys!(e, nr::KILL); // insurance: the session cannot outlive the bridge
    mov_i!(e, rdi, -1); // wait4(-1, &status, 0, 0)
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, STATUS);
    zero!(e, rdx);
    zero!(e, r10);
    sys!(e, nr::WAIT4);
    load64!(e, rax, rsp, STATUS);
    mov_rr_!(e, rcx, rax); // rcx = the original status (the and below
                           // destroys rax — the normal path must re-read the ORIGINAL, exactly
                           // like the reference's `(status & 0xff) ? ... : (status >> 8)` reads
                           // `status` twice)
    e.emit(&and_r_imm(xreg!(rax), 0xFF)); // the signal half
    cmp_i!(e, rax, 0);
    let mut p_normal = vec![fwd(&mut e, Branch::Je)];
    add_i!(e, rax, 128); // 128 + signal
    mov_rr_!(e, rdi, rax);
    sys!(e, nr::EXIT);
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_normal);
    mov_rr_!(e, rax, rcx); // the original status
    e.emit(&shr_r_imm(xreg!(rax), 8)); // status >> 8
    mov_rr_!(e, rdi, rax);
    sys!(e, nr::EXIT);
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    // ── The session (the child) ───────────────────────────────────
    patch(&mut e, &mut p_child);
    // Own session, then the pty slave as the controlling terminal — a pty
    // slave IS claimable (unlike the console device), so job control and
    // tty signals work. The bridge's fds are closed; the slave is dup'd
    // onto 0/1/2 and closed (if it was above 2).
    xsetsid!(e);
    xclose!(e, r12); // the pty master
    xclose!(e, r13); // the port
    load64!(e, rcx, rsp, SLAVE);
    xdup3!(e, rcx, 0);
    load64!(e, rcx, rsp, SLAVE);
    xdup3!(e, rcx, 1);
    load64!(e, rcx, rsp, SLAVE);
    xdup3!(e, rcx, 2);
    load64!(e, rcx, rsp, SLAVE);
    cmp_i!(e, rcx, 2);
    let mut p_skip_close = vec![fwd(&mut e, Branch::Jle)]; // ≤ 2 → already closed
    xclose!(e, rcx);
    patch(&mut e, &mut p_skip_close);
    zero!(e, rdi);
    xioctl_imm!(e, rdi, lx::TIOCSCTTY as i32, 1); // claim stdin; 1 = force-steal

    // exec <command> [args...] — with NO arguments force the shell's
    // interactive mode ("-i"): without it ash reads stdin forever without
    // a prompt. nargv[0] = argv[4] (the command); the loop copies
    // argv[5..] — ONE counter (rbx = n), the source index = n + d
    // (d = 4 without "-i", 3 with it: the "-i" shifts everything down).
    load64!(e, rdx, r15, 40); // rdx = argv[4]
    store64!(e, rsp, NARGV, rdx); // nargv[0] = the command
    mov_i!(e, rbx, 1); // n = 1
    mov_i!(e, r12, 4); // d = 4 (no "-i")
    cmp_i!(e, r14, 5); // argc == 5 → no arguments at all
    let mut p_skip_mi = vec![fwd(&mut e, Branch::Jne)];
    lea!(e, rdx, s_mi);
    store64!(e, rsp, NARGV + 8, rdx); // nargv[1] = "-i"
    mov_i!(e, rbx, 2); // n = 2
    mov_i!(e, r12, 3); // d = 3 (the "-i" shifted everything down)
    patch(&mut e, &mut p_skip_mi);
    let l_nargv = e.offset();
    mov_rr_!(e, rax, r14);
    sub_rr_!(e, rax, r12); // argc - d: n < argc - d ⟺ n + d < argc
    cmp_rr_!(e, rbx, rax);
    let mut p_done_nargv = vec![fwd(&mut e, Branch::Jge)];
    cmp_i!(e, rbx, 63); // nargv[64]: n < 63, NULL at 63
    p_done_nargv.push(fwd(&mut e, Branch::Jge));
    mov_rr_!(e, rax, rbx);
    add_rr_!(e, rax, r12); // i = n + d
    e.emit(&shl_r_imm(xreg!(rax), 3)); // 8*i
    add_i!(e, rax, 8); // &argv[i] = r15 + 8 + 8*i
    add_rr_!(e, rax, r15);
    load64!(e, rdx, rax, 0); // rdx = argv[i]
    mov_rr_!(e, rax, rbx);
    e.emit(&shl_r_imm(xreg!(rax), 3)); // 8*n
    add_i!(e, rax, NARGV); // &nargv[n] = rsp + NARGV + 8*n
    add_rr_!(e, rax, rsp);
    store64!(e, rax, 0, rdx); // nargv[n] = argv[i]
    add_i!(e, rbx, 1); // n++
    e.branch_back(Branch::Jmp, l_nargv);
    patch(&mut e, &mut p_done_nargv);
    // nargv[n] = NULL, then execve(argv[4], nargv, envp).
    mov_rr_!(e, rax, rbx);
    e.emit(&shl_r_imm(xreg!(rax), 3));
    add_i!(e, rax, NARGV);
    add_rr_!(e, rax, rsp);
    zero!(e, rdx);
    store64!(e, rax, 0, rdx); // nargv[n] = NULL
    load64!(e, rdi, r15, 40); // rdi = argv[4] — the command path
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, NARGV); // rsi = nargv
    mov_rr_!(e, rdx, r14); // rdx = envp = r15 + 16 + 8*argc
    e.emit(&shl_r_imm(xreg!(rdx), 3));
    add_i!(e, rdx, 16);
    add_rr_!(e, rdx, r15);
    sys!(e, nr::EXECVE);
    xexit!(e, 125); // the exec failed: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    // ── The exit blocks (patched last: their targets are behind them) ──
    patch(&mut e, &mut p_exit126);
    xexit!(e, 126); // bad arguments
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit120);
    xexit!(e, 120); // the transport is gone: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit121);
    xexit!(e, 121); // the pty setup failed: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    e.build()
}
