//! The crafted `vsockecho` x86_64 guest helper: the relay test's echo
//! endpoint.
//!
//! Listens on the guest's TCP loopback and echoes every connection
//! straight back — sshd's stand-in for the relay channel's measurement
//! (tests/test_vsockrelay.py): the guest carries no openssh, and the
//! python stand-in's startup pegs the single emulated vCPU for minutes
//! and blocks the whole guest — so the endpoint is a crafted helper
//! too, up in milliseconds. A pure echo is exactly the measurement: the
//! channel is assumed to carry interactive input AND large-scale data
//! BOTH WAYS, so every byte the test pushes through the full chain —
//! client → VMM → vsock → vsockrelay → TCP loopback → here — comes
//! straight back, and the round-trip rate IS the channel's honest
//! bidirectional throughput (nothing here generates: the echo measures
//! what the chain itself will carry, and the test verifies every byte).
//!
//! One forked echo child per connection, exactly the vsockrelay's shape:
//!
//!   - SIGCHLD is SIG_IGN (set once, at startup): the kernel auto-reaps
//!     each finished child — no zombies, no wait4 loop — and no signal
//!     ever interrupts the accept loop;
//!   - every refusal (accept, clone) funnels through ONE paced retry —
//!     100 ms, then the accept loop again — never a spin;
//!   - the pump is whole-buffer: 64 KiB per read, echoed back with
//!     partial writes retried until done, then a re-poll. The
//!     transports' own flow control (the vsock credit chain, the TCP
//!     windows) does the pacing; a failed write means the connection is
//!     dead — close and exit, never a spin.
//!
//! usage: vsockecho <port>
//! exit:  120 = the listener failed (socket, bind, or listen)
//!        126 = bad arguments (argc != 2, or a port outside 1..=65535)
//!        The accept loop never exits. An echo child whose connection
//!        closed (either side: EOF or error) closes the fd and exits 0
//!        — auto-reaped (SIGCHLD is SIG_IGN), never forwarded.
//!
//! Pure machine code, built with the x86_64 DSL — no toolchain, no
//! sibling binary. The program documentation below IS the reference:
//!
//! ```text
//! r15 = the initial sp ([r15]=argc, [r15+8+8i]=argv[i]), r14 = argc
//! rsp -= FRAME (16-aligned):
//!       [rsp+0]  pollfd[1] — {fd:i32, events:i16, revents:i16},
//!                 rebuilt every poll iteration (poll writes revents)
//!       [rsp+16] sockaddr_in — bind's: {AF_INET, BE port,
//!                 INADDR_LOOPBACK}; addrlen 16, nothing beyond
//!       [rsp+32] buf (64 KiB) — the echo buffer
//! r13 = the listen fd (the accept loop; the child closes it)
//! r12 = the accepted conn fd (the echo child's only fd)
//! r14/r15 = the pump's moving pointer / remaining length
//! ENTRY: argc != 2 → exit(126); port = atol(argv[1]), 1..=65535 or
//!       exit(126); [rsp+16] = AF_INET | BE(port)<<16 (the byteswap as
//!       two disjoint adds), [rsp+24] = INADDR_LOOPBACK
//! LISTEN: r13 = socket(AF_INET, SOCK_STREAM, 0)  < 0 → exit(120)
//!       bind(r13, [rsp+16], 16)          != 0 → exit(120)
//!       listen(r13, 64)                  != 0 → exit(120)
//!       rt_sigaction(SIGCHLD, &SIG_IGN, 0, 8) — the auto-reap
//! ACCEPT: r12 = accept(r13, 0, 0)        < 0 → the paced retry
//!       clone(SIGCHLD):             < 0 → close(r12) → the paced retry
//!                                 == 0 → the ECHO child (below)
//!       the parent: close(r12) — its copy; the child holds its own —
//!       then the paced retry (never a bare loop)
//! RETRY: nanosleep(100 ms); jmp ACCEPT — one shared block, every
//!       refusal above jumps here
//! ECHO (the child): close(r13); then a poll loop, whole buffers:
//!       pollfd = {r12, POLLIN}; poll(-1)
//!       r12 readable → n = read(r12, buf): n ≤ 0 → the close exit;
//!         else write(r12, buf[0..n)) — partial writes retried until
//!         done; a failed write → the close exit (the fd is gone)
//!       done → re-poll (the next read is already pending)
//! CLOSE: close(r12); exit(0) — auto-reaped, never forwarded; ud2
//!       behind it (exit never returns)
//! ```

use std::sync::OnceLock;

/// The crafted `vsockecho` guest helper (see the module documentation).
/// Pure machine code, built with the x86_64 DSL — no toolchain.
#[cfg(target_arch = "x86_64")]
static VSOCKECHO_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn vsockecho_helper() -> &'static [u8] {
    VSOCKECHO_HELPER.get_or_init(build_vsockecho_elf)
}

#[cfg(target_arch = "x86_64")]
fn build_vsockecho_elf() -> Vec<u8> {
    use crate::elf::x86_64::{
        add_i, add_rr_, and_r_imm, cmp_i, lea, load64, loadb_inc, loadzx16, mov_i, mov_rr_,
        shl_r_imm, shr_r_imm, store64, sub_i, sub_rr_, sys, xclose, xexit, xfork, xreg, zero,
        Branch, X86ElfBuilder,
    };
    use crate::elf::x86_64_linux as lx;
    use crate::elf::x86_64_linux::nr;

    /// The stack frame: pollfd[1], bind's sockaddr_in, and the 64 KiB
    /// echo buffer. 16-aligned.
    const FRAME: i32 = 65568;
    /// bind()'s sockaddr_in (addrlen 16).
    const IN_ADDR: i32 = 16;
    /// The echo buffer.
    const BUF: i32 = 32;
    /// One whole-buffer echo per readable iteration: four syscalls per
    /// 64 KiB, and the transports' own flow control does the pacing.
    const BUF_LEN: i32 = 65536;
    /// listen(2)'s backlog: the vsockrelay's own bound.
    const BACKLOG: i32 = 64;
    /// The paced refusal retry: 100 ms.
    const NAP_NSEC: u64 = 100_000_000;

    // Forward branches: (placeholder offset, branch kind) pairs, patched
    // when their target block is emitted.
    type Fwd = Vec<(usize, Branch)>;
    let mut e = X86ElfBuilder::new();
    let fwd =
        |e: &mut X86ElfBuilder, br: Branch| -> (usize, Branch) { (e.branch_placeholder(br), br) };
    let patch = |e: &mut X86ElfBuilder, v: &mut Fwd| {
        for (at, br) in v.drain(..) {
            e.patch_branch(at, br);
        }
    };

    // The data section: the SIG_IGN kernel_sigaction and the nanosleep
    // timespec — the paced retry's whole state (see vsockrelay.rs).
    let s_sigign = e.emit_data_bytes(&{
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&lx::SIG_IGN.to_le_bytes());
        b
    });
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

    // argc != 2 → exit(126): no port.
    cmp_i!(e, r14, 2);
    let mut p_exit126 = vec![fwd(&mut e, Branch::Jne)];

    // ── The port: atol(argv[1]) ────────────────────────────────────
    // The port is the test's own config; the parse is atol-shaped and
    // the bounds check below rejects everything else.
    let mut p_atol: Fwd = vec![];
    load64!(e, rsi, r15, 16); // rsi = argv[1]
    zero!(e, rbx);
    let atol_port = e.offset();
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
    e.branch_back(Branch::Jmp, atol_port);
    patch(&mut e, &mut p_atol); // the port done (rbx)

    // The bounds: 1..=65535, or exit(126).
    cmp_i!(e, rbx, 0);
    p_exit126.push(fwd(&mut e, Branch::Je));
    cmp_i!(e, rbx, 0x1_0000);
    p_exit126.push(fwd(&mut e, Branch::Jge));

    // ── sockaddr_in: {AF_INET, BE(rbx), INADDR_LOOPBACK} ───────────
    // BE(rbx) as two disjoint adds (see vsockrelay.rs), then the
    // family qword and the address qword — exactly the 16 bytes bind
    // reads, nothing beyond.
    mov_rr_!(e, rax, rbx);
    e.emit(&shr_r_imm(xreg!(rax), 8)); // rbx>>8
    mov_rr_!(e, rcx, rbx);
    e.emit(&shl_r_imm(xreg!(rcx), 8)); // rbx<<8
    e.emit(&and_r_imm(xreg!(rcx), 0xFF00)); // (rbx<<8) & 0xFF00
    add_rr_!(e, rax, rcx); // BE(rbx)
    e.emit(&shl_r_imm(xreg!(rax), 16)); // BE(rbx)<<16
    mov_i!(e, rcx, lx::AF_INET as i32);
    add_rr_!(e, rax, rcx); // AF_INET | BE(rbx)<<16
    store64!(e, rsp, IN_ADDR, rax);
    mov_i!(e, rax, lx::INADDR_LOOPBACK as i32);
    store64!(e, rsp, IN_ADDR + 8, rax);

    // ── The listener ───────────────────────────────────────────────
    mov_i!(e, rdi, lx::AF_INET as i32);
    mov_i!(e, rsi, lx::SOCK_STREAM as i32);
    zero!(e, rdx);
    sys!(e, nr::SOCKET);
    mov_rr_!(e, r13, rax); // r13 = the listen fd
    cmp_i!(e, r13, 0);
    let mut p_exit120 = vec![fwd(&mut e, Branch::Jl)]; // socket failed

    mov_rr_!(e, rdi, r13);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, IN_ADDR);
    mov_i!(e, rdx, 16); // sizeof(sockaddr_in)
    sys!(e, nr::BIND);
    cmp_i!(e, rax, 0);
    p_exit120.push(fwd(&mut e, Branch::Jne)); // bind failed

    mov_rr_!(e, rdi, r13);
    mov_i!(e, rsi, BACKLOG);
    sys!(e, nr::LISTEN);
    cmp_i!(e, rax, 0);
    p_exit120.push(fwd(&mut e, Branch::Jne)); // listen failed

    // rt_sigaction(SIGCHLD, SIG_IGN, 0, 8): the auto-reap (see
    // vsockrelay.rs — the same disposition, the same reasons).
    mov_i!(e, rdi, lx::SIGCHLD as i32);
    lea!(e, rsi, s_sigign);
    zero!(e, rdx);
    mov_i!(e, r10, 8);
    sys!(e, nr::RT_SIGACTION);

    // ── The accept loop (the parent) ───────────────────────────────
    // One refusal funnel, exactly the vsockrelay's: every failure closes
    // what it opened and jumps to the ONE paced retry.
    let l_accept = e.offset();
    mov_rr_!(e, rdi, r13);
    zero!(e, rsi);
    zero!(e, rdx);
    sys!(e, nr::ACCEPT);
    cmp_i!(e, rax, 0);
    let mut p_retry = vec![fwd(&mut e, Branch::Jl)]; // accept failed
    mov_rr_!(e, r12, rax); // r12 = the accepted conn fd

    // clone(SIGCHLD): the echo child. The child holds its own copy of
    // r12 (the fd table copies at clone); the parent closes ITS copy
    // and paces out.
    xfork!(e);
    cmp_i!(e, rax, 0);
    p_retry.push(fwd(&mut e, Branch::Jl)); // clone failed
    cmp_i!(e, rax, 0);
    let mut p_child = vec![fwd(&mut e, Branch::Je)]; // 0 → the child

    // The parent: close(r12) — its copy only — then the paced retry.
    xclose!(e, r12);
    p_retry.push((e.branch_placeholder(Branch::Jmp), Branch::Jmp));

    // ── The paced retry (every refusal above jumps here) ────────────
    let at_retry = e.offset();
    patch(&mut e, &mut p_retry);
    lea!(e, rdi, s_nap);
    zero!(e, rsi);
    sys!(e, nr::NANO_SLEEP);
    e.branch_back(Branch::Jmp, l_accept);

    // ── The echo child ─────────────────────────────────────────────
    // close(r13): the child echoes, it does not accept. Then the poll
    // loop — whole buffers, straight back: the round-trip rate IS the
    // measurement (see the module documentation).
    let at_child = e.offset();
    patch(&mut e, &mut p_child);
    xclose!(e, r13);
    let l_poll = e.offset();
    // pollfd[1] = {r12, POLLIN, 0} — fd:i32 | events:i16<<32.
    mov_rr_!(e, rax, r12);
    mov_i!(e, rdx, lx::POLLIN as i32);
    e.emit(&shl_r_imm(xreg!(rdx), 32));
    add_rr_!(e, rax, rdx);
    store64!(e, rsp, 0, rax); // pfds[0] = {r12, POLLIN}
                              // poll(pfds, 1, -1) — block until readable.
    mov_rr_!(e, rdi, rsp);
    mov_i!(e, rsi, 1);
    mov_i!(e, rdx, -1);
    sys!(e, nr::POLL);
    // pfds[0].revents: zero → nothing to read → the poll loop.
    loadzx16!(e, rax, rsp, 6);
    cmp_i!(e, rax, 0);
    e.branch_back(Branch::Je, l_poll); // skip → the poll loop
                                       // read(r12, buf, 64 KiB) — the echo's whole buffer.
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, BUF);
    mov_i!(e, rdx, BUF_LEN);
    sys!(e, nr::READ);
    cmp_i!(e, rax, 0);
    let mut p_close = vec![fwd(&mut e, Branch::Jle)]; // EOF/error: dead
                                                      // The echo pump: r14 = the moving pointer, r15 = the remaining.
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, BUF);
    mov_rr_!(e, r15, rax);
    let l_pump = e.offset();
    cmp_i!(e, r15, 0);
    let mut p_pump_done = vec![fwd(&mut e, Branch::Jle)];
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, r14);
    mov_rr_!(e, rdx, r15);
    sys!(e, nr::WRITE);
    cmp_i!(e, rax, 0);
    p_close.push(fwd(&mut e, Branch::Jle)); // the fd is gone: dead
    add_rr_!(e, r14, rax);
    sub_rr_!(e, r15, rax);
    e.branch_back(Branch::Jmp, l_pump);
    // The buffer is echoed (or empty): re-poll — the next read is
    // already pending.
    patch(&mut e, &mut p_pump_done);
    e.branch_back(Branch::Jmp, l_poll);

    // ── The close exit: the connection is dead ─────────────────────
    // close(r12), exit(0) — auto-reaped, never forwarded.
    let at_close = e.offset();
    patch(&mut e, &mut p_close);
    xclose!(e, r12);
    xexit!(e, 0);
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    let _ = at_child;
    let _ = at_retry;
    let _ = at_close;

    // ── The exit blocks (patched last: their targets are behind them) ──
    patch(&mut e, &mut p_exit120);
    xexit!(e, 120); // the listener failed
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit126);
    xexit!(e, 126); // bad arguments
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    e.build()
}
