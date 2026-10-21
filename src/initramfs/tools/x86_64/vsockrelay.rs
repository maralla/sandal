//! The crafted `vsockrelay` x86_64 guest helper: the SSH channel's
//! guest-side forwarder.
//!
//! Listens on the guest's vsock (`AF_VSOCK`, CID_ANY — the VMM's own
//! channel bridges each client connection to it) and forwards every
//! accepted connection to the guest's own TCP loopback — sshd there,
//! unmodified: OpenSSH has no AF_VSOCK listen support upstream, so the
//! relay is the whole difference between "sshd on vsock" and "sshd on
//! loopback plus this".
//!
//! One forked pump child per connection — concurrent connections are the
//! point (many ssh sessions at once, each its own attributed stream),
//! and the parent is only ever the accept loop:
//!
//!   - SIGCHLD is SIG_IGN (set once, at startup): the kernel auto-reaps
//!     each finished pump child — no zombies, no wait4 loop — and no
//!     signal ever interrupts the accept loop;
//!   - every refusal (accept, socket, connect, fork) funnels through
//!     ONE paced retry — 100 ms, then the accept loop again — so a
//!     persistent refusal (no sshd on the target: ECONNREFUSED, closed
//!     and refused, never a spin) and an fd exhaustion (EMFILE) both
//!     degrade to ten attempts a second;
//!   - the pump is whole-buffer, both directions, 64 KiB a side: the
//!     channel is assumed to carry interactive input AND bulk data both
//!     ways, so the pump amortizes the syscalls — four per buffer, not
//!     four per byte — and lets the transports' own flow control (the
//!     vsock credit chain, the TCP windows) do the pacing.
//!
//! usage: vsockrelay <vsock-port> <tcp-port>
//! exit:  120 = socket() failed, 121 = bind() failed,
//!        122 = listen() failed, 126 = bad arguments
//!        (argc != 3, or a port outside 1..=65535)
//!        The accept loop never exits. A pump child whose connection
//!        closed (either side: EOF or error) closes both fds and exits
//!        0 — auto-reaped (SIGCHLD is SIG_IGN), never forwarded.
//!
//! Pure machine code, built with the x86_64 DSL — no toolchain, no
//! sibling binary. The program documentation below IS the reference —
//! the flow, the frame layout, the register plan, every bound — kept in
//! lockstep with the code it describes:
//!
//! ```text
//! r15 = the initial sp ([r15]=argc, [r15+8+8i]=argv[i]), r14 = argc
//! rsp -= FRAME (16-aligned):
//!       [rsp+0]   pollfd[2] — {fd:i32, events:i16, revents:i16} ×2,
//!                 rebuilt every poll iteration (poll writes revents)
//!       [rsp+16]  sockaddr_vm — bind's: {AF_VSOCK, 0, listen-port,
//!                 CID_ANY(u32!), flags=0, zero} — two qwords: the
//!                 first AF_VSOCK | port<<32, the second CID_ANY(u32) |
//!                 0 (the cid is a u32 in this kernel, and the second
//!                 half of that qword is the flags byte: zero)
//!       [rsp+32]  the guard — keeps the +28 overshoot off sockaddr_in
//!       [rsp+48]  sockaddr_in — connect's: {AF_INET, BE target-port,
//!                 INADDR_LOOPBACK}; addrlen 16, nothing beyond
//!       [rsp+64]  the guard's tail (never written, never read)
//!       [rsp+72]  in_buf (64 KiB), [rsp+65608] out_buf (64 KiB)
//! rbx = the listen port, then the tcp fd (the pump) — never both
//! rbp = the target port, then the pump's moving scratch
//! r13 = the vsock LISTEN fd (the accept loop; the child closes it)
//! r12 = the accepted vsock conn fd (the pump's vsock side)
//! r14/r15 = each pump's moving pointer / remaining length
//! ENTRY: argc != 3 → exit(126); listen = atol(argv[1]) (rbx),
//!       1..=65535 or exit(126); [rsp+16] = the sockaddr_vm — two
//!       qwords from disjoint halves: AF_VSOCK | rbx<<32, then
//!       CID_ANY(u32) | 0 (this kernel's cid is a u32; the second
//!       qword's high half is the flags byte — zero, or
//!       vsock_addr_validate fails it with EINVAL)
//!       target = atol(argv[2]) (rbp), 1..=65535 or exit(126);
//!       BE(target) = (target>>8) + ((target<<8) & 0xFF00) — the
//!       byteswap as two disjoint adds; [rsp+48] = AF_INET |
//!       BE(target)<<16 (one add), [rsp+56] = INADDR_LOOPBACK
//! LISTEN: r13 = socket(AF_VSOCK, SOCK_STREAM, 0)  < 0 → exit(120)
//!       bind(r13, [rsp+16], 16)          != 0 → exit(120)
//!       listen(r13, 64)                  != 0 → exit(120)
//!       rt_sigaction(SIGCHLD, &SIG_IGN, 0, 8) — the auto-reap
//! ACCEPT: r12 = accept(r13, 0, 0)        < 0 → the paced retry
//!       rbx = socket(AF_INET, SOCK_STREAM, 0)
//!                                     < 0 → close(r12) → the paced retry
//!       connect(rbx, [rsp+48], 16)   != 0 → close(r12, rbx) → the retry
//!       clone(SIGCHLD):             < 0 → close(r12, rbx) → the retry
//!                                 == 0 → the PUMP (below)
//!       the parent: close(r12, rbx) — its copies; the child holds its
//!       own — then the paced retry (never a bare loop: the next
//!       connection waits out the 100 ms)
//! RETRY: nanosleep(100 ms); jmp ACCEPT — one shared block, every
//!       refusal above jumps here
//! PUMP (the child): close(r13); then a poll loop, whole buffers:
//!       pollfd = {r12, POLLIN}, {rbx, POLLIN}; poll(-1)
//!       r12 readable → n = read(r12, in_buf): n ≤ 0 → the close exit;
//!         else write(rbx, in_buf[0..n)) — partial writes retried
//!         until done; a failed write → the close exit (never a spin:
//!         the fd is gone, the connection is dead)
//!       rbx readable → n = read(rbx, out_buf): n ≤ 0 → the close exit;
//!         else write(r12, out_buf[0..n)) — the same pump, the same
//!         close exit on a failed write
//!       either side done → re-poll (the other side may be ready)
//! CLOSE: close(r12); close(rbx); exit(0) — auto-reaped, never
//!       forwarded; ud2 behind it (exit never returns)
//! ```

use std::sync::OnceLock;

/// The crafted `vsockrelay` guest helper (see the module documentation).
/// Pure machine code, built with the x86_64 DSL — no toolchain.
#[cfg(target_arch = "x86_64")]
static VSOCKRELAY_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn vsockrelay_helper() -> &'static [u8] {
    VSOCKRELAY_HELPER.get_or_init(build_vsockrelay_elf)
}

/// One parsed `struct virtio_vsock_hdr` field set — no, the sockaddr
/// halves, as the documentation above describes them.
#[cfg(target_arch = "x86_64")]
fn build_vsockrelay_elf() -> Vec<u8> {
    use crate::elf::x86_64::{
        add_i, add_rr_, and_r_imm, cmp_i, lea, load64, loadb_inc, loadzx16, mov_i, mov_rr_,
        shl_r_imm, shr_r_imm, store64, sub_i, sub_rr_, sys, xclose, xexit, xfork, xreg, zero,
        Branch, X86ElfBuilder,
    };
    use crate::elf::x86_64_linux as lx;
    use crate::elf::x86_64_linux::nr;

    /// The stack frame (see the module documentation): pollfd[2], the
    /// sockaddr_vm + its guard, the sockaddr_in + the guard's tail, and
    /// the two 64 KiB pump buffers. 16-aligned; the +8 tail is slack.
    const FRAME: i32 = 131152;
    /// bind()'s sockaddr_vm (addrlen 16).
    const VM_ADDR: i32 = 16;
    /// connect()'s sockaddr_in (addrlen 16).
    const IN_ADDR: i32 = 48;
    /// The vsock→tcp pump buffer.
    const IN_BUF: i32 = 72;
    /// The tcp→vsock pump buffer.
    const OUT_BUF: i32 = 65608;
    /// One whole-buffer pump per readable side: the channel is assumed
    /// to carry bulk data both ways — four syscalls per 64 KiB, not per
    /// byte — and the transports' own flow control does the pacing.
    const BUF_LEN: i32 = 65536;
    /// listen(2)'s backlog: the python reference server's own bound.
    const BACKLOG: i32 = 64;
    /// The paced refusal retry: 100 ms.
    const NAP_NSEC: u64 = 100_000_000;

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

    // The data section, addressed rip-relative (lea!): the SIG_IGN
    // kernel_sigaction ({handler, flags, restorer, mask} — SIG_IGN and
    // nothing else: no restorer runs, nothing is blocked) and the
    // nanosleep timespec {0, 100 ms} — the paced retry's whole state.
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

    // argc != 3 → exit(126): no listen port, no target port.
    cmp_i!(e, r14, 3);
    let mut p_exit126 = vec![fwd(&mut e, Branch::Jne)];

    // ── The listen port: atol(argv[1]) → rbx ───────────────────────
    // The ports are the VMM's own config (never user input); the parse
    // is atol-shaped (whole digits, fall through past the first
    // non-digit) and the bounds check below rejects everything else.
    let mut p_atol: Fwd = vec![];
    load64!(e, rsi, r15, 16); // rsi = argv[1]
    zero!(e, rbx);
    let atol_listen = e.offset();
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
    e.branch_back(Branch::Jmp, atol_listen);
    patch(&mut e, &mut p_atol); // the listen port done (rbx)

    // The bounds: 1..=65535, or exit(126) — a bind on anything else
    // would only fail later, unattributed.
    cmp_i!(e, rbx, 0);
    p_exit126.push(fwd(&mut e, Branch::Je));
    cmp_i!(e, rbx, 0x1_0000);
    p_exit126.push(fwd(&mut e, Branch::Jge));

    // ── sockaddr_vm: {AF_VSOCK, 0, rbx, CID_ANY(u32), 0, 0} ────────
    // This kernel's sockaddr_vm — {family(2), rsv(2), port(4),
    // cid(u32!), flags(1), zero(3)} — as TWO qwords, each built from
    // disjoint halves (one add), each stored once:
    //   [+0] = AF_VSOCK | 0 (the low dword) | the port << 32 (the high)
    //   [+8] = CID_ANY, this kernel's u32 (the low dword) | 0 (the
    //          high: the flags byte + the zero tail — anything but zero
    //          there fails vsock_addr_validate's
    //          `svm_flags & ~VMADDR_FLAG_TO_HOST` check with EINVAL)
    // (The cid being a u32 — not the u64 the older layouts carried — is
    // the whole trap here: an emission built for the u64 cid puts
    // CID_ANY's other half right on the flags byte.)
    mov_i!(e, rax, lx::AF_VSOCK as i32); // the low dword: AF_VSOCK | 0
    mov_rr_!(e, rcx, rbx); // the listen port
    e.emit(&shl_r_imm(xreg!(rcx), 32)); // the port << 32
    add_rr_!(e, rax, rcx); // disjoint halves, one add
    store64!(e, rsp, VM_ADDR, rax);
    // The second qword: CID_ANY (u32) in the low dword, ZERO above —
    // NOT a sign-extended -1 (which is all ones, and puts 0xFFFFFFFF
    // right back on the flags dword). The zero-extended build: -1
    // shifted right by 32 — 0x00000000FFFFFFFF, exactly the u32 cid
    // over a zeroed flags byte and zero tail.
    mov_i!(e, rax, -1);
    e.emit(&shr_r_imm(xreg!(rax), 32)); // 0x00000000FFFFFFFF
    store64!(e, rsp, VM_ADDR + 8, rax);

    // ── The target port: atol(argv[2]) → rbp ───────────────────────
    load64!(e, rsi, r15, 24); // rsi = argv[2]
    zero!(e, rbp);
    let atol_target = e.offset();
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
    e.branch_back(Branch::Jmp, atol_target);
    patch(&mut e, &mut p_atol); // the target port done (rbp)

    // The bounds, again: 1..=65535 or exit(126).
    cmp_i!(e, rbp, 0);
    p_exit126.push(fwd(&mut e, Branch::Je));
    cmp_i!(e, rbp, 0x1_0000);
    p_exit126.push(fwd(&mut e, Branch::Jge));

    // ── sockaddr_in: {AF_INET, BE(rbp), INADDR_LOOPBACK} ───────────
    // BE(rbp) = (rbp>>8) + ((rbp<<8) & 0xFF00) — the byteswap as two
    // disjoint adds — then [rsp+48] = AF_INET | BE(rbp)<<16 (one add,
    // disjoint again) and [rsp+56] = INADDR_LOOPBACK. Nothing beyond
    // +64: connect's addrlen is 16, and the guard's tail is never
    // written.
    mov_rr_!(e, rax, rbp);
    e.emit(&shr_r_imm(xreg!(rax), 8)); // rbp>>8
    mov_rr_!(e, rcx, rbp);
    e.emit(&shl_r_imm(xreg!(rcx), 8)); // rbp<<8
    e.emit(&and_r_imm(xreg!(rcx), 0xFF00)); // (rbp<<8) & 0xFF00
    add_rr_!(e, rax, rcx); // BE(rbp)
    e.emit(&shl_r_imm(xreg!(rax), 16)); // BE(rbp)<<16
    mov_i!(e, rcx, lx::AF_INET as i32);
    add_rr_!(e, rax, rcx); // AF_INET | BE(rbp)<<16
    store64!(e, rsp, IN_ADDR, rax);
    mov_i!(e, rax, lx::INADDR_LOOPBACK as i32);
    store64!(e, rsp, IN_ADDR + 8, rax);

    // ── The listener ───────────────────────────────────────────────
    // socket(AF_VSOCK, SOCK_STREAM, 0) → the listen fd (r13); bind it
    // on CID_ANY (the kernel maps CID_ANY to the transport-assigned CID,
    // exactly like the python reference server); listen(64).
    mov_i!(e, rdi, lx::AF_VSOCK as i32);
    mov_i!(e, rsi, lx::SOCK_STREAM as i32);
    zero!(e, rdx);
    sys!(e, nr::SOCKET);
    mov_rr_!(e, r13, rax); // r13 = the vsock listen fd
    cmp_i!(e, r13, 0);
    let mut p_exit120 = vec![fwd(&mut e, Branch::Jl)]; // socket failed
    let mut p_exit121 = vec![];

    mov_rr_!(e, rdi, r13);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, VM_ADDR);
    mov_i!(e, rdx, 16); // sizeof(sockaddr_vm)
    sys!(e, nr::BIND);
    cmp_i!(e, rax, 0);
    p_exit121.push(fwd(&mut e, Branch::Jne)); // bind failed

    mov_rr_!(e, rdi, r13);
    mov_i!(e, rsi, BACKLOG);
    sys!(e, nr::LISTEN);
    cmp_i!(e, rax, 0);
    let mut p_exit122 = vec![fwd(&mut e, Branch::Jne)]; // listen failed

    // rt_sigaction(SIGCHLD, SIG_IGN, 0, 8): the kernel auto-reaps every
    // finished pump child — no zombies, no wait4 loop — and no signal
    // ever interrupts the accept loop below.
    mov_i!(e, rdi, lx::SIGCHLD as i32);
    lea!(e, rsi, s_sigign);
    zero!(e, rdx); // no oldact
    mov_i!(e, r10, 8); // sigsetsize
    sys!(e, nr::RT_SIGACTION);

    // ── The accept loop (the parent) ───────────────────────────────
    // One refusal funnel: every failure below (accept, socket, connect,
    // clone) closes what it opened and jumps to the ONE paced retry —
    // 100 ms, then this loop again. A persistent refusal (no sshd:
    // ECONNREFUSED, closed and refused) and an fd exhaustion (EMFILE)
    // both degrade to ten attempts a second, never a spin.
    let l_accept = e.offset();
    mov_rr_!(e, rdi, r13);
    zero!(e, rsi);
    zero!(e, rdx);
    sys!(e, nr::ACCEPT);
    cmp_i!(e, rax, 0);
    let mut p_retry = vec![fwd(&mut e, Branch::Jl)]; // accept failed
    mov_rr_!(e, r12, rax); // r12 = the accepted vsock conn fd

    // The forward target: socket(AF_INET, SOCK_STREAM, 0) → the tcp fd.
    mov_i!(e, rdi, lx::AF_INET as i32);
    mov_i!(e, rsi, lx::SOCK_STREAM as i32);
    zero!(e, rdx);
    sys!(e, nr::SOCKET);
    cmp_i!(e, rax, 0);
    p_retry.push(fwd(&mut e, Branch::Jl)); // socket failed
    mov_rr_!(e, rbx, rax); // rbx = the tcp fd

    // connect(rbx, sockaddr_in, 16) — the guest's own loopback: it
    // completes in-kernel or fails ECONNREFUSED immediately (no sshd),
    // never blocks.
    mov_rr_!(e, rdi, rbx);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, IN_ADDR);
    mov_i!(e, rdx, 16); // sizeof(sockaddr_in)
    sys!(e, nr::CONNECT);
    cmp_i!(e, rax, 0);
    p_retry.push(fwd(&mut e, Branch::Jne)); // connect refused

    // clone(SIGCHLD): the pump child. The child holds its own copies of
    // r12/rbx (the fd table copies at clone); the parent closes ITS
    // copies and paces out — never a bare loop.
    xfork!(e);
    cmp_i!(e, rax, 0);
    p_retry.push(fwd(&mut e, Branch::Jl)); // clone failed
    cmp_i!(e, rax, 0);
    let mut p_child = vec![fwd(&mut e, Branch::Je)]; // 0 → the pump

    // The parent: close(r12, rbx) — its copies only — then the paced
    // retry (the child holds its own).
    xclose!(e, r12);
    xclose!(e, rbx);
    p_retry.push((e.branch_placeholder(Branch::Jmp), Branch::Jmp));

    // ── The paced retry (every refusal above jumps here) ────────────
    let at_retry = e.offset();
    patch(&mut e, &mut p_retry);
    lea!(e, rdi, s_nap);
    zero!(e, rsi);
    sys!(e, nr::NANO_SLEEP);
    e.branch_back(Branch::Jmp, l_accept);

    // ── The pump (the child) ───────────────────────────────────────
    // close(r13): the child pumps, it does not accept. Then the poll
    // loop — whole buffers, both directions, exactly the portagent
    // bridge's shape: pollfd[2] rebuilt every iteration (poll writes
    // revents), each readable side read once into its 64 KiB buffer and
    // pumped whole into the other fd (partial writes retried until
    // done), then a re-poll — the other side may be ready.
    let at_child = e.offset();
    patch(&mut e, &mut p_child);
    xclose!(e, r13);
    let l_poll = e.offset();
    // pollfd[2] = {r12, POLLIN, 0}, {rbx, POLLIN, 0} — one qword each:
    // fd:i32 | events:i16<<32 (revents starts zeroed).
    mov_rr_!(e, rax, r12);
    mov_i!(e, rdx, lx::POLLIN as i32);
    e.emit(&shl_r_imm(xreg!(rdx), 32));
    add_rr_!(e, rax, rdx);
    store64!(e, rsp, 0, rax); // pfds[0] = {r12, POLLIN}
    mov_rr_!(e, rax, rbx);
    mov_i!(e, rdx, lx::POLLIN as i32);
    e.emit(&shl_r_imm(xreg!(rdx), 32));
    add_rr_!(e, rax, rdx);
    store64!(e, rsp, 8, rax); // pfds[1] = {rbx, POLLIN}
                              // poll(pfds, 2, -1) — block until a side is ready.
    mov_rr_!(e, rdi, rsp);
    mov_i!(e, rsi, 2);
    mov_i!(e, rdx, -1);
    sys!(e, nr::POLL);
    // pfds[0].revents (the vsock side): zero → skip to the tcp side.
    loadzx16!(e, rax, rsp, 6);
    cmp_i!(e, rax, 0);
    let mut p_tcp_side = vec![fwd(&mut e, Branch::Je)];

    // ── The vsock side: read(r12) → pump whole into rbx ────────────
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, IN_BUF);
    mov_i!(e, rdx, BUF_LEN);
    sys!(e, nr::READ);
    cmp_i!(e, rax, 0);
    let mut p_close = vec![fwd(&mut e, Branch::Jle)]; // EOF/error: dead
                                                      // The write pump (partial writes retried until done): r14 = the
                                                      // moving pointer, r15 = the remaining length.
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, IN_BUF);
    mov_rr_!(e, r15, rax);
    let l_pump_in = e.offset();
    cmp_i!(e, r15, 0);
    let mut p_pump_in_done = vec![fwd(&mut e, Branch::Jle)];
    mov_rr_!(e, rdi, rbx);
    mov_rr_!(e, rsi, r14);
    mov_rr_!(e, rdx, r15);
    sys!(e, nr::WRITE);
    cmp_i!(e, rax, 0);
    p_close.push(fwd(&mut e, Branch::Jle)); // the fd is gone: dead, no spin
    add_rr_!(e, r14, rax);
    sub_rr_!(e, r15, rax);
    e.branch_back(Branch::Jmp, l_pump_in);
    // The buffer is pumped (or empty): re-poll — the tcp side may be
    // ready. NEVER fall through to it: the sides are reached only
    // through their own revents checks.
    patch(&mut e, &mut p_pump_in_done);
    e.branch_back(Branch::Jmp, l_poll);

    // ── The tcp side: read(rbx) → pump whole into r12 ──────────────
    patch(&mut e, &mut p_tcp_side);
    // pfds[1].revents: zero → nothing to read → the poll loop.
    loadzx16!(e, rax, rsp, 14);
    cmp_i!(e, rax, 0);
    e.branch_back(Branch::Je, l_poll); // skip → the poll loop
    mov_rr_!(e, rdi, rbx);
    mov_rr_!(e, rsi, rsp);
    add_i!(e, rsi, OUT_BUF);
    mov_i!(e, rdx, BUF_LEN);
    sys!(e, nr::READ);
    cmp_i!(e, rax, 0);
    p_close.push(fwd(&mut e, Branch::Jle)); // EOF/error: sshd closed
                                            // The write pump into r12 (the same shape as the vsock side's).
    mov_rr_!(e, r14, rsp);
    add_i!(e, r14, OUT_BUF);
    mov_rr_!(e, r15, rax);
    let l_pump_out = e.offset();
    cmp_i!(e, r15, 0);
    let mut p_pump_out_done = vec![fwd(&mut e, Branch::Jle)];
    mov_rr_!(e, rdi, r12);
    mov_rr_!(e, rsi, r14);
    mov_rr_!(e, rdx, r15);
    sys!(e, nr::WRITE);
    cmp_i!(e, rax, 0);
    p_close.push(fwd(&mut e, Branch::Jle)); // the fd is gone: dead
    add_rr_!(e, r14, rax);
    sub_rr_!(e, r15, rax);
    e.branch_back(Branch::Jmp, l_pump_out);
    // The buffer is pumped (or empty): re-poll.
    patch(&mut e, &mut p_pump_out_done);
    e.branch_back(Branch::Jmp, l_poll);

    // ── The close exit: the connection is dead, either side ─────────
    // close(r12, rbx), exit(0) — auto-reaped (SIGCHLD is SIG_IGN),
    // never forwarded, never a spin: every path above that found its fd
    // gone jumps here instead of looping.
    let at_close = e.offset();
    patch(&mut e, &mut p_close);
    xclose!(e, r12);
    xclose!(e, rbx);
    xexit!(e, 0);
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    let _ = at_child;
    let _ = at_retry;
    let _ = at_close;

    // ── The exit blocks (patched last: their targets are behind them) ──
    patch(&mut e, &mut p_exit120);
    xexit!(e, 120); // socket() failed: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit121);
    xexit!(e, 121); // bind() failed: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit122);
    xexit!(e, 122); // listen() failed: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns
    patch(&mut e, &mut p_exit126);
    xexit!(e, 126); // bad arguments: the marker forwards it
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    e.build()
}
