//! The crafted `ctty` x86_64 guest helper: gives the user command's
//! shell a controlling terminal (job control + tty signals).

use std::sync::OnceLock;

/// The crafted `ctty` guest helper: gives the user command's shell a
/// controlling terminal (job control + tty signals). Pure machine code,
/// built with the x86_64 DSL — no toolchain, no sibling binary.
///
/// Program (System V entry state: [rsp]=argc, [rsp+8+8i]=argv[i]):
/// ```text
/// r15 = rsp
/// r14 = argc                    (preserved across syscalls)
/// setsid()                      — own session (a tty can only be claimed
///                                 by a session leader without a ctty)
/// ioctl(0, TIOCSCTTY, 1)        — claim stdin (1 = force-steal; we run as
///                                 root, and init holds the console without
///                                 using it)
/// execve(argv[1], &argv[1], envp) — run the requested command; the command
///                                 must be an absolute path (the init script
///                                 resolves it with `command -v`)
/// exit(127)                     — only reached if execve failed
/// ```
#[cfg(target_arch = "x86_64")]
static CTTY_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn ctty_helper() -> &'static [u8] {
    CTTY_HELPER.get_or_init(build_ctty_elf)
}

#[cfg(target_arch = "x86_64")]
fn build_ctty_elf() -> Vec<u8> {
    use crate::elf::x86_64::{add_i, add_rr_, load64, shl_r_imm, sys, xexit, zero, X86ElfBuilder};
    use crate::elf::x86_64::{mov_rr_, xioctl_imm, xsetsid};

    let mut e = X86ElfBuilder::new();

    // r15 = rsp — the initial stack: [r15]=argc, [r15+8+8i]=argv[i].
    mov_rr_!(e, r15, rsp);
    load64!(e, r14, r15, 0); // r14 = argc

    // setsid() — own session; a tty can only be claimed by a session
    // leader without a controlling terminal.
    xsetsid!(e);

    // ioctl(0, TIOCSCTTY, 1) — claim stdin; 1 = force-steal (we run as
    // root, and init holds the console without using it).
    zero!(e, rdi);
    xioctl_imm!(e, rdi, crate::elf::x86_64_linux::TIOCSCTTY, 1);

    // rdx = envp = rsp + 16 + 8*argc — the initial environment, preserved.
    mov_rr_!(e, rdx, r14);
    e.emit(&shl_r_imm(crate::elf::x86_64::RDX, 3));
    add_i!(e, rdx, 16);
    add_rr_!(e, rdx, r15);

    // rsi = &argv[1] — the new argv (argv[argc] is still NULL after it).
    mov_rr_!(e, rsi, r15);
    add_i!(e, rsi, 16);

    // rdi = argv[1] — the command path (absolute; resolved by the caller).
    load64!(e, rdi, rsi, 0); // rdi = argv[1] — the command path

    // execve(path, argv+1, envp)
    sys!(e, crate::elf::x86_64_linux::nr::EXECVE);

    // exit(127) — only reached if execve failed.
    xexit!(e, 127);

    e.build()
}

