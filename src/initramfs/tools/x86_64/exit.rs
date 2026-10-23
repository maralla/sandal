//! The crafted `sandal-exit` x86_64 guest helper: the exit protocol.
//!
//! Marker-free exit-code delivery: the init script runs `sandal-exit
//! <status>` once the session is reaped, and the helper stores
//! `EXIT_PORT | (code << 16)` to the VMM's hypercall page — a /dev/mem
//! MMIO write, the same mechanism the export helpers use (userspace MMIO;
//! nested KVM denies I/O-port privileges). The VMM matches the low half
//! against `EXIT_PORT` and reads the code from the high half. No console
//! marker, no string matching, nothing user output can ever act as.
//!
//! usage: sandal-exit <code>    (a missing or non-numeric argument is 0)
//!
//! Pure machine code, built with the x86_64 DSL — no toolchain, no
//! sibling binary:
//!
//! ```text
//! r15 = the initial sp ([r15]=argc, [r15+8+8i]=argv[i]), r14 = argc
//! rbx = 0; argc >= 2 → rbx = atol(argv[1]) (digits only; else stays)
//! rdi = openat(AT_FDCWD, "/dev/mem", O_RDWR)
//! rax = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, rdi, page)
//! rsi = rax + off                       (the hypercall page offset)
//! rax = EXIT_PORT | (rbx << 16); *(u32*)rsi = rax   — the MMIO write
//! exit(0)
//! ```

use std::sync::OnceLock;

/// The crafted `sandal-exit` guest helper (see the module documentation).
#[cfg(target_arch = "x86_64")]
static EXIT_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn exit_helper(mmio_base: u64) -> Vec<u8> {
    EXIT_HELPER
        .get_or_init(|| build_exit_elf(mmio_base))
        .clone()
}

#[cfg(target_arch = "x86_64")]
fn build_exit_elf(mmio_base: u64) -> Vec<u8> {
    use crate::elf::x86_64::{
        add_i, add_rr_, cmp_i, lea, load64, loadb_inc, mov_i, mov_mem_r, mov_r_imm32, mov_r_imm64,
        mov_rr, mov_rr_, shl_r_imm, sub_i, sys, syscall_ins, zero, Branch, X86ElfBuilder, RAX, RDI,
        RSI,
    };
    use crate::elf::x86_64_linux as lx;
    use crate::elf::x86_64_linux::nr;

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

    let s_dev_mem = e.emit_cstring("/dev/mem");

    // ── Entry: the register plan ──────────────────────────────────
    mov_rr_!(e, r15, rsp); // r15 = the initial sp
    load64!(e, r14, r15, 0); // r14 = argc

    // ── code = atol(argv[1]) ──────────────────────────────────────
    // rbx rides the accumulator (portagent's atol shape): v*10 = (v<<3)+(v<<1);
    // a non-digit (or no argument at all) falls through with what is there.
    let mut p_atol: Fwd = vec![];
    zero!(e, rbx);
    cmp_i!(e, r14, 2);
    p_atol.push(fwd(&mut e, Branch::Jl)); // argc < 2 → no argument
    load64!(e, rsi, r15, 16); // rsi = argv[1] = [r15 + 8 + 8*1]
    let atol = e.offset();
    loadb_inc!(e, rax, rsi);
    cmp_i!(e, rax, b'0' as i32);
    p_atol.push(fwd(&mut e, Branch::Jl));
    cmp_i!(e, rax, b'9' as i32);
    p_atol.push(fwd(&mut e, Branch::Jg));
    mov_rr_!(e, rdx, rbx);
    e.emit(&shl_r_imm(crate::elf::x86_64::RDX, 3)); // v<<3
    mov_rr_!(e, rcx, rbx);
    e.emit(&shl_r_imm(crate::elf::x86_64::RCX, 1)); // v<<1
    add_rr_!(e, rdx, rcx); // v*10
    sub_i!(e, rax, b'0' as i32);
    add_rr_!(e, rdx, rax); // v*10 + digit
    mov_rr_!(e, rbx, rdx);
    e.branch_back(Branch::Jmp, atol);
    patch(&mut e, &mut p_atol); // code done (rbx); fall through

    // ── fd = openat(AT_FDCWD, "/dev/mem", O_RDWR) ─────────────────
    mov_i!(e, rdi, lx::AT_FDCWD);
    lea!(e, rsi, s_dev_mem);
    mov_i!(e, rdx, lx::O_RDWR as i32);
    sys!(e, nr::OPENAT);

    // ── base = mmap(NULL, 0x1000, rw, MAP_SHARED, fd, hyper_page) ─
    zero!(e, rdi);
    mov_i!(e, rsi, 0x1000);
    mov_i!(e, rdx, 0x3); // PROT_READ | PROT_WRITE
    e.emit(&mov_r_imm32(crate::elf::x86_64::R10, 1)); // MAP_SHARED
    e.emit(&mov_rr(crate::elf::x86_64::R8, RAX)); // fd
    let (page, off) = crate::vm::x86_hypercall_page_off(mmio_base);
    e.emit(&mov_r_imm64(crate::elf::x86_64::R9, page)); // full 64 bits (0xa0000000)
    mov_i!(e, rax, 9); // mmap
    e.emit(&syscall_ins());

    // ── *(u32*)(base + off) = EXIT_PORT | (code << 16) ────────────
    // The MMIO write through /dev/mem: the low half selects the signal,
    // the high half carries the exit code.
    e.emit(&mov_rr(RSI, RAX)); // rsi = the mapping base
    mov_i!(e, rdx, off as i32);
    e.emit(&crate::elf::x86_64::add_rr(RSI, crate::elf::x86_64::RDX));
    mov_rr_!(e, rax, rbx); // the code
    e.emit(&shl_r_imm(RAX, 16));
    add_i!(e, rax, crate::elf::x86_64_linux::EXIT_PORT as i32);
    e.emit(&mov_mem_r(RSI, 0, RAX));

    // exit(0): the store is done; the init's poweroff follows.
    e.emit(&crate::elf::x86_64::xor_rr(RDI, RDI));
    mov_i!(e, rax, 60);
    e.emit(&syscall_ins());
    e.emit(&[0x0F, 0x0B]); // ud2: exit never returns

    e.build()
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    #[test]
    fn dump_elf() {
        if std::env::var_os("SANDAL_DUMP_EXIT").is_some() {
            let elf = super::build_exit_elf(0xA000_0E00);
            std::fs::write("/tmp/sandal-exit.elf", &elf).unwrap();
        }
    }
}
