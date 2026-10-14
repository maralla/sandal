//! The x86_64 export helper ELFs: `/dev/mem` MMIO writes of the export
//! signal words (userspace MMIO — nested KVM denies I/O-port
//! privileges), built once at first use.

use std::sync::OnceLock;

// x86_64 variants: two-instruction programs (hypercall OUT + exit) built once
// at startup with the x86 DSL.
/// x86_64 helper: open /dev/mem, mmap the hypercall page, store the signal
/// word at the page offset (an MMIO write), then exit. MMIO works from
/// userspace without I/O-port privileges (which nested KVM denies).
#[cfg(target_arch = "x86_64")]
fn build_hypercall_elf(signal: u32, mmio_base: u64) -> Vec<u8> {
    use crate::elf::x86_64::{lea, mov_i, mov_m_imm32, sys, syscall_ins, zero, X86ElfBuilder, RSI};

    let mut e = X86ElfBuilder::new();
    let s_dev_mem = e.emit_cstring("/dev/mem");

    // fd = openat(AT_FDCWD, "/dev/mem", O_RDWR)
    mov_i!(e, rdi, crate::elf::x86_64_linux::AT_FDCWD);
    lea!(e, rsi, s_dev_mem);
    mov_i!(e, rdx, 0x2); // O_RDWR
    sys!(e, 257); // openat

    // base = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, page)
    zero!(e, rdi);
    mov_i!(e, rsi, 0x1000);
    mov_i!(e, rdx, 0x3);
    e.emit(&crate::elf::x86_64::mov_r_imm32(crate::elf::x86_64::R10, 1)); // MAP_SHARED
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::R8,
        crate::elf::x86_64::RAX,
    )); // fd
    let (page, off) = crate::vm::x86_hypercall_page_off(mmio_base);
    e.emit(&crate::elf::x86_64::mov_r_imm64(
        crate::elf::x86_64::R9,
        page,
    )); // offset needs the full 64 bits (0xa0000000)
    mov_i!(e, rax, 9); // mmap
    e.emit(&syscall_ins());
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::R15,
        crate::elf::x86_64::RAX,
    )); // mapping base

    // *(u32*)(base + off) = signal — an MMIO write through /dev/mem.
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::RSI,
        crate::elf::x86_64::R15,
    ));
    mov_i!(e, rdx, off as i32);
    e.emit(&crate::elf::x86_64::add_rr(
        crate::elf::x86_64::RSI,
        crate::elf::x86_64::RDX,
    ));
    e.emit(&mov_m_imm32(RSI, 0, signal as i32));

    // exit(0)
    e.emit(&crate::elf::x86_64::xor_rr(
        crate::elf::x86_64::RDI,
        crate::elf::x86_64::RDI,
    ));
    mov_i!(e, rax, 60);
    e.emit(&syscall_ins());
    e.build()
}
#[cfg(target_arch = "x86_64")]
fn hypercall_elf(cache: &'static OnceLock<Vec<u8>>, signal: u32, mmio_base: u64) -> &'static [u8] {
    cache.get_or_init(|| build_hypercall_elf(signal, mmio_base))
}

#[cfg(target_arch = "x86_64")]
static EXPORT_RESIZE_HELPER: OnceLock<Vec<u8>> = OnceLock::new();
#[cfg(target_arch = "x86_64")]
static EXPORT_DONE_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn export_resize_helper(mmio_base: u64) -> Vec<u8> {
    hypercall_elf(
        &EXPORT_RESIZE_HELPER,
        crate::elf::x86_64_linux::EXPORT_RESIZE_PORT as u32,
        mmio_base,
    )
    .to_vec()
}

#[cfg(target_arch = "x86_64")]
pub fn export_done_helper(mmio_base: u64) -> Vec<u8> {
    hypercall_elf(
        &EXPORT_DONE_HELPER,
        crate::elf::x86_64_linux::EXPORT_DONE_PORT as u32,
        mmio_base,
    )
    .to_vec()
}

