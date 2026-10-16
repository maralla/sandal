//! aarch64 export helper ELFs: `BRK #imm` signal traps (const-evaluated).
//! The immediates are VMM-side protocol constants ([`crate::initramfs`]).
#[cfg(target_arch = "aarch64")]
use crate::elf::aarch64::*;
#[cfg(target_arch = "aarch64")]
use crate::elf::ElfBuilder;
use crate::initramfs::{EXPORT_DONE_IMM, EXPORT_RESIZE_IMM};

/// Minimal guest ELF that asks the VMM to grow /dev/vdb (tmpfs-upper mode):
/// `BRK #EXPORT_RESIZE_IMM` on arm64 (const-evaluated), a hypercall OUT on
/// the resize port on x86_64.
#[cfg(target_arch = "aarch64")]
const EXPORT_RESIZE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_RESIZE_IMM);
    exit!(elf, 0);
    elf.build()
};

#[cfg(target_arch = "aarch64")]
pub fn export_resize_helper(_mmio_base: u64) -> Vec<u8> {
    EXPORT_RESIZE_HELPER.0[..EXPORT_RESIZE_HELPER.1].to_vec()
}

/// Minimal guest ELF that tells the VMM the export data is ready:
/// `BRK #EXPORT_DONE_IMM` on arm64, a hypercall OUT on the done port on x86_64.
#[cfg(target_arch = "aarch64")]
const EXPORT_DONE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_DONE_IMM);
    exit!(elf, 0);
    elf.build()
};

#[cfg(target_arch = "aarch64")]
pub fn export_done_helper(_mmio_base: u64) -> Vec<u8> {
    EXPORT_DONE_HELPER.0[..EXPORT_DONE_HELPER.1].to_vec()
}
