//! Minimal ELF builder for generating static ARM64 Linux executables.
//!
//! This module provides [`ElfBuilder`], a lightweight code accumulator
//! that wraps raw ARM64 instructions and data into a valid ELF binary.
//!
//! # Example
//!
//! ```ignore
//! use crate::elf::arm64::*;
//! use crate::elf::ElfBuilder;
//!
//! let bin = ElfBuilder::new()
//!     .emit(movz_x(0, 42))   // x0 = 42
//!     .emit(movz_x(8, 93))   // __NR_exit
//!     .emit(svc0())
//!     .build();
//! ```

pub mod arm64;

/// Accumulates ARM64 instructions and data, then wraps them in a
/// minimal static ELF executable.
///
/// The generated ELF has a single `PT_LOAD` segment (R+X) at virtual
/// address `0x400000`.  Entry point is the first emitted instruction.
pub struct ElfBuilder {
    code: Vec<u8>,
}

impl ElfBuilder {
    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self { code: Vec::new() }
    }

    /// Emit a single 32-bit ARM64 instruction.
    pub fn emit(&mut self, insn: u32) -> &mut Self {
        self.code.extend_from_slice(&insn.to_le_bytes());
        self
    }

    /// Current byte offset into the code/data section.
    pub fn offset(&self) -> usize {
        self.code.len()
    }

    /// Consume the builder and produce a complete ELF binary.
    ///
    /// The binary is a minimal static ARM64 Linux executable:
    /// - 64-byte ELF header
    /// - 56-byte program header (single PT_LOAD, R+X)
    /// - Code/data immediately following
    pub fn build(self) -> Vec<u8> {
        let code_len = self.code.len();
        let load_addr: u64 = 0x400000;
        let ehdr_size: u16 = 64;
        let phdr_size: u16 = 56;
        let file_offset = ehdr_size as u64 + phdr_size as u64; // code starts at byte 120
        let entry = load_addr + file_offset;

        let mut elf = Vec::new();

        // ── ELF header (64 bytes) ───────────────────────────────────────
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
        elf.push(2); // EI_CLASS: ELFCLASS64
        elf.push(1); // EI_DATA: ELFDATA2LSB
        elf.push(1); // EI_VERSION: EV_CURRENT
        elf.push(0); // EI_OSABI: ELFOSABI_NONE
        elf.extend_from_slice(&[0; 8]); // padding
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
        elf.extend_from_slice(&0xB7u16.to_le_bytes()); // e_machine: EM_AARCH64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
        elf.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&phdr_size.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        debug_assert_eq!(elf.len(), 64);

        // ── Program header (56 bytes) ───────────────────────────────────
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        elf.extend_from_slice(&load_addr.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&load_addr.to_le_bytes()); // p_paddr
        let total_size = file_offset + code_len as u64;
        elf.extend_from_slice(&total_size.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&total_size.to_le_bytes()); // p_memsz
        elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        debug_assert_eq!(elf.len(), 120);

        // ── Code / data payload ─────────────────────────────────────────
        elf.extend_from_slice(&self.code);

        elf
    }
}
