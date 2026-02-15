//! Minimal ELF builder for generating static ARM64 Linux executables.
//!
//! [`ElfBuilder`] uses fixed-size arrays and `const fn` methods,
//! enabling compile-time ELF generation with zero runtime overhead.
//!
//! # Example
//!
//! ```ignore
//! use crate::elf::arm64::*;
//! use crate::elf::ElfBuilder;
//!
//! const BINARY: ([u8; ElfBuilder::MAX_ELF], usize) = {
//!     let mut e = ElfBuilder::new();
//!     e.emit(movz_x(0, 42));   // x0 = 42
//!     e.emit(movz_x(8, 93));   // __NR_exit
//!     e.emit(svc0());
//!     e.build()
//! };
//! // BINARY.0[..BINARY.1] is the valid ELF.
//! ```

#[macro_use]
mod macros;
pub mod linux;

pub mod arm64;

// ── Helpers for writing little-endian values in const context ────────────

/// Write a little-endian u16 into `$buf` at `$pos`, advancing `$pos`.
macro_rules! write_le_u16 {
    ($buf:expr, $pos:expr, $val:expr) => {{
        let v = $val as u16;
        $buf[$pos] = v as u8;
        $buf[$pos + 1] = (v >> 8) as u8;
        $pos += 2;
    }};
}

/// Write a little-endian u32 into `$buf` at `$pos`, advancing `$pos`.
macro_rules! write_le_u32 {
    ($buf:expr, $pos:expr, $val:expr) => {{
        let v = $val as u32;
        $buf[$pos] = v as u8;
        $buf[$pos + 1] = (v >> 8) as u8;
        $buf[$pos + 2] = (v >> 16) as u8;
        $buf[$pos + 3] = (v >> 24) as u8;
        $pos += 4;
    }};
}

/// Write a little-endian u64 into `$buf` at `$pos`, advancing `$pos`.
macro_rules! write_le_u64 {
    ($buf:expr, $pos:expr, $val:expr) => {{
        let v = $val as u64;
        $buf[$pos] = v as u8;
        $buf[$pos + 1] = (v >> 8) as u8;
        $buf[$pos + 2] = (v >> 16) as u8;
        $buf[$pos + 3] = (v >> 24) as u8;
        $buf[$pos + 4] = (v >> 32) as u8;
        $buf[$pos + 5] = (v >> 40) as u8;
        $buf[$pos + 6] = (v >> 48) as u8;
        $buf[$pos + 7] = (v >> 56) as u8;
        $pos += 8;
    }};
}

// ══════════════════════════════════════════════════════════════════════════
// ElfBuilder — compile-time ELF generation
// ══════════════════════════════════════════════════════════════════════════

/// Compile-time ELF builder using fixed-size arrays.
///
/// All methods are `const fn`, allowing the entire ELF binary to be
/// computed at compile time and embedded as a `const` byte array.
///
/// Usage:
/// ```ignore
/// const BINARY: ([u8; ElfBuilder::MAX_ELF], usize) = {
///     let mut e = ElfBuilder::new();
///     e.emit(movz_x(0, 42));
///     e.emit(movz_x(8, 93));
///     e.emit(svc0());
///     e.build()
/// };
/// // BINARY.0[..BINARY.1] is the valid ELF bytes.
/// ```
pub struct ElfBuilder {
    code: [u8; Self::MAX_CODE],
    code_len: usize,
    data: [u8; Self::MAX_DATA],
    data_len: usize,
    /// (code_offset, rd, data_offset) tuples for ADR fixups.
    fixups: [(usize, u32, usize); Self::MAX_FIXUPS],
    fixup_count: usize,
}

impl ElfBuilder {
    pub const MAX_CODE: usize = 4096;
    pub const MAX_DATA: usize = 2048;
    pub const MAX_FIXUPS: usize = 128;
    /// Maximum size of the final ELF binary (header + code + data).
    pub const MAX_ELF: usize = 120 + Self::MAX_CODE + Self::MAX_DATA;

    /// Create an empty builder.
    pub const fn new() -> Self {
        Self {
            code: [0u8; Self::MAX_CODE],
            code_len: 0,
            data: [0u8; Self::MAX_DATA],
            data_len: 0,
            fixups: [(0, 0, 0); Self::MAX_FIXUPS],
            fixup_count: 0,
        }
    }

    /// Emit a single 32-bit ARM64 instruction.
    pub const fn emit(&mut self, insn: u32) {
        let bytes = insn.to_le_bytes();
        self.code[self.code_len] = bytes[0];
        self.code[self.code_len + 1] = bytes[1];
        self.code[self.code_len + 2] = bytes[2];
        self.code[self.code_len + 3] = bytes[3];
        self.code_len += 4;
    }

    /// Current byte offset into the code section.
    pub const fn offset(&self) -> usize {
        self.code_len
    }

    /// Add a null-terminated C string to the data section.
    /// Returns the byte offset within the data section.
    pub const fn emit_cstring(&mut self, s: &str) -> usize {
        let offset = self.data_len;
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            self.data[self.data_len] = bytes[i];
            self.data_len += 1;
            i += 1;
        }
        self.data[self.data_len] = 0; // null terminator
        self.data_len += 1;
        offset
    }

    /// Add a null-terminated C string built by concatenating multiple parts.
    /// Returns the byte offset within the data section.
    pub const fn emit_cstring_parts(&mut self, parts: &[&str]) -> usize {
        let offset = self.data_len;
        let mut i = 0;
        while i < parts.len() {
            let bytes = parts[i].as_bytes();
            let mut j = 0;
            while j < bytes.len() {
                self.data[self.data_len] = bytes[j];
                self.data_len += 1;
                j += 1;
            }
            i += 1;
        }
        self.data[self.data_len] = 0; // null terminator
        self.data_len += 1;
        offset
    }

    /// Emit a placeholder `NOP` for an `ADR Xd, <data>` instruction.
    /// The actual PC-relative offset is patched during [`build`].
    pub const fn emit_adr_data(&mut self, rd: u32, data_offset: usize) {
        let code_offset = self.code_len;
        self.emit(arm64::nop());
        self.fixups[self.fixup_count] = (code_offset, rd, data_offset);
        self.fixup_count += 1;
    }

    /// Emit a `NOP` placeholder and return its byte offset.
    /// Use with [`patch`] for forward branches.
    pub const fn emit_placeholder(&mut self) -> usize {
        let offset = self.code_len;
        self.emit(arm64::nop());
        offset
    }

    /// Overwrite a previously emitted instruction at `offset`.
    pub const fn patch(&mut self, offset: usize, insn: u32) {
        let bytes = insn.to_le_bytes();
        self.code[offset] = bytes[0];
        self.code[offset + 1] = bytes[1];
        self.code[offset + 2] = bytes[2];
        self.code[offset + 3] = bytes[3];
    }

    /// Compute branch offset (in instructions) between two code byte offsets.
    pub const fn branch_offset(from_offset: usize, to_offset: usize) -> i32 {
        ((to_offset as i64 - from_offset as i64) / 4) as i32
    }

    /// Consume the builder and produce a complete ELF binary.
    ///
    /// Returns `(buffer, actual_length)` — the valid ELF is `buffer[..actual_length]`.
    pub const fn build(mut self) -> ([u8; Self::MAX_ELF], usize) {
        // Patch all ADR fixups.
        let code_len = self.code_len;
        let mut i = 0;
        while i < self.fixup_count {
            let (code_off, rd, data_off) = self.fixups[i];
            let byte_offset = (code_len - code_off) + data_off;
            let insn = arm64::adr_x(rd, byte_offset as i32);
            let bytes = insn.to_le_bytes();
            self.code[code_off] = bytes[0];
            self.code[code_off + 1] = bytes[1];
            self.code[code_off + 2] = bytes[2];
            self.code[code_off + 3] = bytes[3];
            i += 1;
        }

        let mut elf = [0u8; Self::MAX_ELF];
        let load_addr: u64 = 0x400000;
        let ehdr_size: u64 = 64;
        let phdr_size: u64 = 56;
        let file_offset = ehdr_size + phdr_size; // 120
        let entry = load_addr + file_offset;
        let payload_len = self.code_len + self.data_len;
        let total_size = file_offset + payload_len as u64;

        // ── ELF header (64 bytes) ───────────────────────────────────
        elf[0] = 0x7f;
        elf[1] = b'E';
        elf[2] = b'L';
        elf[3] = b'F';
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
                    // bytes 7..15 are zero (padding)
        let mut pos: usize = 16;
        write_le_u16!(elf, pos, 2u16); // e_type: ET_EXEC
        write_le_u16!(elf, pos, 0xB7u16); // e_machine: EM_AARCH64
        write_le_u32!(elf, pos, 1u32); // e_version
        write_le_u64!(elf, pos, entry); // e_entry
        write_le_u64!(elf, pos, ehdr_size); // e_phoff
        write_le_u64!(elf, pos, 0u64); // e_shoff
        write_le_u32!(elf, pos, 0u32); // e_flags
        write_le_u16!(elf, pos, ehdr_size as u16); // e_ehsize
        write_le_u16!(elf, pos, phdr_size as u16); // e_phentsize
        write_le_u16!(elf, pos, 1u16); // e_phnum
        write_le_u16!(elf, pos, 0u16); // e_shentsize
        write_le_u16!(elf, pos, 0u16); // e_shnum
        write_le_u16!(elf, pos, 0u16); // e_shstrndx
                                       // pos == 64

        // ── Program header (56 bytes) ───────────────────────────────
        write_le_u32!(elf, pos, 1u32); // p_type: PT_LOAD
        write_le_u32!(elf, pos, 7u32); // p_flags: R|W|X
        write_le_u64!(elf, pos, 0u64); // p_offset
        write_le_u64!(elf, pos, load_addr); // p_vaddr
        write_le_u64!(elf, pos, load_addr); // p_paddr
        write_le_u64!(elf, pos, total_size); // p_filesz
        write_le_u64!(elf, pos, total_size); // p_memsz
        write_le_u64!(elf, pos, 0x1000u64); // p_align
                                            // pos == 120

        // ── Code ────────────────────────────────────────────────────
        i = 0;
        while i < self.code_len {
            elf[pos] = self.code[i];
            pos += 1;
            i += 1;
        }

        // ── Data ────────────────────────────────────────────────────
        i = 0;
        while i < self.data_len {
            elf[pos] = self.data[i];
            pos += 1;
            i += 1;
        }

        (elf, pos)
    }
}
