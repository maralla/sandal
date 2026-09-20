//! x86_64 instruction encoders, ELF builder, and macro DSL for the guest
//! init binary (Linux x86_64 hosts).
//!
//! Unlike the ARM64 builder (fully const-evaluated), the x86 builder runs at
//! startup: variable-length encodings make const evaluation impractical, and
//! the few microseconds of runtime cost are irrelevant.
//!
//! Macros are imported by path (not `#[macro_use]`) so the ARM64 DSL and the
//! x86 DSL can coexist; colliding names carry an `x` prefix.

// The instruction DSL (x86_64) is an intentionally complete reference toolkit: crafted
// guest binaries use subsets of it, and unused entries document the
// surrounding UAPI surface.
#![allow(dead_code)]
#![allow(unused_macros)]
// ── Register numbers (x86_64 encoding order) ────────────────────────────
#![allow(unused_imports)]
pub const RAX: u32 = 0;
pub const RCX: u32 = 1;
pub const RDX: u32 = 2;
pub const RBX: u32 = 3;
pub const RSP: u32 = 4;
pub const RBP: u32 = 5;
pub const RSI: u32 = 6;
pub const RDI: u32 = 7;
pub const R8: u32 = 8;
pub const R9: u32 = 9;
pub const R10: u32 = 10;
pub const R11: u32 = 11;
pub const R12: u32 = 12;
pub const R13: u32 = 13;
pub const R14: u32 = 14;
pub const R15: u32 = 15;

/// True when the register number needs a REX.B/X/R bit (r8-r15).
#[inline]
pub const fn is_rex_high(r: u32) -> bool {
    r >= 8
}

/// REX prefix: W=64-bit operand, R=reg ext, X=index ext, B=rm ext.
#[inline]
pub const fn rex(w: bool, r: bool, x: bool, b: bool) -> u32 {
    0x40 | ((w as u32) << 3) | ((r as u32) << 2) | ((x as u32) << 1) | (b as u32)
}

/// ModRM byte: mod(2) reg(3) rm(3).
#[inline]
pub const fn modrm(mod_: u32, reg: u32, rm: u32) -> u32 {
    (mod_ << 6) | ((reg & 7) << 3) | (rm & 7)
}

/// `[base + disp]` needs an explicit displacement for rbp/r13 bases
/// (mod=00 rm=101 would mean RIP-relative).
#[inline]
const fn needs_disp(base: u32, disp: i32) -> bool {
    disp != 0 || (base & 7) == RBP
}

/// Memory-operand encoding for `[base + disp]`: (mod, displacement bytes).
/// The two MUST agree — mod=00 with the rsp SIB form means disp32, and
/// rbp/r13 need an explicit disp even when zero.
#[inline]
const fn mem_encoding(base: u32, disp: i32) -> (u32, usize) {
    if (base & 7) == RSP {
        if disp == 0 {
            (1, 1) // mod=01 + SIB + disp8=0
        } else {
            (2, 4)
        }
    } else if needs_disp(base, disp) {
        (2, 4)
    } else {
        (1, 1)
    }
}

/// Append ModRM (+SIB for rsp base) bytes for `[base + disp]`.
fn emit_modrm_mem(out: &mut Vec<u8>, reg: u32, base: u32, disp: i32) {
    let (m, _) = mem_encoding(base, disp);
    if (base & 7) == RSP {
        out.push(modrm(m, reg, 4) as u8);
        out.push(0x24);
    } else {
        out.push(modrm(m, reg, base) as u8);
    }
}

fn append_disp(out: &mut Vec<u8>, base: u32, disp: i32) {
    let (_, n) = mem_encoding(base, disp);
    let bytes = disp.to_le_bytes();
    out.extend_from_slice(&bytes[..n]);
}

// ── MOV ─────────────────────────────────────────────────────────────────

/// `MOV r64, imm64` (REX.W B8+r).
pub const fn mov_r_imm64(dst: u32, imm: u64) -> [u8; 10] {
    let mut b = [0u8; 10];
    b[0] = rex(true, false, false, is_rex_high(dst)) as u8;
    b[1] = (0xB8 | (dst & 7)) as u8;
    let bytes = imm.to_le_bytes();
    let mut i = 0;
    while i < 8 {
        b[2 + i] = bytes[i];
        i += 1;
    }
    b
}

/// `MOV r64, imm32` (sign-extended, C7 /0).
pub fn mov_r_imm32(dst: u32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, is_rex_high(dst)) as u8);
    b.push(0xC7);
    b.push(modrm(3, 0, dst) as u8);
    b.extend_from_slice(&imm.to_le_bytes());
    b
}

/// `MOV r64, r64` (89 /r).
pub fn mov_rr(dst: u32, src: u32) -> Vec<u8> {
    let b = vec![
        rex(true, is_rex_high(src), false, is_rex_high(dst)) as u8,
        0x89,
        modrm(3, src, dst) as u8,
    ];
    b
}

/// `MOV r64, [r64 + disp]` (8B /r).
pub fn mov_r_mem(dst: u32, base: u32, disp: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.push(rex(true, is_rex_high(dst), false, is_rex_high(base)) as u8);
    b.push(0x8B);
    emit_modrm_mem(&mut b, dst, base, disp);
    append_disp(&mut b, base, disp);
    b
}

/// `MOV [r64 + disp], r64` (89 /r).
pub fn mov_mem_r(base: u32, disp: i32, src: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.push(rex(true, is_rex_high(src), false, is_rex_high(base)) as u8);
    b.push(0x89);
    emit_modrm_mem(&mut b, src, base, disp);
    append_disp(&mut b, base, disp);
    b
}

/// `MOVZX r64, byte [r64 + disp]` (0F B6 /r).
pub fn movzx_r64_m8(dst: u32, base: u32, disp: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(9);
    b.push(rex(true, is_rex_high(dst), false, is_rex_high(base)) as u8);
    b.push(0x0F);
    b.push(0xB6);
    emit_modrm_mem(&mut b, dst, base, disp);
    append_disp(&mut b, base, disp);
    b
}

/// `MOV dword [r64 + disp], imm32` (C7 /0) — sign-extended to 64.
pub fn mov_m_imm32(base: u32, disp: i32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(11);
    b.push(rex(true, false, false, is_rex_high(base)) as u8);
    b.push(0xC7);
    emit_modrm_mem(&mut b, 0, base, disp);
    append_disp(&mut b, base, disp);
    b.extend_from_slice(&imm.to_le_bytes());
    b
}

// ── Arithmetic / logic ──────────────────────────────────────────────────

/// `ADD r64, imm32` (81/83 /0).
pub fn add_r_imm(dst: u32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, is_rex_high(dst)) as u8);
    if (-128..=127).contains(&imm) && imm != 0 {
        b.push(0x83);
        b.push(modrm(3, 0, dst) as u8);
        b.push(imm as i8 as u8);
    } else {
        b.push(0x81);
        b.push(modrm(3, 0, dst) as u8);
        b.extend_from_slice(&imm.to_le_bytes());
    }
    b
}

/// `SUB r64, imm32` (81/83 /5).
pub fn sub_r_imm(dst: u32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, is_rex_high(dst)) as u8);
    if (-128..=127).contains(&imm) && imm != 0 {
        b.push(0x83);
        b.push(modrm(3, 5, dst) as u8);
        b.push(imm as i8 as u8);
    } else {
        b.push(0x81);
        b.push(modrm(3, 5, dst) as u8);
        b.extend_from_slice(&imm.to_le_bytes());
    }
    b
}

/// `ADD r64, r64` (01 /r).
pub fn add_rr(dst: u32, src: u32) -> Vec<u8> {
    let b = vec![
        rex(true, is_rex_high(src), false, is_rex_high(dst)) as u8,
        0x01,
        modrm(3, src, dst) as u8,
    ];
    b
}

/// `SUB r64, r64` (29 /r).
pub fn sub_rr(dst: u32, src: u32) -> Vec<u8> {
    let b = vec![
        rex(true, is_rex_high(src), false, is_rex_high(dst)) as u8,
        0x29,
        modrm(3, src, dst) as u8,
    ];
    b
}

/// `CMP r64, imm32` (81/83 /7).
pub fn cmp_r_imm(dst: u32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, is_rex_high(dst)) as u8);
    if (-128..=127).contains(&imm) && imm != 0 {
        b.push(0x83);
        b.push(modrm(3, 7, dst) as u8);
        b.push(imm as i8 as u8);
    } else {
        b.push(0x81);
        b.push(modrm(3, 7, dst) as u8);
        b.extend_from_slice(&imm.to_le_bytes());
    }
    b
}

/// `CMP r64, r64` (39 /r).
pub fn cmp_rr(a: u32, b: u32) -> Vec<u8> {
    let v = vec![
        rex(true, is_rex_high(b), false, is_rex_high(a)) as u8,
        0x39,
        modrm(3, b, a) as u8,
    ];
    v
}

/// `TEST r64, r64` (85 /r).
pub fn test_rr(a: u32, b: u32) -> Vec<u8> {
    let v = vec![
        rex(true, is_rex_high(b), false, is_rex_high(a)) as u8,
        0x85,
        modrm(3, b, a) as u8,
    ];
    v
}

/// `AND r64, imm32` (81/83 /4).
pub fn and_r_imm(dst: u32, imm: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(7);
    b.push(rex(true, false, false, is_rex_high(dst)) as u8);
    if (-128..=127).contains(&imm) && imm != 0 {
        b.push(0x83);
        b.push(modrm(3, 4, dst) as u8);
        b.push(imm as i8 as u8);
    } else {
        b.push(0x81);
        b.push(modrm(3, 4, dst) as u8);
        b.extend_from_slice(&imm.to_le_bytes());
    }
    b
}

/// `SHL r64, imm8` (C1 /4).
pub fn shl_r_imm(dst: u32, imm: u8) -> Vec<u8> {
    vec![
        rex(true, false, false, is_rex_high(dst)) as u8,
        0xC1,
        modrm(3, 4, dst) as u8,
        imm,
    ]
}

/// `SHR r64, imm8` (C1 /5).
pub fn shr_r_imm(dst: u32, imm: u8) -> Vec<u8> {
    vec![
        rex(true, false, false, is_rex_high(dst)) as u8,
        0xC1,
        modrm(3, 5, dst) as u8,
        imm,
    ]
}

/// `XOR r64, r64` — zero a register.
pub fn xor_rr(dst: u32, src: u32) -> Vec<u8> {
    let b = vec![
        rex(true, is_rex_high(src), false, is_rex_high(dst)) as u8,
        0x31,
        modrm(3, src, dst) as u8,
    ];
    b
}

/// `INC r64` (REX.W FF /0, REX.B for r8-r15).
#[inline]
fn inc_r64(r: u32) -> [u8; 3] {
    [
        (0x48 | (is_rex_high(r) as u8)) as u8,
        0xFF,
        (0xC0 | (r & 7)) as u8,
    ]
}

// ── Branches ────────────────────────────────────────────────────────────

/// Branch opcodes (rel32 forms; always the full-length encoding so forward
/// placeholders can be patched in place).
#[derive(Clone, Copy)]
pub enum Branch {
    /// JMP rel32 (E9).
    Jmp,
    /// JE rel32 (0F 84) — equal / zero.
    Je,
    /// JNE rel32 (0F 85).
    Jne,
    /// JL rel32 (0F 8C) — signed less.
    Jl,
    /// JGE rel32 (0F 8D).
    Jge,
    /// JLE rel32 (0F 8E).
    Jle,
    /// JG rel32 (0F 8F).
    Jg,
}

impl Branch {
    /// Opcode bytes (without the rel32 displacement).
    const fn opcodes(self) -> &'static [u8] {
        match self {
            Branch::Jmp => &[0xE9],
            Branch::Je => &[0x0F, 0x84],
            Branch::Jne => &[0x0F, 0x85],
            Branch::Jl => &[0x0F, 0x8C],
            Branch::Jge => &[0x0F, 0x8D],
            Branch::Jle => &[0x0F, 0x8E],
            Branch::Jg => &[0x0F, 0x8F],
        }
    }

    /// Total instruction length (opcodes + rel32).
    pub const fn len(self) -> usize {
        self.opcodes().len() + 4
    }

    /// Encode with a rel32 displacement.
    fn encode(self, disp: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(self.opcodes());
        out.extend_from_slice(&disp.to_le_bytes());
        out
    }
}

// ── System / I/O ────────────────────────────────────────────────────────

/// `SYSCALL` (0F 05).
pub const fn syscall_ins() -> [u8; 2] {
    [0x0F, 0x05]
}

/// `IN EAX, DX` (ED) — port in DX, 32-bit result in EAX.
pub const fn in_eax_dx() -> [u8; 1] {
    [0xED]
}

/// `OUT DX, AL` (EE) — port in DX, byte from AL.
pub const fn out_dx_al() -> [u8; 1] {
    [0xEE]
}

// ══════════════════════════════════════════════════════════════════════════
// X86ElfBuilder
// ══════════════════════════════════════════════════════════════════════════

/// Builder for a single-PT_LOAD ET_EXEC x86_64 image (code then data).
pub struct X86ElfBuilder {
    code: Vec<u8>,
    data: Vec<u8>,
    /// (code_offset_of_lea, data_offset) — rip-relative fixups.
    lea_fixups: Vec<(usize, usize)>,
}

impl Default for X86ElfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl X86ElfBuilder {
    pub fn new() -> Self {
        X86ElfBuilder {
            code: Vec::new(),
            data: Vec::new(),
            lea_fixups: Vec::new(),
        }
    }

    /// Append raw instruction bytes.
    pub fn emit(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    /// Current code offset (branch/fixup anchor).
    pub fn offset(&self) -> usize {
        self.code.len()
    }

    /// Add a null-terminated C string to the data section.
    pub fn emit_cstring(&mut self, s: &str) -> usize {
        let off = self.data.len();
        self.data.extend_from_slice(s.as_bytes());
        self.data.push(0);
        off
    }

    /// Concatenate multiple parts into one null-terminated string.
    pub fn emit_cstring_parts(&mut self, parts: &[&str]) -> usize {
        let off = self.data.len();
        for p in parts {
            self.data.extend_from_slice(p.as_bytes());
        }
        self.data.push(0);
        off
    }

    /// Emit a `LEA r64, [rip + disp32]` placeholder addressing `data_offset`.
    /// Patched during [`build`] — the data section follows the code section.
    pub fn emit_lea_data(&mut self, dst: u32, data_offset: usize) {
        let at = self.code.len();
        let mut enc = vec![0u8; 7];
        enc[0] = rex(true, is_rex_high(dst), false, false) as u8;
        enc[1] = 0x8D;
        enc[2] = modrm(0, dst, 5) as u8; // mod=00 rm=101 → rip-relative
        self.code.extend_from_slice(&enc);
        self.lea_fixups.push((at, data_offset));
    }

    /// Emit a backward branch to `target` (an earlier code offset).
    pub fn branch_back(&mut self, br: Branch, target: usize) {
        let disp = target as i64 - (self.code.len() + br.len()) as i64;
        let enc = br.encode(disp as i32);
        self.emit(&enc);
    }

    /// Reserve space for a forward branch; patch with [`patch_branch`].
    pub fn branch_placeholder(&mut self, br: Branch) -> usize {
        let at = self.code.len();
        self.emit(&vec![0xCC; br.len()]);
        at
    }

    /// Patch a forward-branch placeholder to jump to the current offset.
    pub fn patch_branch(&mut self, at: usize, br: Branch) {
        let disp = self.code.len() as i64 - (at + br.len()) as i64;
        let enc = br.encode(disp as i32);
        self.code[at..at + br.len()].copy_from_slice(&enc);
    }

    /// Consume the builder and produce the ELF image bytes.
    pub fn build(mut self) -> Vec<u8> {
        let code_len = self.code.len();

        // Patch LEA fixups: disp = (code_end + data_off) - (lea_end).
        for (at, data_off) in self.lea_fixups.iter() {
            let disp = (code_len + data_off) as i64 - (at + 7) as i64;
            self.code[at + 3..at + 7].copy_from_slice(&(disp as i32).to_le_bytes());
        }

        let mut elf = Vec::with_capacity(120 + code_len + self.data.len());

        let load_addr: u64 = 0x400000;
        let ehdr_size: u64 = 64;
        let phdr_size: u64 = 56;
        let file_offset = ehdr_size + phdr_size;
        let entry = load_addr + file_offset;
        let total_size = file_offset + (code_len + self.data.len()) as u64;

        // ── ELF header ─────────────────────────────────────────────
        elf.extend_from_slice(b"\x7fELF");
        elf.push(2); // ELFCLASS64
        elf.push(1); // ELFDATA2LSB
        elf.push(1); // EV_CURRENT
        elf.extend_from_slice(&[0u8; 9]); // padding
        elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
        elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&(ehdr_size as u16).to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&(phdr_size as u16).to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        // ── Program header: one RWX PT_LOAD ────────────────────────
        elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        elf.extend_from_slice(&7u32.to_le_bytes()); // R|W|X
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        elf.extend_from_slice(&load_addr.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&load_addr.to_le_bytes()); // p_paddr
        elf.extend_from_slice(&total_size.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&total_size.to_le_bytes()); // p_memsz
        elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

        // ── Payload ────────────────────────────────────────────────
        elf.extend_from_slice(&self.code);
        elf.extend_from_slice(&self.data);
        elf
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Macro DSL — x86_64 assembly for the guest init
// ══════════════════════════════════════════════════════════════════════════
//
// Physical registers, x86_64 syscall convention:
//   args: rdi rsi rdx r10 r8 r9   nr: rax   ret: rax (clobbers rcx, r11)
//
// Macro names that collide with the ARM64 DSL carry an `x` prefix; all are
// re-exported at the bottom and imported by path from `init_x86`.

/// Register name → number for the DSL (internal; `x` prefix avoids clashing
/// with the ARM64 `reg!` in the crate-root textual scope).
#[allow(unused_macros)]
macro_rules! xreg {
    (rax) => {
        0
    };
    (rcx) => {
        1
    };
    (rdx) => {
        2
    };
    (rbx) => {
        3
    };
    (rsp) => {
        4
    };
    (rbp) => {
        5
    };
    (rsi) => {
        6
    };
    (rdi) => {
        7
    };
    (r8) => {
        8
    };
    (r9) => {
        9
    };
    (r10) => {
        10
    };
    (r11) => {
        11
    };
    (r12) => {
        12
    };
    (r13) => {
        13
    };
    (r14) => {
        14
    };
    (r15) => {
        15
    };
}

/// Public alias of [`xreg`] for direct register lookups in guest-init code
/// (exported at the crate root via `macro_export`).
#[macro_export]
macro_rules! rx {
    (rax) => {
        0
    };
    (rcx) => {
        1
    };
    (rdx) => {
        2
    };
    (rbx) => {
        3
    };
    (rsp) => {
        4
    };
    (rbp) => {
        5
    };
    (rsi) => {
        6
    };
    (rdi) => {
        7
    };
    (r8) => {
        8
    };
    (r9) => {
        9
    };
    (r10) => {
        10
    };
    (r11) => {
        11
    };
    (r12) => {
        12
    };
    (r13) => {
        13
    };
    (r14) => {
        14
    };
    (r15) => {
        15
    };
}

/// `syscall NR` — number into rax, then `syscall`. Result in rax.
macro_rules! sys {
    ($e:expr, $nr:expr) => {
        $e.emit(&$crate::elf::x86_64::mov_r_imm32(
            $crate::elf::x86_64::xreg!(rax),
            $nr as i32,
        ));
        $e.emit(&$crate::elf::x86_64::syscall_ins());
    };
}

/// `MOV r64, imm32` (sign-extended).
macro_rules! mov_i {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(&$crate::elf::x86_64::mov_r_imm32(
            $crate::elf::x86_64::xreg!($rd),
            $imm as i32,
        ))
    };
}

/// `MOV r64, r64`.
macro_rules! mov_rr_ {
    ($e:expr, $rd:tt, $rs:tt) => {
        $e.emit(&$crate::elf::x86_64::mov_rr(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($rs),
        ))
    };
}

/// `LEA r64, [rip + data]` — address of a data-section string.
macro_rules! lea {
    ($e:expr, $rd:tt, $data:expr) => {
        $e.emit_lea_data($crate::elf::x86_64::xreg!($rd), $data)
    };
}

/// `ADD r64, imm32`.
macro_rules! add_i {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(&$crate::elf::x86_64::add_r_imm(
            $crate::elf::x86_64::xreg!($rd),
            $imm as i32,
        ))
    };
}

/// `SUB r64, imm32`.
macro_rules! sub_i {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(&$crate::elf::x86_64::sub_r_imm(
            $crate::elf::x86_64::xreg!($rd),
            $imm as i32,
        ))
    };
}

/// `ADD r64, r64`.
macro_rules! add_rr_ {
    ($e:expr, $rd:tt, $rs:tt) => {
        $e.emit(&$crate::elf::x86_64::add_rr(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($rs),
        ))
    };
}

/// `SUB r64, r64`.
macro_rules! sub_rr_ {
    ($e:expr, $rd:tt, $rs:tt) => {
        $e.emit(&$crate::elf::x86_64::sub_rr(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($rs),
        ))
    };
}

/// `MOV r64, [r64 + disp]`.
macro_rules! load64 {
    ($e:expr, $rd:tt, $base:tt, $disp:expr) => {
        $e.emit(&$crate::elf::x86_64::mov_r_mem(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($base),
            $disp as i32,
        ))
    };
}

/// `MOV [r64 + disp], r64`.
macro_rules! store64 {
    ($e:expr, $base:tt, $disp:expr, $rs:tt) => {
        $e.emit(&$crate::elf::x86_64::mov_mem_r(
            $crate::elf::x86_64::xreg!($base),
            $disp as i32,
            $crate::elf::x86_64::xreg!($rs),
        ))
    };
}

/// `MOV dword [r64 + disp], imm32`.
macro_rules! store32i {
    ($e:expr, $base:tt, $disp:expr, $imm:expr) => {
        $e.emit(&$crate::elf::x86_64::mov_m_imm32(
            $crate::elf::x86_64::xreg!($base),
            $disp as i32,
            $imm as i32,
        ))
    };
}

/// `MOVZX r64, byte [r64 + disp]`.
macro_rules! loadzx8 {
    ($e:expr, $rd:tt, $base:tt, $disp:expr) => {
        $e.emit(&$crate::elf::x86_64::movzx_r64_m8(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($base),
            $disp as i32,
        ))
    };
}

/// `TEST r64, r64`.
macro_rules! test_ {
    ($e:expr, $ra:tt) => {
        $e.emit(&$crate::elf::x86_64::test_rr(
            $crate::elf::x86_64::xreg!($ra),
            $crate::elf::x86_64::xreg!($ra),
        ))
    };
}

/// `CMP r64, imm32`.
macro_rules! cmp_i {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(&$crate::elf::x86_64::cmp_r_imm(
            $crate::elf::x86_64::xreg!($rd),
            $imm as i32,
        ))
    };
}

/// `CMP r64, r64`.
macro_rules! cmp_rr_ {
    ($e:expr, $ra:tt, $rb:tt) => {
        $e.emit(&$crate::elf::x86_64::cmp_rr(
            $crate::elf::x86_64::xreg!($ra),
            $crate::elf::x86_64::xreg!($rb),
        ))
    };
}

/// `XOR r64, r64` — zero.
macro_rules! zero {
    ($e:expr, $rd:tt) => {
        $e.emit(&$crate::elf::x86_64::xor_rr(
            $crate::elf::x86_64::xreg!($rd),
            $crate::elf::x86_64::xreg!($rd),
        ))
    };
}

/// Zero `N` qwords at `[rsp]` (a fresh stack allocation).
macro_rules! xzero_stack {
    ($e:expr, $words:expr) => {{
        let mut _i: u32 = 0;
        while _i < $words {
            $e.emit(&$crate::elf::x86_64::mov_m_imm32(
                $crate::elf::x86_64::xreg!(rsp),
                (_i * 8) as i32,
                0,
            ));
            _i += 1;
        }
    }};
}

/// Backward conditional branch to an earlier offset.
macro_rules! jcc_back {
    ($e:expr, $br:expr, $target:expr) => {
        $e.branch_back($br, $target)
    };
}

/// Forward branch placeholder.
macro_rules! jcc_fwd {
    ($e:expr, $br:expr) => {
        $e.branch_placeholder($br)
    };
}

/// Patch a forward branch to the current offset.
macro_rules! patch_jcc {
    ($e:expr, $at:expr, $br:expr) => {
        $e.patch_branch($at, $br)
    };
}

/// `INC r64` encoding helper.
#[inline]
pub fn inc_r64_vec(r: u32) -> [u8; 3] {
    inc_r64(r)
}

/// `MOVZX r64, byte [ptr]; INC ptr` — read a byte and advance.
macro_rules! loadb_inc {
    ($e:expr, $val:tt, $ptr:tt) => {{
        $e.emit(&$crate::elf::x86_64::movzx_r64_m8(
            $crate::elf::x86_64::xreg!($val),
            $crate::elf::x86_64::xreg!($ptr),
            0,
        ));
        $e.emit(&$crate::elf::x86_64::inc_r64_vec(
            $crate::elf::x86_64::xreg!($ptr),
        ));
    }};
}

/// `MOV byte [ptr], val8; INC ptr`.
macro_rules! storeb_inc {
    ($e:expr, $ptr:tt, $val:tt) => {{
        let (v, b) = (
            $crate::elf::x86_64::xreg!($val),
            $crate::elf::x86_64::xreg!($ptr),
        );
        // mov r/m8, r8: 88 /r — REX.R for the reg field (src), REX.B for rm.
        let p: u8 = (0x40 | (((v >= 8) as u8) << 2) | ((b >= 8) as u8)) as u8;
        $e.emit(&[p, 0x88]);
        if (b & 7) == 4 {
            $e.emit(&[$crate::elf::x86_64::modrm(2, v, 4) as u8, 0x24]);
        } else if (b & 7) == 5 || b == 4 {
            // rbp/r13 base (or rsp — handled above but keep SIB form safe)
            if (b & 7) == 4 {
                $e.emit(&[$crate::elf::x86_64::modrm(2, v, 4) as u8, 0x24]);
            } else {
                $e.emit(&[$crate::elf::x86_64::modrm(2, v, b) as u8, 0, 0, 0]);
            }
        } else {
            $e.emit(&[$crate::elf::x86_64::modrm(1, v, b) as u8, 0]);
        }
        $e.emit(&$crate::elf::x86_64::inc_r64_vec(b));
    }};
}

/// Batch-register null-terminated C strings in the data section.
macro_rules! xstrings {
    ($e:expr, $($name:ident = $val:expr),* $(,)?) => {
        $(let $name = $e.emit_cstring($val);)*
    };
}

/// `mount(source, target, fstype [, flags [, data_reg]])`.
macro_rules! xmount {
    ($e:expr, $src:expr, $tgt:expr, $fs:expr) => {
        $crate::elf::x86_64::xmount!($e, $src, $tgt, $fs, 0)
    };
    ($e:expr, $src:expr, $tgt:expr, $fs:expr, $flags:expr) => {{
        $crate::elf::x86_64::lea!($e, rdi, $src);
        $crate::elf::x86_64::lea!($e, rsi, $tgt);
        $crate::elf::x86_64::lea!($e, rdx, $fs);
        $crate::elf::x86_64::mov_i!($e, r10, $flags);
        $crate::elf::x86_64::zero!($e, r8);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::MOUNT);
    }};
    ($e:expr, $src:expr, $tgt:expr, $fs:expr, $flags:expr, $data:tt) => {{
        $crate::elf::x86_64::lea!($e, rdi, $src);
        $crate::elf::x86_64::lea!($e, rsi, $tgt);
        $crate::elf::x86_64::lea!($e, rdx, $fs);
        $crate::elf::x86_64::mov_i!($e, r10, $flags);
        $crate::elf::x86_64::mov_rr_!($e, r8, $data);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::MOUNT);
    }};
}

/// `mount --bind source target`.
macro_rules! xmount_bind {
    ($e:expr, $src:expr, $tgt:expr) => {{
        $crate::elf::x86_64::lea!($e, rdi, $src);
        $crate::elf::x86_64::lea!($e, rsi, $tgt);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::mov_i!($e, r10, $crate::elf::x86_64_linux::MS_BIND);
        $crate::elf::x86_64::zero!($e, r8);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::MOUNT);
    }};
}

/// `mkdir path` — mkdirat(AT_FDCWD, path, 0755).
macro_rules! xmkdir {
    ($e:expr, $path:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $crate::elf::x86_64_linux::AT_FDCWD);
        $crate::elf::x86_64::lea!($e, rsi, $path);
        $crate::elf::x86_64::mov_i!($e, rdx, 0x1ED);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::MKDIRAT);
    }};
}

/// `mkdir child` under a parent *path*: openat(parent) + mkdirat + close.
#[allow(unused_macros)]
macro_rules! xmkdir_under {
    ($e:expr, $parent:expr, $child:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $crate::elf::x86_64_linux::AT_FDCWD);
        $crate::elf::x86_64::lea!($e, rsi, $parent);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::mov_i!($e, r10, $crate::elf::x86_64_linux::O_RDONLY);
        $crate::elf::x86_64::zero!($e, r8);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::OPENAT);
        $crate::elf::x86_64::mov_rr_!($e, r14, rax); // parent dirfd
        $crate::elf::x86_64::mov_rr_!($e, rdi, rax);
        $crate::elf::x86_64::lea!($e, rsi, $child);
        $crate::elf::x86_64::mov_i!($e, rdx, 0x1ED);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::MKDIRAT);
        $crate::elf::x86_64::mov_rr_!($e, rdi, r14);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::CLOSE);
    }};
}

/// `cd path`.
macro_rules! xchdir {
    ($e:expr, $path:expr) => {{
        $crate::elf::x86_64::lea!($e, rdi, $path);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::CHDIR);
    }};
}

/// `pivot_root new_root put_old`.
macro_rules! xpivot_root {
    ($e:expr, $new:expr, $old:expr) => {{
        $crate::elf::x86_64::lea!($e, rdi, $new);
        $crate::elf::x86_64::lea!($e, rsi, $old);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::PIVOT_ROOT);
    }};
}

/// `openat(AT_FDCWD, path, flags [, mode])` — result in rax.
macro_rules! xopenat {
    ($e:expr, $path:expr, $flags:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $crate::elf::x86_64_linux::AT_FDCWD);
        $crate::elf::x86_64::lea!($e, rsi, $path);
        $crate::elf::x86_64::mov_i!($e, rdx, $flags);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::OPENAT);
    }};
    ($e:expr, $path:expr, $flags:expr, $mode:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $crate::elf::x86_64_linux::AT_FDCWD);
        $crate::elf::x86_64::lea!($e, rsi, $path);
        $crate::elf::x86_64::mov_i!($e, rdx, $flags);
        $crate::elf::x86_64::mov_i!($e, r10, $mode);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::OPENAT);
    }};
}

/// `close(fd_register)`.
macro_rules! xclose {
    ($e:expr, $fd:tt) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $fd);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::CLOSE);
    }};
}

/// `exit(code)`.
macro_rules! xexit {
    ($e:expr, $code:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $code);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::EXIT);
    }};
}

/// `ioctl(fd_reg, cmd, buf_ptr_reg)`.
macro_rules! xioctl {
    ($e:expr, $fd:tt, $cmd:expr, $buf:tt) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $fd);
        $crate::elf::x86_64::mov_i!($e, rsi, $cmd);
        $crate::elf::x86_64::mov_rr_!($e, rdx, $buf);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::IOCTL);
    }};
    ($e:expr, $fd:tt, $cmd:expr) => {
        $crate::elf::x86_64::xioctl!($e, $fd, $cmd, rsp)
    };
}

/// `ioctl(fd, cmd, immediate)`.
macro_rules! xioctl_imm {
    ($e:expr, $fd:tt, $cmd:expr, $val:expr) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $fd);
        $crate::elf::x86_64::mov_i!($e, rsi, $cmd);
        $crate::elf::x86_64::mov_i!($e, rdx, $val);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::IOCTL);
    }};
}

/// `setsid()`.
macro_rules! xsetsid {
    ($e:expr) => {
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::SETSID)
    };
}

/// `dup3(oldfd_reg, newfd_imm)`.
macro_rules! xdup3 {
    ($e:expr, $oldfd:tt, $newfd:expr) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $oldfd);
        $crate::elf::x86_64::mov_i!($e, rsi, $newfd);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::DUP3);
    }};
}

/// `fork()` — clone(SIGCHLD, 0, 0, 0, 0); child pid in rax.
macro_rules! xfork {
    ($e:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $crate::elf::x86_64_linux::SIGCHLD);
        $crate::elf::x86_64::zero!($e, rsi);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::zero!($e, r10);
        $crate::elf::x86_64::zero!($e, r8);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::CLONE);
    }};
}

/// `wait4(pid_reg)` — status written to [rsp].
macro_rules! xwait4 {
    ($e:expr, $pid:tt) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $pid);
        $crate::elf::x86_64::mov_rr_!($e, rsi, rsp);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::zero!($e, r10);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::WAIT4);
    }};
}

/// `reboot(LINUX_REBOOT_CMD_POWER_OFF)`.
macro_rules! xreboot {
    ($e:expr) => {{
        $e.emit(&$crate::elf::x86_64::mov_r_imm64(
            $crate::elf::x86_64::xreg!(rdi),
            0xFEE1_DEAD,
        ));
        $e.emit(&$crate::elf::x86_64::mov_r_imm64(
            $crate::elf::x86_64::xreg!(rsi),
            0x2812_1969,
        ));
        $e.emit(&$crate::elf::x86_64::mov_r_imm64(
            $crate::elf::x86_64::xreg!(rdx),
            0x4321_FEDC,
        ));
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::REBOOT);
    }};
}

/// `socket(domain, type)`.
macro_rules! socket_ {
    ($e:expr, $domain:expr, $ty:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $domain);
        $crate::elf::x86_64::mov_i!($e, rsi, $ty);
        $crate::elf::x86_64::zero!($e, rdx);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::SOCKET);
    }};
}

/// `clock_settime(clockid, &timespec @ rsp)`.
macro_rules! xclock_settime {
    ($e:expr, $clk:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $clk);
        $crate::elf::x86_64::mov_rr_!($e, rsi, rsp);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::CLOCK_SETTIME);
    }};
}

/// `write(fd, buf, len)` — immediate or register fd.
macro_rules! xsys_write {
    ($e:expr, $fd:literal, $buf:expr, $len:expr) => {{
        $crate::elf::x86_64::mov_i!($e, rdi, $fd);
        $crate::elf::x86_64::lea!($e, rsi, $buf);
        $crate::elf::x86_64::mov_i!($e, rdx, $len);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::WRITE);
    }};
    ($e:expr, $fd:tt, $buf:expr, $len:expr) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $fd);
        $crate::elf::x86_64::lea!($e, rsi, $buf);
        $crate::elf::x86_64::mov_i!($e, rdx, $len);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::WRITE);
    }};
    ($e:expr, $fd:tt, $ptr:tt) => {{
        $crate::elf::x86_64::mov_rr_!($e, rdi, $fd);
        $crate::elf::x86_64::mov_rr_!($e, rsi, $ptr);
        $crate::elf::x86_64::sys!($e, $crate::elf::x86_64_linux::nr::WRITE);
    }};
}

/// VMM hypercalls via a dedicated I/O port (the x86 analog of `BRK #imm`).
///
///   - port [`INIT_CONFIG_PORT`]: `IN EAX, DX` returns the config blob size;
///     the VMM pushes the blob to the console RX beforehand.
///   - port [`EXPORT_RESIZE_PORT`] / [`EXPORT_DONE_PORT`]: `OUT DX, AL`.
macro_rules! hyper_config_size {
    ($e:expr) => {{
        // mov dx, INIT_CONFIG_PORT; in eax, dx
        $e.emit(&[0x66, 0xBA]);
        $e.emit(&($crate::elf::x86_64_linux::INIT_CONFIG_PORT as u16).to_le_bytes());
        $e.emit(&$crate::elf::x86_64::in_eax_dx());
    }};
}

macro_rules! hyper_signal {
    ($e:expr, $port:expr) => {{
        // mov dx, port; xor eax, eax; out dx, al
        $e.emit(&[0x66, 0xBA]);
        $e.emit(&($port as u16).to_le_bytes());
        $e.emit(&$crate::elf::x86_64::xor_rr(
            $crate::elf::x86_64::xreg!(rax),
            $crate::elf::x86_64::xreg!(rax),
        ));
        $e.emit(&$crate::elf::x86_64::out_dx_al());
    }};
}

/// `strlen(src)` — length of the NUL-terminated string at src into rdx.
#[allow(unused_macros)]
macro_rules! xstrlen {
    ($e:expr, $src:tt) => {{
        $crate::elf::x86_64::mov_rr_!($e, rsi, $src);
        let _loop = $e.offset();
        $crate::elf::x86_64::loadb_inc!($e, r11, rsi);
        $crate::elf::x86_64::jcc_back!($e, Branch::Jne, _loop);
        $crate::elf::x86_64::sub_rr_!($e, rdx, rsi);
        $crate::elf::x86_64::sub_i!($e, rdx, 1);
    }};
}

// ── Macro re-exports ────────────────────────────────────────────────────
// Re-exported for the crafted-binary builders; not every guest program
// uses every macro (see the module-level allow at the top of this file).

pub(crate) use add_i;
pub(crate) use add_rr_;
pub(crate) use cmp_i;
pub(crate) use cmp_rr_;
pub(crate) use hyper_config_size;
pub(crate) use hyper_signal;
pub(crate) use jcc_back;
pub(crate) use jcc_fwd;
pub(crate) use lea;
pub(crate) use load64;
pub(crate) use loadb_inc;
pub(crate) use loadzx8;
pub(crate) use mov_i;
pub(crate) use mov_rr_;
pub(crate) use patch_jcc;
pub(crate) use socket_;
pub(crate) use store32i;
pub(crate) use store64;
pub(crate) use storeb_inc;
pub(crate) use sub_i;
pub(crate) use sub_rr_;
pub(crate) use sys;
pub(crate) use test_;
pub(crate) use xchdir;
pub(crate) use xclock_settime;
pub(crate) use xclose;
pub(crate) use xdup3;
pub(crate) use xexit;
pub(crate) use xfork;
pub(crate) use xioctl;
pub(crate) use xioctl_imm;
pub(crate) use xmkdir;
pub(crate) use xmkdir_under;
pub(crate) use xmount;
pub(crate) use xmount_bind;
pub(crate) use xopenat;
pub(crate) use xpivot_root;
pub(crate) use xreboot;
pub(crate) use xreg;
pub(crate) use xsetsid;
pub(crate) use xstrings;
pub(crate) use xsys_write;
pub(crate) use xwait4;
pub(crate) use xzero_stack;
pub(crate) use zero;
