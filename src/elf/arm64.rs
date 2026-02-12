//! ARM64 (AArch64) instruction encoders.
//!
//! Each function returns a single 32-bit little-endian ARM64 instruction.

// ── Move instructions ───────────────────────────────────────────────────

/// `MOVN Xd, #imm16` — move wide with NOT (64-bit).
/// Loads `~(imm16 << 0)` into `Xd`.  Commonly used for small negative
/// constants, e.g. `movn_x(0, 99)` produces `X0 = -100`.
pub fn movn_x(rd: u32, imm16: u32) -> u32 {
    0x92800000 | (imm16 << 5) | rd
}

/// `MOVZ Xd, #imm16` — move wide with zero (64-bit).
pub fn movz_x(rd: u32, imm16: u32) -> u32 {
    0xD2800000 | (imm16 << 5) | rd
}

/// `MOVZ Wd, #imm16` — move wide with zero (32-bit).
pub fn movz_w(rd: u32, imm16: u32) -> u32 {
    0x52800000 | (imm16 << 5) | rd
}

// ── Arithmetic / logical ────────────────────────────────────────────────

/// `MOV Xd, Xm` — encoded as `ORR Xd, XZR, Xm`.
pub fn mov_x(rd: u32, rm: u32) -> u32 {
    0xAA0003E0 | (rm << 16) | rd
}

/// `ADD Xd, Xn|SP, #imm12` — 64-bit add immediate.
pub fn add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x91000000 | (imm12 << 10) | (rn << 5) | rd
}

/// `ADD Xd, Xn, Xm` — 64-bit add (shifted register, shift=0).
pub fn add_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8B000000 | (rm << 16) | (rn << 5) | rd
}

/// `CMP Xn, #imm12` — compare immediate, encoded as `SUBS XZR, Xn, #imm12`.
pub fn cmp_x_imm(rn: u32, imm12: u32) -> u32 {
    0xF1000000 | (imm12 << 10) | (rn << 5) | 31
}

/// `LSL Xd, Xn, #shift` — logical shift left, encoded as `UBFM`.
pub fn lsl_x(rd: u32, rn: u32, shift: u32) -> u32 {
    let immr = (64 - shift) & 63;
    let imms = 63 - shift;
    0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
}

// ── Load / store ────────────────────────────────────────────────────────

/// `LDR Xt, [SP, #byte_off]` — load 64-bit from stack (unsigned offset).
/// `byte_off` must be 8-byte aligned.
pub fn ldr_x_sp(rt: u32, byte_off: u32) -> u32 {
    assert!(byte_off.is_multiple_of(8), "byte_off must be 8-byte aligned");
    0xF9400000 | ((byte_off / 8) << 10) | (31 << 5) | rt
}

// ── Branch / system ─────────────────────────────────────────────────────

/// `B.LT` — branch if less-than (signed). `offset_insns` is in
/// instructions (not bytes) relative to this instruction.
pub fn b_lt(offset_insns: i32) -> u32 {
    0x54000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | 0xB
}

/// `SVC #0` — supervisor call (syscall).
pub fn svc0() -> u32 {
    0xD4000001
}
