//! ARM64 (AArch64) instruction encoders.
//!
//! All functions are `const fn` — they are pure arithmetic and can be
//! evaluated at compile time.

// ── Move instructions ───────────────────────────────────────────────────

/// `MOVN Xd, #imm16` — move wide with NOT (64-bit).
/// Loads `~(imm16 << 0)` into `Xd`.  Commonly used for small negative
/// constants, e.g. `movn_x(0, 99)` produces `X0 = -100`.
pub const fn movn_x(rd: u32, imm16: u32) -> u32 {
    0x92800000 | (imm16 << 5) | rd
}

/// `MOVZ Xd, #imm16` — move wide with zero (64-bit).
pub const fn movz_x(rd: u32, imm16: u32) -> u32 {
    0xD2800000 | (imm16 << 5) | rd
}

/// `MOVZ Wd, #imm16` — move wide with zero (32-bit).
pub const fn movz_w(rd: u32, imm16: u32) -> u32 {
    0x52800000 | (imm16 << 5) | rd
}

/// `MOVK Xd, #imm16, LSL #shift` — move with keep (64-bit).
/// Inserts `imm16` into the 16-bit field at `shift` (0, 16, 32, 48)
/// without disturbing other bits.
pub const fn movk_x(rd: u32, imm16: u32, shift: u32) -> u32 {
    let hw = shift / 16;
    0xF2800000 | (hw << 21) | (imm16 << 5) | rd
}

/// `MOVK Wd, #imm16, LSL #shift` — move with keep (32-bit).
/// Inserts `imm16` into the 16-bit field at `shift` (0, 16).
pub const fn movk_w(rd: u32, imm16: u32, shift: u32) -> u32 {
    let hw = shift / 16;
    0x72800000 | (hw << 21) | (imm16 << 5) | rd
}

// ── Arithmetic / logical ────────────────────────────────────────────────

/// `MOV Xd, Xm` — encoded as `ORR Xd, XZR, Xm`.
pub const fn mov_x(rd: u32, rm: u32) -> u32 {
    0xAA0003E0 | (rm << 16) | rd
}

/// `ADD Xd, Xn|SP, #imm12` — 64-bit add immediate.
pub const fn add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x91000000 | (imm12 << 10) | (rn << 5) | rd
}

/// `ADD Xd, Xn, Xm` — 64-bit add (shifted register, shift=0).
pub const fn add_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8B000000 | (rm << 16) | (rn << 5) | rd
}

/// `SUB Xd, Xn|SP, #imm12` — 64-bit subtract immediate.
pub const fn sub_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0xD1000000 | (imm12 << 10) | (rn << 5) | rd
}

/// `CMP Xn, #imm12` — compare immediate, encoded as `SUBS XZR, Xn, #imm12`.
pub const fn cmp_x_imm(rn: u32, imm12: u32) -> u32 {
    0xF1000000 | (imm12 << 10) | (rn << 5) | 31
}

/// `CMP Xn, Xm` — compare registers, encoded as `SUBS XZR, Xn, Xm`.
pub const fn cmp_x_reg(rn: u32, rm: u32) -> u32 {
    0xEB000000 | (rm << 16) | (rn << 5) | 31
}

/// `LSL Xd, Xn, #shift` — logical shift left, encoded as `UBFM`.
pub const fn lsl_x(rd: u32, rn: u32, shift: u32) -> u32 {
    let immr = (64 - shift) & 63;
    let imms = 63 - shift;
    0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
}

/// `UBFX Xd, Xn, #lsb, #width` — unsigned bitfield extract.
/// Extracts `width` bits starting at bit `lsb`.
/// Encoded as `UBFM Xd, Xn, #lsb, #(lsb+width-1)`.
pub const fn ubfx_x(rd: u32, rn: u32, lsb: u32, width: u32) -> u32 {
    let immr = lsb;
    let imms = lsb + width - 1;
    0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
}

// ── Load / store ────────────────────────────────────────────────────────

/// `LDR Xt, [SP, #byte_off]` — load 64-bit from stack (unsigned offset).
/// `byte_off` must be 8-byte aligned.
pub const fn ldr_x_sp(rt: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(8),
        "byte_off must be 8-byte aligned"
    );
    0xF9400000 | ((byte_off / 8) << 10) | (31 << 5) | rt
}

/// `LDR Xt, [Xn, #byte_off]` — load 64-bit (unsigned offset).
/// `byte_off` must be 8-byte aligned.
pub const fn ldr_x(rt: u32, rn: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(8),
        "byte_off must be 8-byte aligned"
    );
    0xF9400000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}

/// `LDR Wt, [Xn, #byte_off]` — load 32-bit (unsigned offset).
/// `byte_off` must be 4-byte aligned.
pub const fn ldr_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(4),
        "byte_off must be 4-byte aligned"
    );
    0xB9400000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}

/// `STR Xt, [Xn, #byte_off]` — store 64-bit (unsigned offset).
/// `byte_off` must be 8-byte aligned.
pub const fn str_x(rt: u32, rn: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(8),
        "byte_off must be 8-byte aligned"
    );
    0xF9000000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}

/// `STR Wt, [Xn, #byte_off]` — store 32-bit (unsigned offset).
/// `byte_off` must be 4-byte aligned.
pub const fn str_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(4),
        "byte_off must be 4-byte aligned"
    );
    0xB9000000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}

/// `STRH Wt, [Xn, #byte_off]` — store 16-bit (unsigned offset).
/// `byte_off` must be 2-byte aligned.
pub const fn strh_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    assert!(
        byte_off.is_multiple_of(2),
        "byte_off must be 2-byte aligned"
    );
    0x79000000 | ((byte_off / 2) << 10) | (rn << 5) | rt
}

/// `LDRB Wt, [Xn, #byte_off]` — load byte (unsigned offset).
pub const fn ldrb_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x39400000 | (byte_off << 10) | (rn << 5) | rt
}

/// `LDRB Wt, [Xn], #1` — load byte with post-increment by 1.
pub const fn ldrb_w_post(rt: u32, rn: u32) -> u32 {
    0x38400400 | (1 << 12) | (rn << 5) | rt
}

/// `STRB Wt, [Xn], #1` — store byte with post-increment by 1.
pub const fn strb_w_post(rt: u32, rn: u32) -> u32 {
    0x38000400 | (1 << 12) | (rn << 5) | rt
}

// ── Address computation ─────────────────────────────────────────────────

/// `ADR Xd, #byte_offset` — PC-relative address (±1 MB range).
/// `byte_offset` is the signed byte distance from this instruction to the target.
pub const fn adr_x(rd: u32, byte_offset: i32) -> u32 {
    let imm = byte_offset as u32;
    let immlo = imm & 3;
    let immhi = (imm >> 2) & 0x7FFFF;
    (immlo << 29) | 0x10000000 | (immhi << 5) | rd
}

// ── Branch / system ─────────────────────────────────────────────────────

/// `B #offset` — unconditional branch.
/// `offset_insns` is in instructions (not bytes) relative to this instruction.
pub const fn b(offset_insns: i32) -> u32 {
    0x14000000 | ((offset_insns as u32) & 0x3FFFFFF)
}

/// `B.LT` — branch if less-than (signed). `offset_insns` is in
/// instructions (not bytes) relative to this instruction.
pub const fn b_lt(offset_insns: i32) -> u32 {
    0x54000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | 0xB
}

/// `B.GE` — branch if greater-or-equal (signed).
pub const fn b_ge(offset_insns: i32) -> u32 {
    0x54000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | 0xA
}

/// `CBZ Xt, #offset` — compare and branch if zero (64-bit).
/// `offset_insns` is in instructions.
pub const fn cbz(rt: u32, offset_insns: i32) -> u32 {
    0xB4000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | rt
}

/// `CBNZ Xt, #offset` — compare and branch if not zero (64-bit).
/// `offset_insns` is in instructions.
pub const fn cbnz(rt: u32, offset_insns: i32) -> u32 {
    0xB5000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | rt
}

/// `BRK #imm16` — breakpoint instruction.
/// Causes an exception trapped by the hypervisor (EC=0x3C).
pub const fn brk(imm16: u32) -> u32 {
    0xD4200000 | (imm16 << 5)
}

/// `SVC #0` — supervisor call (syscall).
pub const fn svc0() -> u32 {
    0xD4000001
}

/// `UDIV Xd, Xn, Xm` — unsigned divide (64-bit).
pub const fn udiv_x(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9AC00800 | (rm << 16) | (rn << 5) | rd
}

/// `MSUB Xd, Xn, Xm, Xa` — multiply-subtract: `Xd = Xa - Xn * Xm`.
/// Useful for computing remainder after UDIV.
pub const fn msub_x(rd: u32, rn: u32, rm: u32, ra: u32) -> u32 {
    0x9B008000 | (rm << 16) | (ra << 10) | (rn << 5) | rd
}

/// `SUB Xd, Xn, Xm` — 64-bit subtract (register).
pub const fn sub_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xCB000000 | (rm << 16) | (rn << 5) | rd
}

/// `BIC Xd, Xn, Xm` — 64-bit bit clear (Xd = Xn AND NOT Xm).
pub const fn bic_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8A200000 | (rm << 16) | (rn << 5) | rd
}

/// `SUB Xd|SP, Xn|SP, Xm (UXTX)` — 64-bit subtract using *extended
/// register* encoding so that register 31 is SP (not XZR).
///
/// The shifted-register form (`SUB Xd, Xn, Xm`) treats reg 31 as XZR.
/// This variant uses the extended-register form with UXTX #0 (identity
/// extension for 64-bit) which treats Rd and Rn as SP when they are 31.
pub const fn sub_sp_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    // SUB (extended register): sf=1 op=1 S=0 01011 00 1 Rm option=011 imm3=000 Rn Rd
    0xCB206000 | (rm << 16) | (rn << 5) | rd
}

/// `NOP` — no operation.
pub const fn nop() -> u32 {
    0xD503201F
}
