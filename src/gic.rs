//! Software GICv3 emulation (spec: docs/vmm-spec.md §2.2).
//!
//! HVF's native GIC (`hv_gic_create`) is deliberately not used: the VMM must
//! observe the guest's ICC EOI to unmask the HVF vtimer, which is only possible
//! when the ICC system registers trap.  This module owns the complete interrupt
//! state: distributor/redistributor MMIO registers, CPU-interface sysregs, and
//! level-triggered device SPIs.

// Interrupt numbers (GIC INTID). SPIs: INTID = 32 + spi_num.
pub const IRQ_VTIMER: u32 = 27; // PPI 11 (virtual timer)
pub const SPI_NET: u32 = 16;
pub const SPI_CONSOLE: u32 = 17;
pub const SPI_BLK: u32 = 18;
pub const SPI_DATA_BLK: u32 = 19;
pub const SPI_RNG: u32 = 20;
pub const SPI_FS_START: u32 = 21; // virtiofs devices take SPI_FS_START + i

// ─────────────────────────────────────────────────────────────────────────────
// Software GICv3
// ─────────────────────────────────────────────────────────────────────────────
#[inline]
fn test_bit(arr: &[u64; 2], intid: u32) -> bool {
    (arr[(intid / 64) as usize] >> (intid % 64)) & 1 != 0
}

#[inline]
fn set_bit(arr: &mut [u64; 2], intid: u32, on: bool) {
    let idx = (intid / 64) as usize;
    let bit = 1u64 << (intid % 64);
    if on {
        arr[idx] |= bit;
    } else {
        arr[idx] &= !bit;
    }
}

/// Read the distributor bitmap register `n` (32-bit register at `base + 4n`,
/// covering INTIDs 32n..32n+31) out of a 128-bit per-INTID state array.
#[inline]
fn bitmap_read(arr: &[u64; 2], n: usize) -> u32 {
    let bit0 = 32 * n;
    (arr[bit0 / 64] >> (bit0 % 64)) as u32
}

/// Set or clear the bits of distributor bitmap register `n`.
#[inline]
fn bitmap_set(arr: &mut [u64; 2], n: usize, val: u32, on: bool) {
    let bit0 = 32 * n;
    let mask = (val as u64) << (bit0 % 64);
    if on {
        arr[bit0 / 64] |= mask;
    } else {
        arr[bit0 / 64] &= !mask;
    }
}

/// Replace the contents of distributor bitmap register `n`.
#[inline]
fn bitmap_replace(arr: &mut [u64; 2], n: usize, val: u32) {
    let bit0 = 32 * n;
    let idx = bit0 / 64;
    let shift = bit0 % 64;
    arr[idx] = (arr[idx] & !(0xffff_ffffu64 << shift)) | ((val as u64) << shift);
}

/// GICD/GICR ICFGR: two config bits per INTID; register `n` covers INTIDs
/// 16n..16n+15, i.e. one 32-bit half-word of the 256-bit config array.
#[inline]
fn icfgr_read(arr: &[u64; 4], n: usize) -> u32 {
    let bit0 = 32 * n;
    (arr[bit0 / 64] >> (bit0 % 64)) as u32
}

#[inline]
fn icfgr_write(arr: &mut [u64; 4], n: usize, val: u32) {
    let bit0 = 32 * n;
    let idx = bit0 / 64;
    let shift = bit0 % 64;
    arr[idx] = (arr[idx] & !(0xffff_ffffu64 << shift)) | ((val as u64) << shift);
}

#[derive(Clone, Copy)]
pub struct Gic {
    // Distributor
    pub d_ctlr: u32,
    pub d_typer: u64,
    pub d_iidr: u32,
    // Per-INTID state, 128 interrupts (INTID 0-127). Redistributor owns 0-31,
    // distributor owns 32-127; the arrays are shared for simplicity.
    pub igroupr: [u64; 2],   // 0 = Group 0, 1 = Group 1
    pub isenabler: [u64; 2], // enable
    pub ispendr: [u64; 2],   // pending
    pub isactiver: [u64; 2], // active
    pub icfgr: [u64; 4],     // trigger: 2 bits per INTID (16 per 32-bit register), 0 = level
    pub igrpmodr: [u64; 2],
    pub ipriority: [u8; 128],
    // Redistributor
    pub r_ctlr: u32,
    pub r_typer: u64,
    pub r_waker: u32,
    pub r_pidr0: u32,
    // CPU interface
    pub icc_pmr: u8,
    pub icc_bpr1: u8,
    pub icc_ctlr: u32,
    pub icc_sre: u32,
    pub icc_igrpen0: u32,
    pub icc_igrpen1: u32,
    pub icc_ap1r0: u32,
}

impl Default for Gic {
    fn default() -> Self {
        Gic {
            d_ctlr: 0,
            d_typer: 0,
            d_iidr: 0,
            igroupr: [0; 2],
            isenabler: [0; 2],
            ispendr: [0; 2],
            isactiver: [0; 2],
            icfgr: [0; 4],
            igrpmodr: [0; 2],
            ipriority: [0; 128],
            r_ctlr: 0,
            r_typer: 0,
            r_waker: 0,
            r_pidr0: 0,
            icc_pmr: 0,
            icc_bpr1: 0,
            icc_ctlr: 0,
            icc_sre: 0,
            icc_igrpen0: 0,
            icc_igrpen1: 0,
            icc_ap1r0: 0,
        }
    }
}

impl Gic {
    pub fn new() -> Self {
        Gic {
            d_typer: 0x1,        // ITLinesNumber=1 (64 SPIs), no ITS/LSPI
            d_iidr: 0x0202_043b, // ARM Ltd, arch rev
            // GICR_TYPER: bit 4 is Last (per ARM IHI0069 / Linux
            // GICR_TYPER_LAST); bits [63:32] are the processor affinity (0 for
            // CPU0).  Setting the Last bit stops Linux's gic_iterate_rdists()
            // from stepping into the next (unmapped) 128 KiB redistributor frame.
            r_typer: 1u64 << 4,
            r_pidr0: 0x0000_0090, // PIDR0: ARM Ltd
            icc_pmr: 0xf0,        // allow all priorities by default
            icc_sre: 1,           // system register interface enabled
            icc_igrpen1: 1,       // group 1 (IRQ) enabled
            icc_ctlr: 3 << 29,    // PRIbits: 8 priority bits
            ..Gic::default()
        }
    }

    #[inline]
    pub fn set_pending(&mut self, intid: u32) {
        // A level interrupt must not re-pend while it is already Active.
        if !test_bit(&self.isactiver, intid) {
            set_bit(&mut self.ispendr, intid, true);
        }
    }

    /// Update level-triggered device pending state from the devices.
    /// Re-assert level-triggered device interrupts.  `active` lists the INTIDs
    /// of devices whose `interrupt_status` is non-zero; a level interrupt is
    /// re-pended on every pass and only stays high while the device asserts.
    pub fn update_level_irqs(&mut self, active: &[u32]) {
        for &intid in active {
            self.set_pending(intid);
        }
    }

    /// True if there is an enabled, pending interrupt whose priority passes PMR.
    pub fn deliverable(&self) -> bool {
        // Fast path: nothing pending at all.
        if self.ispendr == [0, 0] {
            return false;
        }
        let group1_ok = self.icc_igrpen1 != 0;
        let group0_ok = self.icc_igrpen0 != 0;
        for intid in 0u32..128 {
            let bit = 1u64 << (intid % 64);
            let arr_idx = (intid / 64) as usize;
            if self.ispendr[arr_idx] & bit == 0 {
                continue;
            }
            if self.isenabler[arr_idx] & bit == 0 {
                continue;
            }
            let grp = (self.igroupr[arr_idx] >> (intid % 64)) & 1;
            if grp == 1 && !group1_ok {
                continue;
            }
            if grp == 0 && !group0_ok {
                continue;
            }
            if (self.ipriority[intid as usize] as u32) > (self.icc_pmr as u32) {
                continue;
            }
            return true;
        }
        false
    }

    /// ICC_IAR1_EL1 read: return the highest-priority pending+enabled group-1
    /// interrupt, mark it Active. Returns 1023 (spurious) if none.
    pub fn ack(&mut self) -> u32 {
        let mut best = 0u32;
        let mut best_prio = 0xffu8;
        let mut found = false;
        for intid in 0u32..128 {
            let bit = 1u64 << (intid % 64);
            let arr_idx = (intid / 64) as usize;
            if self.ispendr[arr_idx] & bit == 0 {
                continue;
            }
            if self.isenabler[arr_idx] & bit == 0 {
                continue;
            }
            if (self.igroupr[arr_idx] >> (intid % 64)) & 1 != 1 {
                continue; // group 1 only for IAR1
            }
            let prio = self.ipriority[intid as usize];
            if (prio as u32) > (self.icc_pmr as u32) {
                continue;
            }
            if prio < best_prio {
                best = intid;
                best_prio = prio;
                found = true;
            }
        }
        if !found {
            return 1023;
        }
        set_bit(&mut self.ispendr, best, false);
        set_bit(&mut self.isactiver, best, true);
        best
    }

    /// ICC_EOIR1_EL1 / ICC_DIR_EL1 write: deactivate the interrupt.
    pub fn eoi(&mut self, intid: u32) {
        set_bit(&mut self.isactiver, intid, false);
        // Level-triggered sources that are still asserting re-pend on EOI.
        // (Device IRQs are re-pended by update_level_irqs after every exit;
        // the vtimer is re-pended by the next VTIMER_ACTIVATED exit.)
    }

    // ── Distributor MMIO ───────────────────────────────────────────────
    pub fn gicd_read(&self, off: u64) -> u32 {
        match off {
            0x000 => self.d_ctlr,
            0x004 => (self.d_typer & 0xffff_ffff) as u32,
            0x008 => self.d_iidr,
            // Peripheral ID registers — used by Linux to detect GICv3:
            // (GICD_PIDR2 & 0xf0) must be 0x30 (GICv3) or 0x40 (GICv4).
            0xffe0 => 0x90, // PIDR0 (ARM Ltd)
            0xffe4 => 0xb4, // PIDR1
            0xffe8 => 0x3b, // PIDR2 (arch rev 3 = GICv3)
            0xffec => 0x00, // PIDR3
            0xffd0 => 0x04, // PIDR4
            _ => {
                // Bitmap registers: 32-bit register at `base + 4n` covers
                // INTIDs 32n..32n+31.  n = 0 (INTIDs 0-31) is owned by the
                // redistributor and reads as zero here.
                let (base, arr): (u64, &[u64; 2]) = match off {
                    0x080..=0x0bc => (0x080, &self.igroupr),
                    0x100..=0x13c => (0x100, &self.isenabler),
                    0x180..=0x1bc => (0x180, &self.isenabler),
                    0x200..=0x23c => (0x200, &self.ispendr),
                    0x280..=0x2bc => (0x280, &self.ispendr),
                    0x300..=0x33c => (0x300, &self.isactiver),
                    0x380..=0x3bc => (0x380, &self.isactiver),
                    0xd00..=0xd3c => (0xd00, &self.igrpmodr),
                    _ => {
                        // GICD_ICFGRn: 16 INTIDs per 32-bit register.
                        if (0xc00..=0xc1c).contains(&off) {
                            let n = ((off - 0xc00) / 4) as usize;
                            if n < 2 {
                                return 0; // INTID 0-31 are redistributor-owned
                            }
                            return icfgr_read(&self.icfgr, n);
                        }
                        // GICD_IPRIORITYRn: 4 priorities per 32-bit register.
                        if (0x400..=0x7fc).contains(&off) {
                            let base_intid = ((off - 0x400) / 4 * 4) as usize;
                            if base_intid < 32 {
                                return 0;
                            }
                            let mut v = 0u32;
                            for i in 0..4 {
                                v |= (self.ipriority[base_intid + i] as u32) << (i * 8);
                            }
                            return v;
                        }
                        return 0;
                    }
                };
                let n = ((off - base) / 4) as usize;
                if n == 0 {
                    return 0;
                }
                bitmap_read(arr, n)
            }
        }
    }

    pub fn gicd_write(&mut self, off: u64, val: u32) {
        match off {
            0x000 => self.d_ctlr = val,
            0x004 | 0x008 => { /* TYPER/IIDR read-only */ }
            0x0f00 => { /* GICD_SGIR: ignore (no SGIs for a UP guest) */ }
            _ => {
                let (base, which): (u64, u8) = match off {
                    0x080..=0x0bc => (0x080, 0),
                    0x100..=0x13c => (0x100, 1),
                    0x180..=0x1bc => (0x180, 2),
                    0x200..=0x23c => (0x200, 3),
                    0x280..=0x2bc => (0x280, 4),
                    0x300..=0x33c => (0x300, 5),
                    0x380..=0x3bc => (0x380, 6),
                    0xd00..=0xd3c => (0xd00, 7),
                    _ => {
                        if (0xc00..=0xc1c).contains(&off) {
                            let n = ((off - 0xc00) / 4) as usize;
                            if n >= 2 {
                                icfgr_write(&mut self.icfgr, n, val);
                            }
                            return;
                        }
                        if (0x400..=0x7fc).contains(&off) {
                            let base_intid = ((off - 0x400) / 4 * 4) as usize;
                            if base_intid < 32 {
                                return;
                            }
                            for i in 0..4 {
                                self.ipriority[base_intid + i] = ((val >> (i * 8)) & 0xff) as u8;
                            }
                        }
                        return;
                    }
                };
                let n = ((off - base) / 4) as usize;
                if n == 0 {
                    return; // INTID 0-31 owned by the redistributor
                }
                match which {
                    0 => bitmap_replace(&mut self.igroupr, n, val),
                    1 | 2 => bitmap_set(&mut self.isenabler, n, val, which == 1),
                    3 | 4 => bitmap_set(&mut self.ispendr, n, val, which == 3),
                    5 | 6 => bitmap_set(&mut self.isactiver, n, val, which == 5),
                    7 => bitmap_replace(&mut self.igrpmodr, n, val),
                    _ => {}
                }
            }
        }
    }

    // ── Redistributor MMIO ─────────────────────────────────────────────
    // Two 64 KB frames: RD base (offset < 0x10000) and SGI/PPI base (+0x10000).
    pub fn gicr_read(&self, off: u64) -> u32 {
        if off < 0x10000 {
            match off {
                0x0000 => self.r_ctlr,
                0x0004 => self.r_pidr0, // IIDR
                0x0008 => (self.r_typer & 0xffff_ffff) as u32,
                0x0014 => self.r_waker,
                0xffe0 => 0x90, // PIDR0
                0xffe4 => 0xb4, // PIDR1
                0xffe8 => 0x3b, // PIDR2 (arch rev 3 = GICv3)
                0xffec => 0x00, // PIDR3
                0xffd0 => 0x04, // PIDR4
                _ => 0,
            }
        } else {
            let o = off - 0x10000;
            match o {
                0x0080 => self.igroupr[0] as u32,
                0x0088 => (self.igroupr[0] >> 32) as u32,
                0x0100 => self.isenabler[0] as u32,
                0x0180 => self.isenabler[0] as u32,
                0x0200 => self.ispendr[0] as u32,
                0x0280 => self.ispendr[0] as u32,
                0x0300 => self.isactiver[0] as u32,
                0x0380 => self.isactiver[0] as u32,
                0x0c00 => icfgr_read(&self.icfgr, 0),
                0x0c04 => icfgr_read(&self.icfgr, 1),
                0x0d00 => self.igrpmodr[0] as u32,
                _ => {
                    // priority registers GICR_IPRIORITYR0..7 at 0x0400+4n
                    if (0x0400..=0x041c).contains(&o) {
                        let n = ((o - 0x0400) / 4) as usize;
                        let mut v = 0u32;
                        for i in 0..4 {
                            v |= (self.ipriority[n * 4 + i] as u32) << (i * 8);
                        }
                        v
                    } else {
                        0
                    }
                }
            }
        }
    }

    pub fn gicr_write(&mut self, off: u64, val: u32) {
        if off < 0x10000 {
            match off {
                0x0000 => self.r_ctlr = val,
                0x0014 => {
                    // GICR_WAKER: clear ProcessorSleep (bit 1)
                    self.r_waker = val & !0x2;
                }
                _ => {}
            }
        } else {
            let o = off - 0x10000;
            match o {
                0x0080 => {
                    // GICR_IGROUPR0: only INTIDs 0-31 (low word).
                    self.igroupr[0] = (self.igroupr[0] & 0xffff_ffff_0000_0000) | val as u64;
                }
                0x0088 => self.igroupr[0] = (self.igroupr[0] & 0xffff_ffff) | ((val as u64) << 32),
                0x0100 => self.isenabler[0] |= val as u64,
                0x0180 => self.isenabler[0] &= !(val as u64),
                0x0200 => self.ispendr[0] |= val as u64,
                0x0280 => self.ispendr[0] &= !(val as u64),
                0x0300 => self.isactiver[0] |= val as u64,
                0x0380 => self.isactiver[0] &= !(val as u64),
                0x0c00 => icfgr_write(&mut self.icfgr, 0, val),
                0x0c04 => icfgr_write(&mut self.icfgr, 1, val),
                0x0d00 => {
                    self.igrpmodr[0] = (self.igrpmodr[0] & 0xffff_ffff_0000_0000) | val as u64;
                }
                _ => {
                    if (0x0400..=0x041c).contains(&o) {
                        let n = ((o - 0x0400) / 4) as usize;
                        for i in 0..4 {
                            self.ipriority[n * 4 + i] = ((val >> (i * 8)) & 0xff) as u8;
                        }
                    }
                }
            }
        }
    }
}
