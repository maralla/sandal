//! macOS host specifics: the Hypervisor.framework run loop and the arm64
//! hypervisor glue — the vtimer mask flow, the software-GIC IRQ line, the
//! ICC/timer sysreg traps, and WFI parking. See `docs/vmm-spec.md` for the
//! complete HVF contract.

use super::{
    Args, Vmm, MAX_FS_DEVICES, RAM_BASE, SPI_BLK, SPI_CONSOLE, SPI_DATA_BLK, SPI_FS_START, SPI_NET,
    SPI_RNG,
};
use crate::hypervisor::{HvSysReg, Reg, Vcpu};
use crate::irqs::IRQ_VTIMER;
use anyhow::Result;

pub(super) const CNTFRQ: u64 = 24_000_000; // Apple Silicon host timer frequency (Hz)

// HVF exit reasons (local SDK hv_vcpu_types.h)
const EXIT_CANCELED: u32 = 0;
const EXIT_EXCEPTION: u32 = 1;
const EXIT_VTIMER_ACTIVATED: u32 = 2;

// Exception classes (EC field, bits 31..26 of the syndrome)
const EC_WFX_TRAP: u32 = 0x01;
const EC_AA64_HVC: u32 = 0x16;
const EC_AA64_SMC: u32 = 0x17;
const EC_SYSTEMREGISTERTRAP: u32 = 0x18;
const EC_DATA_ABORT: u32 = 0x24;
const EC_DATA_ABORT_LOWER: u32 = 0x25;
const EC_BRK: u32 = 0x3c;

extern "C" {
    fn mach_absolute_time() -> u64;
}

/// Hypervisor setup at VM creation: trap BRK/debug exceptions to EL2 and
/// arm the vtimer (offset once, mask clear). Returns the vtimer offset
/// (CNTVOFF) for the run loop's WFI deadline math.
pub(super) fn hvf_setup(vcpu: &Vcpu) -> Result<u64> {
    // Trap BRK/debug exceptions to EL2 so the guest init's `BRK #imm`
    // protocol exits reach the VMM instead of being delivered to the
    // guest as SIGTRAP (which kills init).
    vcpu.set_trap_debug_exceptions(true)?;
    // CNTVOFF (`hv_vcpu_set_vtimer_offset`) is set once and never touched
    // again (spec §2.1): the guest's CNTVCT (= CNTPCT − CNTVOFF) starts
    // near 0 and advances at the host rate. Without it HVF reports a
    // frozen/0 counter and guest `__delay` loops spin.
    let vt_off = unsafe { mach_absolute_time() };
    vcpu.set_vtimer_offset(vt_off)?;
    vcpu.set_vtimer_mask(false)?;
    Ok(vt_off)
}

impl Vmm {
    #[cfg(target_os = "macos")]
    fn device_irq_intids(&self) -> ([u32; MAX_FS_DEVICES + 5], usize) {
        let mut irqs = [0u32; MAX_FS_DEVICES + 5];
        let mut n = 0;
        let mut push = |intid: u32| {
            irqs[n] = intid;
            n += 1;
        };
        if self.console.lock().unwrap().interrupt_status != 0 {
            push(32 + SPI_CONSOLE);
        }
        if self.blk.as_ref().is_some_and(|d| d.interrupt_status != 0) {
            push(32 + SPI_BLK);
        }
        if self
            .data_blk
            .as_ref()
            .is_some_and(|d| d.interrupt_status != 0)
        {
            push(32 + SPI_DATA_BLK);
        }
        if self.rng.as_ref().is_some_and(|d| d.interrupt_status != 0) {
            push(32 + SPI_RNG);
        }
        if self
            .net
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|d| d.interrupt_status != 0)
        {
            push(32 + SPI_NET);
        }
        for (i, dev) in self.virtiofs.iter().enumerate() {
            if dev.interrupt_status != 0 {
                push(32 + SPI_FS_START + i as u32);
            }
        }
        (irqs, n)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn run_loop_hvf(&mut self, _args: &Args) -> Result<i32> {
        loop {
            // Poll the user-space network backend and deliver any incoming
            // packets to the guest's RX queue.
            if let Some(net) = self.net.lock().unwrap().as_mut() {
                net.poll_backend();
                net.process_rx(self.memory.as_shared_slice(), RAM_BASE);
            }

            // Re-pend level-triggered device IRQs before each run.
            let (active, n) = self.device_irq_intids();
            self.gic.update_level_irqs(&active[..n]);
            let deliverable = self.gic.deliverable();
            // The IRQ line into the vCPU must mirror the software GIC's pending
            // state: assert when an enabled interrupt passes PMR, de-assert when
            // nothing is deliverable.  Leaving it asserted after the guest has
            // taken/completed the interrupt livelocks Linux in a spurious-IRQ
            // storm (IAR reads 1023 forever while the line stays high).
            //
            // `hv_vcpu_set_pending_interrupt` is one-shot: the pending state is
            // cleared when `hv_vcpu_run` returns, so a deliverable interrupt is
            // re-asserted before every run.  Idle iterations (nothing
            // deliverable, line already low) skip the hypervisor call.
            if deliverable || self.irq_line_asserted {
                let _ = self.vcpu.set_pending_interrupt(0, deliverable);
                self.irq_line_asserted = deliverable;
            }

            match self.vcpu.run()? {
                EXIT_CANCELED => continue,
                EXIT_VTIMER_ACTIVATED => self.on_vtimer()?,
                EXIT_EXCEPTION => {
                    let syndrome = self.vcpu.read_exception_syndrome()?;
                    let ec = ((syndrome >> 26) & 0x3f) as u32;
                    match ec {
                        EC_DATA_ABORT | EC_DATA_ABORT_LOWER => {
                            self.handle_data_abort(syndrome)?;
                        }
                        EC_SYSTEMREGISTERTRAP => self.handle_sysreg(syndrome)?,
                        EC_WFX_TRAP => self.handle_wfi(syndrome)?,
                        EC_AA64_HVC => self.handle_hvc()?,
                        EC_AA64_SMC => {
                            // PSCI via SMC (not used; dtb method=hvc). Treat as HVC.
                            self.vcpu
                                .write_register(Reg::Pc, self.vcpu.read_register(Reg::Pc)? + 4)?;
                            self.handle_hvc()?;
                        }
                        EC_BRK => self.handle_brk(syndrome)?,
                        _ => {
                            log::warn!(
                                "unhandled exception class 0x{ec:x} at PC=0x{:x}",
                                self.vcpu.read_register(Reg::Pc)?
                            );
                        }
                    }
                }
                r => {
                    log::warn!("unexpected exit reason {r}");
                }
            }

            // Drain guest console TX → host stdout (intercepting protocol markers).
            let tx = self
                .console
                .lock()
                .unwrap()
                .process_tx(self.memory.as_shared_slice(), RAM_BASE);
            if !tx.is_empty() {
                self.process_console_tx(&tx);
            }

            // Host stdin → guest console RX.
            self.poll_stdin()?;

            // If the guest asked the VMM to shut down, exit the loop.
            if self.guest_shutdown {
                break;
            }
        }
        Ok(self.guest_exit_code.unwrap_or(0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HVF exit handlers
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    #[cfg(target_os = "macos")]
    fn on_vtimer(&mut self) -> Result<()> {
        // HVF auto-masks the vtimer; pend PPI 27 so the guest's clockevent ISR
        // runs. The mask is cleared when the guest EOIs INTID 27.
        self.gic.set_pending(IRQ_VTIMER);
        self.vtimer_masked = true;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn handle_wfi(&mut self, _syndrome: u64) -> Result<()> {
        // Advance past the WFI/WFE.
        let pc = self.vcpu.read_register(Reg::Pc)?;
        self.vcpu.write_register(Reg::Pc, pc + 4)?;

        // If an interrupt is already pending, re-enter immediately.
        if self.gic.deliverable() {
            return Ok(());
        }

        // Otherwise wait until the guest's vtimer expires or host input
        // arrives. Compute the vtimer deadline from CNTV_CVAL/CNTV_CTL.
        let mut wait_ms: i32 = 1000; // safety cap (spurious WFI)
        let ctl = self
            .vcpu
            .read_sys_register(HvSysReg::CntvCtlEl0)
            .unwrap_or(0);
        let enabled = ctl & 1 != 0;
        let imask = ctl & 2 != 0;
        if enabled && !imask {
            if let Ok(cval) = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0) {
                // CNTVCT = CNTPCT - CNTVOFF, where CNTVOFF is the vtimer offset
                // set once at VM creation.  Compare against the *virtual*
                // counter, not the raw host counter (the two differ by a huge
                // constant, which would make every WFI look already-expired and
                // livelock the guest in a spurious-timer IRQ storm).
                let now_virt = unsafe { mach_absolute_time() }.wrapping_sub(self.vt_off);
                if cval <= now_virt {
                    // Already expired: pend the timer now.
                    self.gic.set_pending(IRQ_VTIMER);
                    self.vtimer_masked = true;
                    return Ok(());
                }
                let delta_ticks = cval - now_virt;
                let delta_ms = (delta_ticks * 1000 / CNTFRQ) as i32;
                wait_ms = delta_ms.clamp(1, 1000);
            }
        }

        // Wait for host stdin and/or the timer deadline.
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            self.drain_stdin()?;
        } else if n == 0 {
            // Timeout: the vtimer expired while the vCPU was idle-parked.
            self.gic.set_pending(IRQ_VTIMER);
            self.vtimer_masked = true;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn handle_hvc(&mut self) -> Result<()> {
        // PSCI via HVC. HVF advances the PC past the HVC itself, so we only
        // set x0 to the PSCI return value.
        let fid = self.vcpu.read_register(Reg::X0)?;
        let ret: u64 = match fid {
            0x8400_0000 => 0x0000_0001_0000_0002, // PSCI_VERSION → 1.1
            0x8400_0002 => 0,                     // CPU_OFF: success
            0xc400_0003 | 0x8400_0003 => 0,       // CPU_ON: single CPU, treat as success
            0x8400_0008 | 0x8400_0009 => {
                // SYSTEM_OFF / SYSTEM_RESET: stop the VM.
                self.guest_shutdown = true;
                0
            }
            0x8400_0005 => 0, // MIGRATE_INFO_TYPE → TOS migration not required
            0x8400_0004 | 0xc400_0004 => 0, // AFFINITY_INFO: on
            0x8400_0006 | 0xc400_0006 => 0xffff_ffff_ffff_fffe, // MIGRATE: not supported
            _ => 0xffff_ffff_ffff_ffff, // unknown → -1 (SMCCC)
        };
        self.vcpu.write_register(Reg::X0, ret)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn handle_data_abort(&mut self, syndrome: u64) -> Result<()> {
        let isv = (syndrome >> 24) & 1 != 0;
        if !isv {
            // Non-synchronized abort (e.g. SIMD); just skip.
            let pc = self.vcpu.read_register(Reg::Pc)?;
            self.vcpu.write_register(Reg::Pc, pc + 4)?;
            return Ok(());
        }
        let iswrite = (syndrome >> 6) & 1 != 0;
        let sas = (syndrome >> 22) & 3;
        let len = 1usize << sas;
        let srt = (syndrome >> 16) & 0x1f;
        let sse = (syndrome >> 21) & 1 != 0;
        let addr = self.vcpu.read_fault_address()?;

        if iswrite {
            // Register 31 on a store is WZR/XZR: the value is zero, not X0.
            let val = match Reg::from_gpr(srt as u8) {
                Some(r) => self.vcpu.read_register(r)?,
                None => 0,
            };
            self.mmio_write(addr, len, val);
        } else {
            let val = self.mmio_read(addr, len, sas as u8);
            let val = if sse && len < 8 {
                // sign-extend from the access width
                let shift = 64 - len * 8;
                ((val << shift) as i64 >> shift) as u64
            } else {
                val
            };
            if let Some(r) = Reg::from_gpr(srt as u8) {
                self.vcpu.write_register(r, val)?;
            }
        }
        let pc = self.vcpu.read_register(Reg::Pc)?;
        self.vcpu.write_register(Reg::Pc, pc + 4)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn handle_sysreg(&mut self, syndrome: u64) -> Result<()> {
        let isread = syndrome & 1 != 0;
        let rt = ((syndrome >> 5) & 0x1f) as u8;
        let crm = (syndrome >> 1) & 0xf;
        let crn = (syndrome >> 10) & 0xf;
        let op1 = (syndrome >> 14) & 0x7;
        let op2 = (syndrome >> 17) & 0x7;
        let op0 = (syndrome >> 20) & 0x3;

        // Advance past the MRS/MSR instruction (4 bytes) for every trap.
        let pc = self.vcpu.read_register(Reg::Pc)?;
        self.vcpu.write_register(Reg::Pc, pc + 4)?;

        // ICC (GIC CPU interface) system registers.
        if op0 == 3 && op1 == 0 {
            match (crn, crm, op2) {
                (4, 6, 0) => {
                    // ICC_PMR_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_pmr as u64)?;
                    } else {
                        self.gic.icc_pmr = (self.read_gpr(rt)? & 0xff) as u8;
                    }
                    return Ok(());
                }
                (12, 12, 0) => {
                    // ICC_IAR1_EL1
                    let intid = self.gic.ack() as u64;
                    self.write_gpr(rt, intid)?;
                    return Ok(());
                }
                (12, 12, 1) => {
                    // ICC_EOIR1_EL1
                    let intid = (self.read_gpr(rt)? & 0x3ff) as u32;
                    self.gic.eoi(intid);
                    if intid == IRQ_VTIMER {
                        self.unmask_vtimer()?;
                    }
                    return Ok(());
                }
                (12, 11, 1) => {
                    // ICC_DIR_EL1 (deactivate)
                    let intid = (self.read_gpr(rt)? & 0x3ff) as u32;
                    self.gic.eoi(intid);
                    if intid == IRQ_VTIMER {
                        self.unmask_vtimer()?;
                    }
                    return Ok(());
                }
                (12, 12, 3) => {
                    // ICC_BPR1_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_bpr1 as u64)?;
                    } else {
                        self.gic.icc_bpr1 = (self.read_gpr(rt)? & 0x7) as u8;
                    }
                    return Ok(());
                }
                (12, 12, 4) => {
                    // ICC_CTLR_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_ctlr as u64)?;
                    }
                    return Ok(());
                }
                (12, 12, 5) => {
                    // ICC_SRE_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_sre as u64)?;
                    } else {
                        self.gic.icc_sre = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 12, 6) => {
                    // ICC_IGRPEN0_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_igrpen0 as u64)?;
                    } else {
                        self.gic.icc_igrpen0 = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 12, 7) => {
                    // ICC_IGRPEN1_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_igrpen1 as u64)?;
                    } else {
                        self.gic.icc_igrpen1 = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 9, 0) => {
                    // ICC_AP1R0_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_ap1r0 as u64)?;
                    } else {
                        self.gic.icc_ap1r0 = (self.read_gpr(rt)? & 0xffff_ffff) as u32;
                    }
                    return Ok(());
                }
                (12, 8, 0) => {
                    // ICC_IAR0_EL1 — no group-0 interrupts; spurious.
                    if isread {
                        self.write_gpr(rt, 1023)?;
                    }
                    return Ok(());
                }
                _ => {}
            }
        }

        // Counter-timer registers. CRn=14, EL0. Encodings (per ARM ARM D11 and
        // Linux arch/arm64/include/asm/sysreg.h):
        //   CNTFRQ_EL0  (0,0)   CNTPCT_EL0   (0,1)   CNTVCT_EL0   (0,2)
        //   CNTPCTSS_EL0(0,5)   CNTVCTSS_EL0 (0,6)
        //   CNTP_TVAL   (2,0)   CNTP_CTL     (2,1)   CNTP_CVAL    (2,2)
        //   CNTV_TVAL   (3,0)   CNTV_CTL     (3,1)   CNTV_CVAL    (3,2)
        // The counter reads are synthesized from mach_absolute_time (the host
        // CNTPCT) minus CNTVOFF for the virtual counter; HVF rejects EL2 reads
        // of CNTVCT/CNTPCT, so a guest read that traps here would otherwise see
        // a frozen counter and spin in __delay.
        if op0 == 3 && op1 == 3 && crn == 14 {
            let now = unsafe { mach_absolute_time() };
            let now_virt = now.wrapping_sub(self.vt_off);
            match (crm, op2) {
                (0, 0) => {
                    // CNTFRQ_EL0
                    if isread {
                        self.write_gpr(rt, CNTFRQ)?;
                    }
                    return Ok(());
                }
                (0, 1) | (0, 5) => {
                    // CNTPCT_EL0 / CNTPCTSS_EL0: raw host counter.
                    if isread {
                        self.write_gpr(rt, now)?;
                    }
                    return Ok(());
                }
                (0, 2) | (0, 6) => {
                    // CNTVCT_EL0 / CNTVCTSS_EL0: CNTPCT minus CNTVOFF (the
                    // vtimer offset set once at VM creation).
                    if isread {
                        self.write_gpr(rt, now_virt)?;
                    }
                    return Ok(());
                }
                (2, 1) => {
                    // CNTP_CTL_EL0: this VM only uses the virtual timer, so
                    // tolerate HVF rejecting physical-timer accesses instead of
                    // failing the whole run loop.
                    if isread {
                        let v = self
                            .vcpu
                            .read_sys_register(HvSysReg::CntpCtlEl0)
                            .unwrap_or(0);
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        let _ = self.vcpu.write_sys_register(HvSysReg::CntpCtlEl0, v);
                    }
                    return Ok(());
                }
                (3, 0) => {
                    // CNTV_TVAL_EL0 — the arm64 clockevent writes this 32-bit
                    // relative value to arm the next tick.  Translate it into
                    // an absolute CVAL for the HVF virtual timer, otherwise the
                    // comparator never moves and the timer IRQ storms forever.
                    if isread {
                        let cval = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0)?;
                        let tval = cval.wrapping_sub(now_virt) as u32;
                        self.write_gpr(rt, tval as u64)?;
                    } else {
                        let tval = self.read_gpr(rt)? as u32 as i32 as i64;
                        let cval = (now_virt as i64).wrapping_add(tval) as u64;
                        self.vcpu.write_sys_register(HvSysReg::CntvCvalEl0, cval)?;
                    }
                    return Ok(());
                }
                (3, 1) => {
                    // CNTV_CTL_EL0: forward to HVF's virtual timer
                    if isread {
                        let v = self.vcpu.read_sys_register(HvSysReg::CntvCtlEl0)?;
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        self.vcpu.write_sys_register(HvSysReg::CntvCtlEl0, v)?;
                    }
                    return Ok(());
                }
                (3, 2) => {
                    // CNTV_CVAL_EL0: forward to HVF's virtual timer
                    if isread {
                        let v = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0)?;
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        self.vcpu.write_sys_register(HvSysReg::CntvCvalEl0, v)?;
                    }
                    return Ok(());
                }
                _ => {
                    // Other timer regs (e.g. CNTP_TVAL/CNTP_CVAL): synthesize a
                    // consistent value, ignore writes.
                    if isread {
                        self.write_gpr(rt, 0)?;
                    }
                    return Ok(());
                }
            }
        }

        // Feature ID registers: return curated values.  These reads normally do
        // not trap (native EL1 reads); the values below only matter if HVF does
        // route them to the VMM.  The guest kernel is built for 48-bit VA, and
        // Apple Silicon HVF reports 48-bit VA, so VARange is reported as 0.
        if op0 == 3 && op1 == 0 && crn == 0 {
            let v = match (crm, op2) {
                (0, 0) => 0x411f_d070u64, // MIDR_EL1 (Cortex-A57)
                (4, 0) => 0x110_011u64,   // ID_AA64PFR0: EL0/EL1/FP/ASIMD
                (7, 0) => 0x5u64,         // ID_AA64MMFR0: 48-bit PARange
                (2, 1) => 0u64,           // ID_AA64MMFR2: VARange=0 (48-bit VA)
                _ => 0,
            };
            if isread {
                self.write_gpr(rt, v)?;
            }
            return Ok(());
        }

        // Unknown sysreg: permissive (read 0 / ignore write).
        if isread {
            self.write_gpr(rt, 0)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn unmask_vtimer(&mut self) -> Result<()> {
        if self.vtimer_masked {
            self.vcpu.set_vtimer_mask(false)?;
            self.vtimer_masked = false;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn write_gpr(&mut self, rt: u8, val: u64) -> Result<()> {
        if let Some(r) = Reg::from_gpr(rt) {
            self.vcpu.write_register(r, val)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn read_gpr(&mut self, rt: u8) -> Result<u64> {
        match Reg::from_gpr(rt) {
            Some(r) => self.vcpu.read_register(r),
            None => Ok(0),
        }
    }

    #[cfg(target_os = "macos")]
    fn poll_stdin(&mut self) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 0) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            self.drain_stdin()?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn drain_stdin(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if n == 0 {
                return Ok(());
            }
            self.console.lock().unwrap().push_rx_and_drain(
                self.memory.as_shared_slice(),
                RAM_BASE,
                &buf[..n as usize],
            );
        }
    }
}
