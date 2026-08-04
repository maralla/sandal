//! SP804 Dual-Timer MMIO emulation.
//!
//! The Linux kernel's SP804 driver expects:
//!   Timer 1 (offset 0x00) — clockevent (oneshot/periodic with interrupt on SPI 29)
//!   Timer 2 (offset 0x20) — clocksource (free-running, no interrupt)
//!
//! Register layout (each timer is 0x20 apart):
//!   Offset 0x00 — Timer1Load      (RW)  Load / period
//!   Offset 0x04 — Timer1Value     (RO)  Current counter
//!   Offset 0x08 — Timer1Control   (RW)  Control
//!   Offset 0x0C — Timer1IntClr    (WO)  Interrupt clear
//!   Offset 0x10 — Timer1RIS       (RO)  Raw interrupt status
//!   Offset 0x14 — Timer1MIS       (RO)  Masked interrupt status
//!   Offset 0x18 — Timer1BGLoad    (RW)  Background load
//!   Offset 0x20 — Timer2Load      (RW)
//!   ...
//!
//! Control bits:
//!   bit 0 — OneShot      (1 = one-shot, stops at 0)
//!   bit 1 — TimerSize    (1 = 32-bit)
//!   bit 2:3 — Prescale   (0=÷1, 1=÷16, 2=÷256)
//!   bit 5  — IntEnable
//!   bit 6  — TimerMode   (1 = periodic)
//!   bit 7  — TimerEn

use std::time::Instant;

/// Timer frequency in Hz (1 MHz = 1 tick per µs).
pub const SP804_FREQ_HZ: u64 = 1_000_000;

pub struct Sp804 {
    // ---- Timer 1 (clockevent, oneshot/periodic with interrupt on SPI 29) ----
    load1: u32,
    ctrl1: u32,
    bgl1: u32,
    counter1: Option<u32>,
    armed_at_tick1: u64,
    irq_pending1: bool,
    // ---- Timer 2 (clocksource, free-running) ----
    load2: u32,
    ctrl2: u32,
    bgl2: u32,
    birth: Instant,
    /// Whether the VMM has already asserted SPI 29 for the current Timer 1
    /// expiry.  Guards against re-pending the SPI on every main-loop iteration
    /// while `irq_pending1` stays true (which floods the guest with timer
    /// interrupts and can preempt a critical section holding a spinlock).
    spi_pended1: bool,
}

impl Sp804 {
    pub fn new() -> Self {
        Self {
            load1: 0,
            ctrl1: 0,
            bgl1: 0,
            counter1: None,
            armed_at_tick1: 0,
            irq_pending1: false,
            load2: 0,
            ctrl2: 0,
            bgl2: 0,
            birth: Instant::now(),
            spi_pended1: false,
        }
    }

    fn elapsed_ticks(&self) -> u64 {
        let ns = self.birth.elapsed().as_nanos() as u64;
        ns * SP804_FREQ_HZ / 1_000_000_000
    }

    // ---- Timer 1: clockevent (oneshot/periodic down-counter) ----

    fn timer1_value(&self) -> u32 {
        if self.ctrl1 & 0x80 == 0 {
            return self.counter1.unwrap_or(self.load1);
        }
        let elapsed = self.elapsed_ticks();
        let start = self.effective_start1();
        let load = self.load1 as u64;
        if elapsed >= start + load {
            0
        } else {
            (load - (elapsed - start)) as u32
        }
    }

    /// Force Timer 1 IRQ to pending. Used to unstick a hung vCPU.
    pub fn force_timer1_irq(&mut self) {
        self.irq_pending1 = true;
    }

    /// Whether Timer 1 currently has an asserted (masked) IRQ, without any
    /// side effects.  Used to decide whether to wake a WFI-parked vCPU.
    pub fn timer1_irq_asserted(&self) -> bool {
        self.irq_pending1 && self.ctrl1 & 0x20 != 0
    }

    /// Whether the VMM has already pended SPI 29 for the current expiry.
    pub fn timer1_spi_pended(&self) -> bool {
        self.spi_pended1
    }

    /// Mark SPI 29 as pended for the current Timer 1 expiry.
    pub fn mark_timer1_spi_pended(&mut self) {
        self.spi_pended1 = true;
    }

    /// Check whether Timer 1 has expired. Returns true if SPI 29 should be asserted.
    pub fn check_timer1_irq(&mut self) -> bool {
        if self.irq_pending1 {
            return self.ctrl1 & 0x20 != 0;
        }
        if self.ctrl1 & 0x80 == 0 {
            return false;
        }
        let elapsed = self.elapsed_ticks();
        let start = self.effective_start1();
        let target = start + self.load1 as u64;
        if elapsed >= target {
            self.irq_pending1 = true;
            // Fresh expiry: allow the VMM to (re-)pend SPI 29 once.
            self.spi_pended1 = false;
            self.counter1 = None;
            if self.ctrl1 & 0x40 != 0 {
                // Periodic: re-arm immediately
                self.armed_at_tick1 = elapsed;
            } else {
                // One-shot: disable
                self.ctrl1 &= !0x80;
            }
            return self.ctrl1 & 0x20 != 0;
        }
        false
    }

    fn effective_start1(&self) -> u64 {
        if let Some(c) = self.counter1 {
            self.armed_at_tick1
                .saturating_sub((self.load1 as u64).saturating_sub(c as u64))
        } else {
            self.armed_at_tick1
        }
    }

    // ---- Timer 2: free-running down-counter (clocksource) ----

    fn timer2_value(&self) -> u32 {
        if self.ctrl2 & 0x80 == 0 {
            return self.load2;
        }
        let ticks = self.elapsed_ticks();
        let period = (self.load2 as u64) + 1;
        let rem = if period == 0x1_0000_0000 {
            ticks as u32
        } else {
            (ticks % period) as u32
        };
        self.load2.wrapping_sub(rem)
    }

    // ---- MMIO handlers ----

    pub fn mmio_read(&mut self, offset: u64) -> u32 {
        match offset {
            0x00 => self.load1,
            0x04 => self.timer1_value(),
            0x08 => self.ctrl1,
            0x10 => self.irq_pending1 as u32,
            0x14 => (self.irq_pending1 && self.ctrl1 & 0x20 != 0) as u32,
            0x18 => self.bgl1,

            0x20 => self.load2,
            0x24 => self.timer2_value(),
            0x28 => self.ctrl2,
            0x38 => self.bgl2,

            // PrimeCell identification registers
            0xFE0 => 0x04,
            0xFE4 => 0x18,
            0xFE8 => 0x04,
            0xFEC => 0x00,
            0xFF0 => 0x0D,
            0xFF4 => 0xF0,
            0xFF8 => 0x05,
            0xFFC => 0xB1,
            _ => 0,
        }
    }

    pub fn mmio_write(&mut self, offset: u64, value: u32) {
        let now = self.elapsed_ticks();
        match offset {
            0x00 => {
                self.load1 = value;
                self.counter1 = None;
                if self.ctrl1 & 0x80 != 0 {
                    self.armed_at_tick1 = now;
                    self.irq_pending1 = false;
                }
                self.spi_pended1 = false;
            }
            0x04 => {
                self.counter1 = Some(value);
                if self.ctrl1 & 0x80 != 0 {
                    self.irq_pending1 = false;
                }
                self.spi_pended1 = false;
            }
            0x08 => {
                let was_enabled = self.ctrl1 & 0x80 != 0;
                self.ctrl1 = value;
                if !was_enabled && value & 0x80 != 0 {
                    self.armed_at_tick1 = now;
                    self.irq_pending1 = false;
                    self.counter1 = None;
                }
                self.spi_pended1 = false;
            }
            0x0C => {
                // Timer1IntClr — guest ISR acknowledges the interrupt.
                self.irq_pending1 = false;
                self.spi_pended1 = false;
            }
            0x18 => self.bgl1 = value,

            0x20 => self.load2 = value,
            0x28 => self.ctrl2 = value,
            0x38 => self.bgl2 = value,
            _ => {}
        }
    }
}
