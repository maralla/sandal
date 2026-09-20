//! macOS Hypervisor.framework (HVF) backend — Apple Silicon only.
//!
//! Contract (source of truth: `docs/vmm-spec.md`):
//!
//! - The GIC is emulated in software by the VMM ([`gic`]) — `hv_gic_create`
//!   is deliberately not used, so the VMM can observe the guest's ICC EOI and
//!   unmask the virtual timer (spec §1.1/§1.3).
//! - The guest arch timer is delivered through
//!   `HV_EXIT_REASON_VTIMER_ACTIVATED`; the VMM pends PPI 27 in the software
//!   GIC and unmasks the vtimer when the guest EOIs INTID 27 (spec §1.1).
//! - Device IRQs are level-triggered SPIs in the software GIC, injected via a
//!   bare IRQ-line assert (`hv_vcpu_set_pending_interrupt`), re-asserted
//!   before every run (the pending state is one-shot per `hv_vcpu_run`).
//! - Guest `BRK #imm` (init protocol) reaches the VMM via debug-exception
//!   traps (`hv_vcpu_set_trap_debug_exceptions`).

pub mod ffi;
pub mod gic;
pub mod vcpu;
pub mod vm;

pub use ffi::HvSysReg;
pub use gic::Gic;
pub use vcpu::Vcpu;
pub use vm::Vm;
