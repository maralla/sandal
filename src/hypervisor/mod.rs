//! Hypervisor backend abstraction.
//!
//! Two backends implement the same narrow surface used by the VMM core
//! (`crate::vm`):
//!
//! - **macOS Apple Silicon** — Apple Hypervisor.framework (`hvf/`). The GIC
//!   is emulated in software by the VMM (see `docs/vmm-spec.md`).
//! - **Linux aarch64** — KVM (`kvm/`) with the in-kernel GICv3 (VGIC) and
//!   in-kernel virtual timer, which removes the need for the software GIC.

#[cfg(target_os = "macos")]
mod hvf;
#[cfg(target_os = "linux")]
pub mod kvm;

// ─────────────────────────────────────────────────────────────────────────────
// Shared ARM64 register identifiers
// ─────────────────────────────────────────────────────────────────────────────

// Guest memory permission flags (HVF `hv_vm_map` semantics). The KVM backend
// maps guest memory read/write/execute unconditionally and ignores these.
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

/// ARM64 CPU registers. Values match HVF's `hv_reg_t`; the KVM backend maps
/// the general-purpose registers onto `KVM_REG_ARM_CORE` ids (X0–X30 in
/// declaration order, Pc/pstate via the `user_pt_regs` layout).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // the full register file is part of the FFI surface
pub enum Reg {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    Fp = 29,   // Frame pointer (X29)
    Lr = 30,   // Link register (X30)
    Pc = 31,   // Program counter
    Fpcr = 32, // Floating-point control register
    Fpsr = 33, // Floating-point status register
    Cpsr = 34, // Current Program Status Register
}

impl Reg {
    /// Convert a general-purpose register index (0-30) to the corresponding
    /// `Reg`. Returns `None` for index 31 (XZR) or out-of-range values.
    #[cfg_attr(target_os = "linux", allow(dead_code))] // used by the HVF data-abort path
    pub fn from_gpr(index: u8) -> Option<Self> {
        if index <= 30 {
            // Safety: Reg is #[repr(u32)] with values 0-30 mapping to X0-Lr.
            Some(unsafe { std::mem::transmute::<u32, Reg>(index as u32) })
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend exports
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub use hvf::{Gic, HvSysReg, Vcpu, Vm};

#[cfg(target_os = "linux")]
pub use kvm::{KvmExit, Vcpu, Vm};
