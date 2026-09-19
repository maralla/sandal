//! Thin Rust bindings over the `src/hypervisor/ffi.c` wrappers for Apple's
//! Hypervisor.framework.
//!
//! Only the API surface actually used by the software-GIC VMM (see
//! `docs/vmm-spec.md`) is bound here.  In particular there are no
//! `hv_gic_create`/SPI/ICC bindings: HVF's native GIC is deliberately not used.

use std::ffi::c_void;

pub type HvReturn = i32;
pub type HvVcpu = u32;

pub const HV_SUCCESS: HvReturn = 0;

// Memory permissions
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

/// ARM64 CPU registers (`hv_reg_t`).
#[repr(u32)]
#[cfg(target_arch = "aarch64")]
#[allow(dead_code)] // the full register file is part of the FFI surface
pub enum HvReg {
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

impl HvReg {
    /// Convert a general-purpose register index (0-30) to the corresponding
    /// `HvReg`. Returns `None` for index 31 (XZR) or out-of-range values.
    pub fn from_gpr(index: u8) -> Option<Self> {
        if index <= 30 {
            // Safety: HvReg is #[repr(u32)] with values 0-30 mapping to X0-Lr.
            Some(unsafe { std::mem::transmute::<u32, HvReg>(index as u32) })
        } else {
            None
        }
    }
}

#[repr(C)]
pub struct HvVcpuExitException {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
pub struct HvVcpuExit {
    pub reason: u32,
    pub exception: HvVcpuExitException,
}

#[link(name = "hvffi", kind = "static")]
extern "C" {
    pub fn hv_vm_create_wrapper(flags: u64) -> HvReturn;
    pub fn hv_vm_destroy_wrapper() -> HvReturn;
    pub fn hv_vm_map_wrapper(addr: *mut c_void, gpa: u64, size: usize, flags: u64) -> HvReturn;
    pub fn hv_vcpu_create_wrapper(vcpu: *mut HvVcpu, exit_info: *mut *mut HvVcpuExit) -> HvReturn;
    pub fn hv_vcpu_destroy_wrapper(vcpu: HvVcpu) -> HvReturn;
    pub fn hv_vcpu_run_wrapper(vcpu: HvVcpu) -> HvReturn;
    pub fn hv_vcpu_read_register_wrapper(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
    pub fn hv_vcpu_write_register_wrapper(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_read_sys_reg_wrapper(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_write_sys_reg_wrapper(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_pending_interrupt_wrapper(
        vcpu: HvVcpu,
        int_type: u32,
        pending: bool,
    ) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_vtimer_mask_wrapper(vcpu: HvVcpu, vtimer_is_masked: bool) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_vtimer_offset_wrapper(vcpu: HvVcpu, vtimer_offset: u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_trap_debug_exceptions_wrapper(vcpu: HvVcpu, value: bool) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpus_exit_wrapper(vcpus: *mut u64, vcpu_count: u32) -> HvReturn;
}

/// ARM64 system registers used by the VMM (`hv_sys_reg_t`).
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[cfg(target_arch = "aarch64")]
pub enum HvSysReg {
    /// Counter-timer Physical Timer Control.
    CntpCtlEl0 = 0xdf11,
    /// Counter-timer Virtual Timer Control.
    CntvCtlEl0 = 0xdf19,
    /// Counter-timer Virtual Timer CompareValue.
    CntvCvalEl0 = 0xdf1a,
}
