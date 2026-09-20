//! Thin Rust bindings over the `src/hypervisor/hvf/ffi.c` wrappers for Apple's
//! Hypervisor.framework.
//!
//! Only the API surface actually used by the software-GIC VMM (see
//! `docs/vmm-spec.md`) is bound here.  In particular there are no
//! `hv_gic_create`/SPI/ICC bindings: HVF's native GIC is deliberately not used.

use crate::hypervisor::Reg;
use std::ffi::c_void;

pub type HvReturn = i32;
pub type HvVcpu = u32;

pub const HV_SUCCESS: HvReturn = 0;

/// The shared register enum, aliased under its HVF name.
pub type HvReg = Reg;

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
    #[allow(dead_code)] // the HVF kick primitive; reserved for the net wake path
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
