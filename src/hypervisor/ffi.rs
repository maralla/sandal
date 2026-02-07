#![allow(dead_code)]

use std::ffi::c_void;

pub type HvReturn = i32;
pub type HvVcpu = u32;

pub const HV_SUCCESS: HvReturn = 0;
pub const HV_ERROR: HvReturn = -1;

// Memory permissions
pub const HV_MEMORY_READ: u64 = 1 << 0;
pub const HV_MEMORY_WRITE: u64 = 1 << 1;
pub const HV_MEMORY_EXEC: u64 = 1 << 2;

// CPU registers - ARM64 architecture
#[repr(u32)]
#[allow(dead_code)]
#[cfg(target_arch = "aarch64")]
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

// CPU registers - x86_64 architecture
#[repr(u32)]
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub enum HvReg {
    Rip = 0,
    Rflags = 1,
    Rax = 2,
    Rcx = 3,
    Rdx = 4,
    Rbx = 5,
    Rsi = 6,
    Rdi = 7,
    Rsp = 8,
    Rbp = 9,
    R8 = 10,
    R9 = 11,
    R10 = 12,
    R11 = 13,
    R12 = 14,
    R13 = 15,
    R14 = 16,
    R15 = 17,
    Cs = 18,
    Ss = 19,
    Ds = 20,
    Es = 21,
    Fs = 22,
    Gs = 23,
    Cr0 = 24,
    Cr2 = 25,
    Cr3 = 26,
    Cr4 = 27,
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
    pub fn hv_vm_unmap_wrapper(gpa: u64, size: usize) -> HvReturn;
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
    pub fn hv_vcpu_get_vtimer_mask_wrapper(vcpu: HvVcpu, vtimer_is_masked: *mut bool) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_vtimer_offset_wrapper(vcpu: HvVcpu, vtimer_offset: u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_get_vtimer_offset_wrapper(vcpu: HvVcpu, vtimer_offset: *mut u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpus_exit_wrapper(vcpus: *mut HvVcpu, vcpu_count: u32) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_vcpu_set_trap_debug_exceptions_wrapper(vcpu: HvVcpu, value: bool) -> HvReturn;

    // GIC functions
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_config_create_wrapper() -> *mut std::ffi::c_void;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_config_set_distributor_base_wrapper(
        config: *mut std::ffi::c_void,
        addr: u64,
    ) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_config_set_redistributor_base_wrapper(
        config: *mut std::ffi::c_void,
        addr: u64,
    ) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_create_wrapper(config: *mut std::ffi::c_void) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_config_release_wrapper(config: *mut std::ffi::c_void);

    // GIC parameter query functions
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_distributor_size_wrapper(size: *mut usize) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_distributor_base_alignment_wrapper(alignment: *mut usize) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_redistributor_region_size_wrapper(size: *mut usize) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_redistributor_size_wrapper(size: *mut usize) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_redistributor_base_alignment_wrapper(alignment: *mut usize) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_redistributor_base_wrapper(vcpu: HvVcpu, base: *mut u64) -> HvReturn;
    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_get_spi_interrupt_range_wrapper(base: *mut u32, count: *mut u32) -> HvReturn;

    #[cfg(target_arch = "aarch64")]
    pub fn hv_gic_set_spi_wrapper(intid: u32, level: bool) -> HvReturn;
}

// ARM64 system registers
#[repr(u32)]
#[allow(dead_code)]
#[cfg(target_arch = "aarch64")]
pub enum HvSysReg {
    // System info
    MidrEl1 = 0xc000,  // Main ID Register
    MpidrEl1 = 0xc005, // Multiprocessor Affinity Register

    // Memory management
    SctlrEl1 = 0xc080, // System Control Register
    Ttbr0El1 = 0xc100, // Translation Table Base Register 0
    Ttbr1El1 = 0xc101, // Translation Table Base Register 1
    TcrEl1 = 0xc102,   // Translation Control Register
    MairEl1 = 0xc510,  // Memory Attribute Indirection Register

    // Exception handling
    SpsrEl1 = 0xc200, // Saved Program Status Register (EL1)
    ElrEl1 = 0xc201,  // Exception Link Register (EL1)
    SpEl0 = 0xc208,   // Stack Pointer (EL0)
    EsrEl1 = 0xc290,  // Exception Syndrome Register (EL1)
    FarEl1 = 0xc300,  // Fault Address Register (EL1)
    VbarEl1 = 0xc600, // Vector Base Address Register

    // Stack pointers
    SpEl1 = 0xe208, // Stack Pointer (EL1)

    // Debug
    MdscrEl1 = 0x8012, // Monitor Debug System Control Register
}
