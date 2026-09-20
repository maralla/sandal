//! Raw KVM UAPI bindings (`include/uapi/linux/kvm.h`,
//! `arch/arm64/include/uapi/asm/kvm.h`).
//!
//! Only the surface used by the sandal VMM is bound. All constants are copied
//! from the Linux 6.x UAPI headers, which are stable. The full set is kept
//! (even currently-unused constants) as part of the UAPI surface.

#![allow(dead_code)]

use std::os::fd::RawFd;

// ─────────────────────────────────────────────────────────────────────────────
// ioctl request encoding
// ─────────────────────────────────────────────────────────────────────────────

const KVMIO: u32 = 0xAE;
const NR_IO: u32 = 0;
const NR_IOW: u32 = 1;
const NR_IOWR: u32 = 3;
const SIZE_SHIFT: u32 = 16;

const fn io(nr: u32) -> u32 {
    NR_IO << 30 | KVMIO << 8 | nr
}

const fn iow(nr: u32, size: u32) -> u32 {
    NR_IOW << 30 | size << SIZE_SHIFT | KVMIO << 8 | nr
}

const fn iowr(nr: u32, size: u32) -> u32 {
    NR_IOWR << 30 | size << SIZE_SHIFT | KVMIO << 8 | nr
}

// System ioctls
pub const KVM_GET_API_VERSION: u32 = io(0x00);
pub const KVM_CHECK_EXTENSION: u32 = io(0x03);
pub const KVM_GET_VCPU_MMAP_SIZE: u32 = io(0x04);

// VM ioctls
pub const KVM_CREATE_VM: u32 = io(0x01);
pub const KVM_CREATE_VCPU: u32 = io(0x41);
pub const KVM_SET_USER_MEMORY_REGION: u32 =
    iow(0x46, std::mem::size_of::<KvmUserspaceMemoryRegion>() as u32);
pub const KVM_IRQ_LINE: u32 = iow(0x61, std::mem::size_of::<KvmIrqLevel>() as u32);
pub const KVM_SET_GUEST_DEBUG: u32 = iow(0x9b, std::mem::size_of::<KvmGuestDebug>() as u32);
pub const KVM_CREATE_DEVICE: u32 = iowr(0xe0, std::mem::size_of::<KvmCreateDevice>() as u32);
pub const KVM_SET_DEVICE_ATTR: u32 = iow(0xe1, std::mem::size_of::<KvmDeviceAttr>() as u32);

// VM ioctls (x86)
pub const KVM_CREATE_IRQCHIP: u32 = io(0x60);
pub const KVM_CREATE_PIT2: u32 = iow(0x77, std::mem::size_of::<KvmPitConfig>() as u32);

/// `struct kvm_pit_config` (KVM_CREATE_PIT2).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmPitConfig {
    pub flags: u32,
    pub pad: [u32; 15],
}

/// Dummy speaker port emulation: KVM handles port 0x61 with the real PIT
/// channel-2 OUT state, which the guest kernel's TSC calibration polls.
pub const KVM_PIT_SPEAKER_DUMMY: u32 = 1;

// CPUID configuration. `nent` must be at least the kernel's
// KVM_MAX_CPUID_ENTRIES for KVM_GET_SUPPORTED_CPUID (the real count is
// returned in kvm_cpuid2.nent). The request size field is not validated
// by the kernel; it is the header size, matching the UAPI macro.
pub const KVM_MAX_CPUID_ENTRIES: usize = 256;
pub const KVM_GET_SUPPORTED_CPUID: u32 = (3 << 30) | (8 << 16) | (0xAE << 8) | 0x05;
pub const KVM_SET_CPUID2: u32 = (1 << 30) | (8 << 16) | (0xAE << 8) | 0x90;

/// `struct kvm_cpuid2` (variable-length: header + entries).
#[repr(C)]
pub struct KvmCpuid2 {
    pub nent: u32,
    pub padding: u32,
    pub entries: __IncompleteArrayField<KvmCpuidEntry>,
}

/// `struct kvm_cpuid_entry2`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmCpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// Minimal incomplete-array helper for variable-length ioctl structs.
#[repr(C)]
pub struct __IncompleteArrayField<T> {
    _marker: std::marker::PhantomData<T>,
}

impl<T> __IncompleteArrayField<T> {
    pub const fn new() -> Self {
        __IncompleteArrayField {
            _marker: std::marker::PhantomData,
        }
    }
    #[allow(clippy::ptr_as_ptr)]
    pub fn as_slice(&self, len: usize) -> &[T] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const T, len) }
    }
    pub fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self as *mut _ as *mut T, len) }
    }
}

// vCPU ioctls
pub const KVM_RUN: u32 = io(0x80);
pub const KVM_GET_ONE_REG: u32 = iow(0xab, std::mem::size_of::<KvmOneReg>() as u32);
pub const KVM_SET_ONE_REG: u32 = iow(0xac, std::mem::size_of::<KvmOneReg>() as u32);

// arm64 vcpu init (KVM_ARM_VCPU_INIT is required before the first KVM_RUN).
pub const KVM_ARM_VCPU_INIT: u32 = iow(0xae, std::mem::size_of::<KvmVcpuInit>() as u32);
pub const KVM_ARM_PREFERRED_TARGET: u32 = iowr(0xaf, std::mem::size_of::<KvmVcpuInit>() as u32);

/// `struct kvm_vcpu_init` (KVM_ARM_VCPU_INIT / KVM_ARM_PREFERRED_TARGET).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

// ─────────────────────────────────────────────────────────────────────────────
// API constants
// ─────────────────────────────────────────────────────────────────────────────

pub const KVM_API_VERSION: i32 = 12;

/// Capabilities (KVM_CHECK_EXTENSION ids).
pub const KVM_CAP_IRQCHIP: i32 = 0;
pub const KVM_CAP_SET_GUEST_DEBUG: i32 = 23;
pub const KVM_CAP_DEVICE_CTRL: i32 = 89;
pub const KVM_CAP_ARM_VM_IPA_SIZE: i32 = 165;

/// `struct kvm_userspace_memory_region` (KVM_SET_USER_MEMORY_REGION).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

/// `struct kvm_irq_level` (KVM_IRQ_LINE).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmIrqLevel {
    pub irq: u32,
    pub level: i32,
}

/// ARM IRQ-line encoding for KVM_IRQ_LINE (`arch/arm64/include/uapi/asm/kvm.h`).
pub const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
pub const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;

/// Build the `irq` field for a level-triggered SPI injection. `intid` is the
/// GIC INTID (SPIs start at 32).
#[inline]
pub fn spi_irq_line(intid: u32) -> u32 {
    (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | intid
}

/// `struct kvm_one_reg` (KVM_SET_ONE_REG / KVM_GET_ONE_REG).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmOneReg {
    pub id: u64,
    pub addr: u64,
}

// ARM64 core register ids: KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE
// | offsetof(struct kvm_regs, field) / 4.
pub const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
pub const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
pub const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;

// Offsets within `struct user_pt_regs` (in __u32 units after the /4):
// regs[0..31] = X0..X30, sp = 62, pc = 64, pstate = 66.
pub const fn core_reg_id(idx: u32) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | idx as u64
}

pub const CORE_REG_PC: u32 = 64;
pub const CORE_REG_PSTATE: u32 = 66;

/// `struct kvm_guest_debug` (KVM_SET_GUEST_DEBUG).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmGuestDebug {
    pub control: u32,
    pub pad: u32,
    pub arch: KvmGuestDebugArch,
}

/// `struct kvm_guest_debug_arch`:
/// - arm64: 16 hardware breakpoint/watchpoint register pairs.
/// - x86_64: 8 debug registers (DR0-DR7).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg(target_arch = "aarch64")]
pub struct KvmGuestDebugArch {
    pub dbg_bcr: [u64; 16],
    pub dbg_bvr: [u64; 16],
    pub dbg_wcr: [u64; 16],
    pub dbg_wvr: [u64; 16],
}

#[cfg(target_arch = "aarch64")]
impl Default for KvmGuestDebugArch {
    fn default() -> Self {
        KvmGuestDebugArch {
            dbg_bcr: [0; 16],
            dbg_bvr: [0; 16],
            dbg_wcr: [0; 16],
            dbg_wvr: [0; 16],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
#[cfg(target_arch = "x86_64")]
pub struct KvmGuestDebugArch {
    pub debugreg: [u64; 8],
}

pub const KVM_GUESTDBG_ENABLE: u32 = 0x0000_0001;
pub const KVM_GUESTDBG_SINGLESTEP: u32 = 0x0000_0002;
/// Trap guest `BRK` instructions to the VMM (routes debug exceptions to EL2
/// via MDCR_EL2.TDE; KVM_EXIT_DEBUG reports ESR_EL2 in `debug.arch.hsr`).
pub const KVM_GUESTDBG_USE_SW_BP: u32 = 1 << 16;
pub const KVM_GUESTDBG_USE_HW: u32 = 1 << 17;

/// `struct kvm_create_device` (KVM_CREATE_DEVICE).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmCreateDevice {
    pub type_: u32,
    pub fd: u32,
    pub flags: u32,
}

pub const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;

/// `struct kvm_device_attr` (KVM_SET_DEVICE_ATTR / KVM_HAS_DEVICE_ATTR).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmDeviceAttr {
    pub flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

// VGICv3 device attribute groups (`arch/arm64/include/uapi/asm/kvm.h`).
pub const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
pub const KVM_DEV_ARM_VGIC_GRP_NR_IRQS: u32 = 3;
pub const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
pub const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;

pub const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
pub const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// struct kvm_run
// ─────────────────────────────────────────────────────────────────────────────

// Exit reasons (include/uapi/linux/kvm.h).
pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_EXCEPTION: u32 = 1;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_DEBUG: u32 = 4;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub const KVM_EXIT_SYSTEM_EVENT: u32 = 24;

pub const KVM_SYSTEM_EVENT_SHUTDOWN: u32 = 1;
pub const KVM_SYSTEM_EVENT_RESET: u32 = 2;

/// `struct kvm_segment` (KVM_SET_SREGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub typ: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// `struct kvm_sregs` (KVM_GET_SREGS / KVM_SET_SREGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

/// `struct kvm_dtable`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// `struct kvm_regs` (x86_64, KVM_GET_REGS / KVM_SET_REGS).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub const KVM_SET_REGS: u32 = iow(0x82, std::mem::size_of::<KvmRegs>() as u32);
pub const KVM_SET_SREGS: u32 = iow(0x84, std::mem::size_of::<KvmSregs>() as u32);

/// The `kvm_run` union (arm64 view). Interpreted according to `exit_reason`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union KvmRunUnion {
    pub fail_entry: KvmFailEntry,
    /// `KVM_EXIT_IO` payload (x86_64).
    pub io: KvmIo,
    /// `KVM_EXIT_DEBUG` payload (x86_64 view).
    pub debug_x86: KvmDebugX86,
    pub debug: KvmDebugExit,
    pub mmio: KvmMmio,
    pub system_event: KvmSystemEvent,
    pub padding: [u8; 256],
}

/// `KVM_EXIT_IO` union member: `struct { direction, size, port, count, data_offset }`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}

/// `struct kvm_debug_exit_arch` (x86_64): the debug exception number and
/// the faulting PC.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmDebugExitArchX86 {
    pub exception: u32,
    pub pad: u32,
    pub pc: u64,
    pub dr6: u64,
    pub dr7: u64,
}

/// `KVM_EXIT_DEBUG` union member (x86_64 view): `struct { arch }`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmDebugX86 {
    pub arch: KvmDebugExitArchX86,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
}

/// `struct kvm_debug_exit_arch` (arm64): ESR_EL2 of the debug exception.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmDebugExitArch {
    pub hsr: u32,
    pub hsr_high: u32,
    pub far: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmDebugExit {
    pub arch: KvmDebugExitArch,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmSystemEvent {
    pub type_: u32,
    pub ndata: u32,
    pub data: [u64; 2],
}

/// `struct kvm_run`. Only the pre-union header fields and the union payloads
/// below offset 64 are accessed; the tail (kvm_valid_regs / kvm_dirty_regs /
/// arch sync regs) differs per architecture and is left as raw bytes. The
/// vCPU run mmap must therefore cover at least the first 64 bytes (checked
/// at creation time).
#[repr(C)]
pub struct KvmRun {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub padding1: [u8; 6],
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    pub cr8: u64,
    pub apic_base: u64,
    pub u: KvmRunUnion,
    /// Unused tail — sized to cover the largest arch's kvm_run.
    pub _tail: [u8; 2048],
}

/// Smallest mmap size we require: everything through `mmio.is_write` (52).
pub const KVM_RUN_MIN_SIZE: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// raw syscall wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Run an ioctl without arguments (pass 0).
#[inline]
pub fn ioctl_raw(fd: RawFd, req: u32) -> std::io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, req as libc::c_ulong, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ret)
}

/// Run an ioctl with a pointer argument.
#[inline]
pub fn ioctl_ptr<T>(fd: RawFd, req: u32, arg: *mut T) -> std::io::Result<i32> {
    let ret = unsafe { libc::ioctl(fd, req as libc::c_ulong, arg as *mut libc::c_void) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ret)
}

/// Open /dev/kvm and verify the API version.
pub fn open_kvm() -> std::io::Result<RawFd> {
    let fd = unsafe { libc::open(c"/dev/kvm".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ver = ioctl_raw(fd, KVM_GET_API_VERSION)?;
    if ver != KVM_API_VERSION {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::other(format!(
            "/dev/kvm API version {ver}, expected {KVM_API_VERSION}"
        )));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_numbers_match_uapi() {
        // From include/uapi/linux/kvm.h (no size arg for _IO).
        assert_eq!(KVM_GET_API_VERSION, 0xAE00);
        assert_eq!(KVM_CREATE_VM, 0xAE01);
        assert_eq!(KVM_CHECK_EXTENSION, 0xAE03);
        assert_eq!(KVM_GET_VCPU_MMAP_SIZE, 0xAE04);
        assert_eq!(KVM_CREATE_VCPU, 0xAE41);
        assert_eq!(KVM_RUN, 0xAE80);
        // _IOW/_IOWR with sizes (struct sizes per the UAPI headers).
        assert_eq!(
            KVM_SET_USER_MEMORY_REGION,
            (1 << 30) | (32 << 16) | (0xAE << 8) | 0x46
        );
        assert_eq!(KVM_IRQ_LINE, (1 << 30) | (8 << 16) | (0xAE << 8) | 0x61);
        assert_eq!(KVM_SET_ONE_REG, (1 << 30) | (16 << 16) | (0xAE << 8) | 0xac);
        assert_eq!(
            KVM_SET_GUEST_DEBUG,
            (1 << 30) | (72 << 16) | (0xAE << 8) | 0x9b
        );
        assert_eq!(
            KVM_CREATE_DEVICE,
            (3 << 30) | (12 << 16) | (0xAE << 8) | 0xe0
        );
        assert_eq!(
            KVM_SET_DEVICE_ATTR,
            (1 << 30) | (24 << 16) | (0xAE << 8) | 0xe1
        );
        // KVM_GET_SUPPORTED_CPUID is a system ioctl with a header-sized
        // request (the kernel bounds writes by kvm_cpuid2.nent).
        assert_eq!(
            KVM_GET_SUPPORTED_CPUID,
            (3 << 30) | (8 << 16) | (0xAE << 8) | 0x05
        );
        assert_eq!(KVM_SET_CPUID2, (1 << 30) | (8 << 16) | (0xAE << 8) | 0x90);
    }

    #[test]
    fn core_reg_ids() {
        assert_eq!(core_reg_id(0), 0x6030_0000_0010_0000); // X0
        assert_eq!(core_reg_id(CORE_REG_PC), 0x6030_0000_0010_0040);
        assert_eq!(core_reg_id(CORE_REG_PSTATE), 0x6030_0000_0010_0042);
    }

    #[test]
    fn kvm_run_union_offsets() {
        // The union must start at offset 32 and mmio.data at 40 so it matches
        // the kernel's struct kvm_run (verified against asm/kvm.h on x86_64
        // and arm64 — the pre-union layout is arch-independent).
        let base = std::mem::offset_of!(KvmRun, u);
        assert_eq!(base, 32);
        assert_eq!(std::mem::offset_of!(KvmMmio, data), 8);
        assert_eq!(std::mem::offset_of!(KvmMmio, len), 16);
        assert_eq!(std::mem::offset_of!(KvmDebugExitArch, far), 8);
        assert_eq!(std::mem::offset_of!(KvmSystemEvent, data), 8);
    }
}
