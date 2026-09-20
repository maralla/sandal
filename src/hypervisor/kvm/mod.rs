//! KVM backend: VM (memory slots, in-kernel VGICv3, IRQ lines) and vCPU.
//!
//! Unlike the HVF backend, the GIC (VGICv3) and the virtual timer live inside
//! the kernel, so the VMM never touches ICC system registers or vtimer state:
//!
//! - Device SPIs are injected by driving a *level* through `KVM_IRQ_LINE`
//!   (`kvm/system.rs::spi_irq_line`); the line must mirror the devices' pending
//!   state and is lowered when the guest consumes the work ( virtio
//!   `InterruptACK` clears `interrupt_status`).
//! - The guest vtimer is fully emulated by KVM: it wakes WFI-blocked vCPUs and
//!   delivers PPI 27 through the VGIC with no VMM involvement.
//! - WFI blocks inside `KVM_RUN` without a userspace exit. Console input and
//!   network data therefore arrive on poller threads that raise the
//!   corresponding SPI line to kick the vCPU (the following MMIO exit then
//!   delivers the data).

mod system;

use std::ffi::c_void;
use std::os::fd::RawFd;
#[cfg(target_arch = "aarch64")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};

#[cfg(target_arch = "aarch64")]
use super::Reg;
use system::*;

// ─────────────────────────────────────────────────────────────────────────────
// VM
// ─────────────────────────────────────────────────────────────────────────────

/// A KVM VM. Cloneable: poller threads keep a handle for IRQ injection.
#[derive(Clone)]
pub struct Vm {
    inner: Arc<VmInner>,
}

struct VmInner {
    /// The VM ioctl fd (KVM_CREATE_VM).
    fd: RawFd,
    /// The /dev/kvm system ioctl fd (API version, extensions, mmap size).
    kvm_fd: RawFd,
    /// Whether the vgic device has been created (IRQ_LINE requires it).
    #[cfg(target_arch = "aarch64")]
    vgic_ready: AtomicBool,
}

impl Drop for VmInner {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Vm {
    /// Create a KVM VM: open /dev/kvm, verify it is an arm64 host capable of
    /// the guest's memory map, and create the VM.
    pub fn new() -> Result<Self> {
        let kvm_fd = open_kvm().map_err(|e| anyhow!("failed to open /dev/kvm: {e}"))?;

        #[cfg(target_arch = "aarch64")]
        {
            // KVM_CAP_ARM_VM_IPA_SIZE doubles as an arm64 check (the guest
            // places RAM at 0x4000_0000 and devices below it).
            let ipa = unsafe {
                libc::ioctl(
                    kvm_fd,
                    KVM_CHECK_EXTENSION as libc::c_ulong,
                    KVM_CAP_ARM_VM_IPA_SIZE as libc::c_ulong,
                )
            };
            if ipa <= 0 {
                unsafe { libc::close(kvm_fd) };
                bail!("sandal requires an arm64 Linux host with KVM support");
            }
            if ipa < 32 {
                unsafe { libc::close(kvm_fd) };
                bail!("KVM IPA size {ipa} bits is too small for the sandal memory map");
            }

            // Guest debug (the init BRK protocol) requires KVM_CAP_SET_GUEST_DEBUG.
            let gdb = unsafe {
                libc::ioctl(
                    kvm_fd,
                    KVM_CHECK_EXTENSION as libc::c_ulong,
                    KVM_CAP_SET_GUEST_DEBUG as libc::c_ulong,
                )
            };
            if gdb <= 0 {
                unsafe { libc::close(kvm_fd) };
                bail!(
                    "KVM does not support KVM_CAP_SET_GUEST_DEBUG (needed for the init protocol)"
                );
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            // The in-kernel irqchip (PIC + PIT) provides the guest timer and
            // IRQ routing for the virtio-mmio devices.
            let irqchip = unsafe {
                libc::ioctl(
                    kvm_fd,
                    KVM_CHECK_EXTENSION as libc::c_ulong,
                    KVM_CAP_IRQCHIP as libc::c_ulong,
                )
            };
            if irqchip <= 0 {
                unsafe { libc::close(kvm_fd) };
                bail!("KVM does not support the in-kernel irqchip (KVM_CAP_IRQCHIP)");
            }
        }

        let ret = unsafe { libc::ioctl(kvm_fd, KVM_CREATE_VM as libc::c_ulong, 0) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(kvm_fd) };
            return Err(anyhow!("KVM_CREATE_VM failed: {e}"));
        }
        let vm_fd = ret;

        Ok(Vm {
            inner: Arc::new(VmInner {
                fd: vm_fd,
                kvm_fd,
                #[cfg(target_arch = "aarch64")]
                vgic_ready: AtomicBool::new(false),
            }),
        })
    }

    /// Map host memory into the guest physical address space. The `flags`
    /// argument mirrors the HVF API and is ignored: KVM slots are RWX.
    pub fn map_memory(
        &self,
        host_addr: *mut c_void,
        guest_addr: u64,
        size: usize,
        _flags: u64,
    ) -> Result<()> {
        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: guest_addr,
            memory_size: size as u64,
            userspace_addr: host_addr as u64,
        };
        if std::env::var_os("SANDAL_DEBUG_KVM").is_some() {
            eprintln!(
                "memregion: slot={} gpa=0x{:x} size=0x{:x} uaddr=0x{:x}",
                region.slot, region.guest_phys_addr, region.memory_size, region.userspace_addr
            );
        }
        ioctl_ptr(
            self.inner.fd,
            KVM_SET_USER_MEMORY_REGION,
            &region as *const KvmUserspaceMemoryRegion as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_USER_MEMORY_REGION failed: {e}"))?;
        Ok(())
    }

    /// Create and initialize the in-kernel GICv3 (VGIC) with the distributor
    /// and redistributor at the addresses advertised in the device tree.
    #[cfg(target_arch = "aarch64")]
    pub fn create_vgic(
        &self,
        dist_base: u64,
        dist_size: u64,
        redist_base: u64,
        redist_size: u64,
    ) -> Result<()> {
        let _ = (dist_size, redist_size); // sizes are implied (2 × 64K per CPU)

        let mut create = KvmCreateDevice {
            type_: KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        ioctl_ptr(
            self.inner.fd,
            KVM_CREATE_DEVICE,
            &mut create as *mut KvmCreateDevice as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_CREATE_DEVICE (VGICv3) failed: {e}"))?;
        let dev_fd: RawFd = create.fd as RawFd;

        let set_addr = |attr: u64, addr: u64| -> Result<()> {
            let req = KvmDeviceAttr {
                flags: 0,
                group: KVM_DEV_ARM_VGIC_GRP_ADDR,
                attr,
                addr: &addr as *const u64 as u64,
            };
            ioctl_ptr(
                dev_fd,
                KVM_SET_DEVICE_ATTR,
                &req as *const KvmDeviceAttr as *mut libc::c_void,
            )?;
            Ok(())
        };
        set_addr(KVM_VGIC_V3_ADDR_TYPE_DIST, dist_base)?;
        set_addr(KVM_VGIC_V3_ADDR_TYPE_REDIST, redist_base)?;

        // Number of supported interrupts: our highest SPI is
        // SPI_FS_START + MAX_FS_DEVICES - 1 → INTID < 64; round up to 512.
        let nr_irqs: u32 = 512;
        let req = KvmDeviceAttr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: &nr_irqs as *const u32 as u64,
        };
        ioctl_ptr(
            dev_fd,
            KVM_SET_DEVICE_ATTR,
            &req as *const KvmDeviceAttr as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_DEVICE_ATTR (vgic nr_irqs) failed: {e}"))?;

        // Finalize the vgic so it can start taking injections.
        let req = KvmDeviceAttr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: KVM_DEV_ARM_VGIC_CTRL_INIT,
            addr: 0,
        };
        ioctl_ptr(
            dev_fd,
            KVM_SET_DEVICE_ATTR,
            &req as *const KvmDeviceAttr as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_DEVICE_ATTR (vgic init) failed: {e}"))?;

        unsafe { libc::close(dev_fd) };
        self.inner.vgic_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Drive a device interrupt line. Thread-safe: used by the console/net
    /// poller threads to wake a WFI/hlt-blocked vCPU.
    ///
    /// - arm64: `intid` is the GIC INTID (SPIs ≥ 32), encoded with the
    ///   KVM_ARM_IRQ_TYPE_SPI type bits.
    /// - x86_64: `intid` is the legacy ISA GSI (0-15), routed by the in-kernel
    ///   PIC.
    pub fn irq_line(&self, intid: u32, level: bool) -> Result<()> {
        let line = KvmIrqLevel {
            #[cfg(target_arch = "aarch64")]
            irq: spi_irq_line(intid),
            #[cfg(target_arch = "x86_64")]
            irq: intid,
            level: level as i32,
        };
        ioctl_ptr(
            self.inner.fd,
            KVM_IRQ_LINE,
            &line as *const KvmIrqLevel as *mut libc::c_void,
        )
        .map(|_| ())
        .map_err(|e| anyhow!("KVM_IRQ_LINE failed: {e}"))
    }

    /// Create the in-kernel interrupt controller (x86: PIC + IOAPIC + LAPIC)
    /// plus the in-kernel PIT (with dummy-speaker port 0x61 emulation, which
    /// the guest kernel's early TSC calibration polls). Must be called before
    /// the first vCPU is created. Device IRQs are then delivered as legacy
    /// ISA GSIs (0-15) via [`Vm::irq_line`].
    #[cfg(target_arch = "x86_64")]
    pub fn create_irqchip(&self) -> Result<()> {
        ioctl_raw(self.inner.fd, system::KVM_CREATE_IRQCHIP)
            .map_err(|e| anyhow!("KVM_CREATE_IRQCHIP failed: {e}"))?;
        let mut cfg = system::KvmPitConfig {
            flags: system::KVM_PIT_SPEAKER_DUMMY,
            pad: [0; 15],
        };
        ioctl_ptr(
            self.inner.fd,
            system::KVM_CREATE_PIT2,
            &mut cfg as *mut system::KvmPitConfig as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_CREATE_PIT2 failed: {e}"))?;
        Ok(())
    }

    /// The /dev/kvm system ioctl fd.
    pub fn kvm_fd(&self) -> RawFd {
        self.inner.kvm_fd
    }

    /// The VM ioctl fd.
    pub fn vm_fd(&self) -> RawFd {
        self.inner.fd
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// vCPU
// ─────────────────────────────────────────────────────────────────────────────

pub enum KvmExit {
    /// Guest MMIO access (virtio devices, PL011 UART).
    Mmio {
        addr: u64,
        len: usize,
        is_write: bool,
        data: [u8; 8],
    },
    /// Guest debug exception (arm64). For `BRK #imm`, `hsr` is ESR_EL2 with
    /// EC = 0x3c and the immediate in the low 16 bits; the vCPU PC still
    /// points at the instruction and must be advanced by the VMM.
    #[cfg(target_arch = "aarch64")]
    Debug { hsr: u32 },
    /// Guest port I/O (x86_64): serial console (COM1) and the VMM hypercall
    /// ports. `count` is always 1 for our device model.
    Io {
        port: u16,
        len: usize,
        is_write: bool,
        /// The value for OUT; filled by [`Vcpu::fill_io_read`] for IN.
        value: u64,
    },
    /// The guest executed HLT (x86_64). Only surfaces when an interrupt
    /// cannot wake the vCPU; treated like a spurious exit.
    Hlt,
    /// Debug exception (x86_64 single-step / breakpoints).
    #[cfg(target_arch = "x86_64")]
    DebugX86 { exception: u32, pc: u64, dr6: u64 },
    /// KVM internal error (suberror code).
    InternalError(u64),
    /// PSCI SYSTEM_OFF / SYSTEM_RESET (arm64, handled in-kernel) or the x86
    /// KVM system-event path; reported here.
    SystemEvent(#[allow(dead_code)] u32),
    /// vCPU failed to enter; the VM cannot continue.
    FailEntry(u64),
    /// Anything else (should not happen with this device model).
    Unknown(u32),
}

pub struct Vcpu {
    fd: RawFd,
    /// /dev/kvm system fd (for KVM_GET_SUPPORTED_CPUID).
    kvm_fd: RawFd,
    run: *mut KvmRun,
    run_size: usize,
}

// The kvm_run mapping is owned by this struct and only accessed here; the
// vCPU fd itself is only used from the VM thread.
unsafe impl Send for Vcpu {}

impl Drop for Vcpu {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.run as *mut _, self.run_size);
            libc::close(self.fd);
        }
    }
}

impl Vcpu {
    /// Create the single vCPU and map its `kvm_run` shared page.
    pub fn new(vm: &Vm) -> Result<Self> {
        let ret = unsafe { libc::ioctl(vm.vm_fd(), KVM_CREATE_VCPU as libc::c_ulong, 0u64) };
        if ret < 0 {
            return Err(anyhow!(
                "KVM_CREATE_VCPU failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd: RawFd = ret;

        // KVM_GET_VCPU_MMAP_SIZE is a system ioctl (on /dev/kvm), not a
        // vCPU ioctl.
        let run_size = ioctl_raw(vm.kvm_fd(), KVM_GET_VCPU_MMAP_SIZE)? as usize;
        if run_size < KVM_RUN_MIN_SIZE {
            bail!("KVM_GET_VCPU_MMAP_SIZE returned {run_size}, too small for struct kvm_run");
        }
        let run = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                run_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if (run as isize) < 0 {
            return Err(anyhow!(
                "mmap(kvm_run) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let vcpu = Vcpu {
            fd,
            kvm_fd: vm.kvm_fd(),
            run: run as *mut KvmRun,
            run_size,
        };

        // arm64 requires KVM_ARM_VCPU_INIT (with the preferred target type)
        // before the first KVM_RUN; without it KVM_RUN fails with -ENOEXEC.
        // x86 vCPUs need no init ioctl (the irqchip is created on the VM
        // before vCPU creation).
        #[cfg(target_arch = "aarch64")]
        {
            let mut init = KvmVcpuInit {
                target: 0,
                features: [0; 7],
            };
            ioctl_ptr(
                vm.vm_fd(),
                KVM_ARM_PREFERRED_TARGET,
                &mut init as *mut KvmVcpuInit as *mut libc::c_void,
            )
            .map_err(|e| anyhow!("KVM_ARM_PREFERRED_TARGET failed: {e}"))?;
            ioctl_ptr(
                fd,
                KVM_ARM_VCPU_INIT,
                &mut init as *mut KvmVcpuInit as *mut libc::c_void,
            )
            .map_err(|e| anyhow!("KVM_ARM_VCPU_INIT failed: {e}"))?;
        }

        Ok(vcpu)
    }

    /// Set the x86_64 vCPU state for a PVH (direct) boot: flat 32-bit
    /// protected mode, paging off, `rip = entry`, `rbx = hvm_start_info`.
    /// The kernel's PVH entry sets up its own GDT, stack and page tables.
    #[cfg(target_arch = "x86_64")]
    pub fn init_pvh(&self, entry: u64, start_info: u64) -> Result<()> {
        // CS: 32-bit flat code segment (base 0, limit 4G, exec/read/accessed).
        let mut sregs = KvmSregs {
            cs: KvmSegment {
                base: 0,
                limit: 0xffff_ffff,
                selector: 0x8,
                typ: 0x9b,
                present: 1,
                dpl: 0,
                db: 1,
                s: 1,
                g: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        // Data segments: flat, present (the PVH entry reads through DS).
        for seg in [
            &mut sregs.ds,
            &mut sregs.es,
            &mut sregs.fs,
            &mut sregs.gs,
            &mut sregs.ss,
        ] {
            *seg = KvmSegment {
                base: 0,
                limit: 0xffff_ffff,
                selector: 0x10,
                typ: 0x93,
                present: 1,
                dpl: 0,
                db: 1,
                s: 1,
                g: 1,
                ..Default::default()
            };
        }
        // 32-bit protected mode, paging disabled.
        sregs.cr0 = 0x11; // PE | ET
        ioctl_ptr(
            self.fd,
            KVM_SET_SREGS,
            &mut sregs as *mut KvmSregs as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_SREGS failed: {e}"))?;

        let mut regs = KvmRegs {
            rip: entry,
            rbx: start_info,
            rsp: 0x8000, // scratch; the kernel installs its own stack
            rflags: 0x2, // bit 1 is always set
            ..Default::default()
        };
        ioctl_ptr(
            self.fd,
            KVM_SET_REGS,
            &mut regs as *mut KvmRegs as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_REGS failed: {e}"))?;
        Ok(())
    }

    /// Run the vCPU until the next userspace exit.
    pub fn run(&mut self) -> Result<KvmExit> {
        let ret = unsafe { libc::ioctl(self.fd, KVM_RUN as libc::c_ulong, 0) };
        if ret < 0 {
            // EINTR can happen on signals; retry transparently.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(KvmExit::Unknown(u32::MAX)); // caller re-runs
            }
            return Err(anyhow!("KVM_RUN failed: {err}"));
        }

        let reason = unsafe { (*self.run).exit_reason };
        Ok(match reason {
            #[cfg(target_arch = "x86_64")]
            KVM_EXIT_IO => {
                let io = unsafe { (*self.run).u.io };
                let off = io.data_offset as usize;
                let len = io.size as usize;
                let is_write = io.direction == KVM_EXIT_IO_OUT;
                let value = if is_write {
                    self.read_io_data(off, len)
                } else {
                    0
                };
                KvmExit::Io {
                    port: io.port,
                    len,
                    is_write,
                    value,
                }
            }
            KVM_EXIT_MMIO => {
                let mmio = unsafe { (*self.run).u.mmio };
                KvmExit::Mmio {
                    addr: mmio.phys_addr,
                    len: mmio.len as usize,
                    is_write: mmio.is_write != 0,
                    data: mmio.data,
                }
            }
            KVM_EXIT_DEBUG => {
                #[cfg(target_arch = "aarch64")]
                {
                    let dbg = unsafe { (*self.run).u.debug };
                    KvmExit::Debug { hsr: dbg.arch.hsr }
                }
                #[cfg(target_arch = "x86_64")]
                {
                    let dbg = unsafe { (*self.run).u.debug_x86 };
                    KvmExit::DebugX86 {
                        exception: dbg.arch.exception,
                        pc: dbg.arch.pc,
                        dr6: dbg.arch.dr6,
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            KVM_EXIT_HLT => KvmExit::Hlt,
            KVM_EXIT_SYSTEM_EVENT => {
                let ev = unsafe { (*self.run).u.system_event };
                KvmExit::SystemEvent(ev.type_)
            }
            KVM_EXIT_FAIL_ENTRY => {
                let fe = unsafe { (*self.run).u.fail_entry };
                KvmExit::FailEntry(fe.hardware_entry_failure_reason)
            }
            KVM_EXIT_INTERNAL_ERROR => {
                let internal = unsafe { (*self.run).u.fail_entry };
                KvmExit::InternalError(internal.hardware_entry_failure_reason)
            }
            other => KvmExit::Unknown(other),
        })
    }

    /// Read the value transferred by a `KVM_EXIT_IO` OUT from the shared
    /// run page (`data_offset` points into it).
    #[cfg(target_arch = "x86_64")]
    fn read_io_data(&self, offset: usize, len: usize) -> u64 {
        let base = self.run as *const u8;
        let mut val = 0u64;
        for i in 0..len {
            val |= (unsafe { base.add(offset + i).read_volatile() } as u64) << (8 * i);
        }
        val
    }

    /// Provide the read data for a pending `KVM_EXIT_IO` IN so the guest
    /// instruction completes on the next run.
    #[cfg(target_arch = "x86_64")]
    pub fn fill_io_read(&self, offset: usize, len: usize, value: u64) {
        let base = self.run as *mut u8;
        for i in 0..len {
            unsafe {
                base.add(offset + i)
                    .write_volatile((value >> (8 * i)) as u8);
            }
        }
    }

    /// Data offset of the current `KVM_EXIT_IO` exit (for [`Self::fill_io_read`]).
    #[cfg(target_arch = "x86_64")]
    pub fn io_data_offset(&self) -> usize {
        unsafe { (*self.run).u.io.data_offset as usize }
    }

    /// Provide the read data for a pending `KVM_EXIT_MMIO` read so the guest
    /// instruction can complete on the next run. KVM handles sign-extension.
    pub fn fill_mmio_read(&self, data: &[u8]) {
        assert!(data.len() <= 8);
        unsafe {
            let run = self.run;
            let dst = std::ptr::addr_of_mut!((*run).u.mmio.data);
            std::ptr::copy_nonoverlapping(data.as_ptr(), (*dst).as_mut_ptr(), data.len());
        }
    }

    /// Install a CPUID model on the vCPU: query the host KVM's supported
    /// feature set and pass it through. Required for guests that touch MSRs
    /// gated on CPUID features (e.g. EFER.LME requires X86_FEATURE_LM) and
    /// for sane feature reporting to the guest kernel.
    #[cfg(target_arch = "x86_64")]
    pub fn set_supported_cpuid(&self) -> Result<()> {
        const HDR: usize = 8; // nent + padding
        const ENTRY: usize = std::mem::size_of::<KvmCpuidEntry>();

        let max = KVM_MAX_CPUID_ENTRIES;
        let mut buf = vec![0u8; HDR + max * ENTRY];
        let cpuid2 = buf.as_mut_ptr() as *mut KvmCpuid2;
        unsafe {
            (*cpuid2).nent = max as u32;
            (*cpuid2).padding = 0;
        }
        // Query the host KVM's supported feature set (system ioctl).
        let ret = unsafe {
            libc::ioctl(
                self.kvm_fd,
                KVM_GET_SUPPORTED_CPUID as libc::c_ulong,
                cpuid2 as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(anyhow!(
                "KVM_GET_SUPPORTED_CPUID failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let nent = unsafe { (*cpuid2).nent } as usize;
        if std::env::var_os("SANDAL_DEBUG_KVM").is_some() {
            eprintln!("cpuid: {nent} entries");
        }
        if nent > max {
            bail!("KVM_GET_SUPPORTED_CPUID returned {nent} entries");
        }
        // Install it on the vCPU (the request size is the header size, like
        // the UAPI macro — the kernel validates it).
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                KVM_SET_CPUID2 as libc::c_ulong,
                cpuid2 as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(anyhow!(
                "KVM_SET_CPUID2 failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Enable single-stepping (debug aid: `SANDAL_X86_TRACE=1`).
    #[cfg(target_arch = "x86_64")]
    pub fn set_guest_debug_singlestep(&self) -> Result<()> {
        let mut dbg = KvmGuestDebug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            ..Default::default()
        };
        ioctl_ptr(
            self.fd,
            KVM_SET_GUEST_DEBUG,
            &mut dbg as *mut KvmGuestDebug as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_GUEST_DEBUG failed: {e}"))?;
        Ok(())
    }

    /// Enable trapping of guest `BRK` instructions to the VMM (the init
    /// protocol uses BRK immediates to call into the VMM).
    #[cfg(target_arch = "aarch64")]
    pub fn set_guest_debug_sw_bp(&self) -> Result<()> {
        let mut dbg = KvmGuestDebug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            ..Default::default()
        };
        ioctl_ptr(
            self.fd,
            KVM_SET_GUEST_DEBUG,
            &mut dbg as *mut KvmGuestDebug as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_SET_GUEST_DEBUG failed: {e}"))?;
        Ok(())
    }

    /// Write a general-purpose or system register.
    #[cfg(target_arch = "aarch64")]
    pub fn write_register(&self, reg: Reg, value: u64) -> Result<()> {
        let idx = match reg {
            Reg::Pc => CORE_REG_PC,
            Reg::Cpsr => CORE_REG_PSTATE,
            r => {
                let n = r as u32;
                if n > 30 {
                    bail!("register {r:?} not supported by the KVM backend");
                }
                n
            }
        };
        self.set_core_reg(core_reg_id(idx), value)
    }

    /// Read a general-purpose or system register.
    #[cfg(target_arch = "aarch64")]
    pub fn read_register(&self, reg: Reg) -> Result<u64> {
        let idx = match reg {
            Reg::Pc => CORE_REG_PC,
            Reg::Cpsr => CORE_REG_PSTATE,
            r => {
                let n = r as u32;
                if n > 30 {
                    bail!("register {r:?} not supported by the KVM backend");
                }
                n
            }
        };
        self.get_core_reg(core_reg_id(idx))
    }

    #[cfg(target_arch = "aarch64")]
    fn get_core_reg(&self, id: u64) -> Result<u64> {
        let mut value: u64 = 0;
        let mut reg = KvmOneReg {
            id,
            addr: &mut value as *mut u64 as u64,
        };
        ioctl_ptr(
            self.fd,
            KVM_GET_ONE_REG,
            &mut reg as *mut KvmOneReg as *mut libc::c_void,
        )
        .map_err(|e| anyhow!("KVM_GET_ONE_REG failed: {e}"))?;
        Ok(value)
    }

    #[cfg(target_arch = "aarch64")]
    fn set_core_reg(&self, id: u64, value: u64) -> Result<()> {
        let mut reg = KvmOneReg {
            id,
            addr: &value as *const u64 as u64,
        };
        ioctl_ptr(
            self.fd,
            KVM_SET_ONE_REG,
            &mut reg as *mut KvmOneReg as *mut libc::c_void,
        )
        .map(|_| ())
        .map_err(|e| anyhow!("KVM_SET_ONE_REG failed: {e}"))
    }
}
