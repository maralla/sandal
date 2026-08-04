use crate::cli::Args;
use crate::devicetree::DeviceTree;
use crate::hypervisor::{
    self, HvGicDistributorReg, HvGicIccReg, HvReg, HvSysReg, Vcpu, Vm, HV_MEMORY_EXEC,
    HV_MEMORY_READ, HV_MEMORY_WRITE,
};
use crate::net::NetworkFilter;
use crate::snapshot::{
    self, read_cpu_state, CpuState, DeviceState, SnapshotRestore, VirtioMmioSnapshot,
};
use crate::tar;
use crate::unet::UserNet;
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::console::VirtioConsoleDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;
use crate::virtio::{read_avail_idx, REG_INTERRUPT_ACK, REG_INTERRUPT_STATUS};
use crate::chip::timer::Sp804;
use crate::{ext2, initramfs, rootfs};
use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use log::{debug, error, info, trace, warn};
use memmap2::MmapMut;
use std::collections::hash_map::DefaultHasher;
use std::ffi::c_void;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs, mem, process, thread, time};

// ARM64 guest physical memory layout.
// All addresses are GPAs (Guest Physical Addresses) — the address space as seen by the
// guest VM. Addresses below RAM_BASE are reserved for MMIO (Memory-Mapped I/O) device
// registers (GIC, UART, virtio), and guest RAM is placed above them. The device tree
// describes this layout to the kernel.
#[cfg(target_arch = "aarch64")]
mod mem_layout {
    // Guest RAM base address, placed above the MMIO region.
    pub const RAM_BASE: u64 = 0x40000000;
    // Default text_offset from the Linux ARM64 boot protocol, specifying the kernel
    // entry point offset from the start of RAM.
    // See: https://www.kernel.org/doc/Documentation/arm64/booting.txt
    pub const KERNEL_OFFSET: u64 = 0x80000;
    // DTB (Device Tree Blob) describes the VM hardware to the kernel, loaded at
    // RAM_BASE + DTB_OFFSET, well past the kernel to avoid overlap.
    pub const DTB_OFFSET: u64 = 0x8000000;
    // Initial ramdisk (initramfs) loaded at RAM_BASE + INITRD_OFFSET. Contains the
    // root filesystem packed as a cpio archive, immediately after the DTB region.
    pub const INITRD_OFFSET: u64 = 0x8100000;
    // UART (Universal Asynchronous Receiver-Transmitter) MMIO absolute address (not
    // an offset from RAM_BASE). Guest
    // writes here are intercepted and forwarded to the host terminal for all guest I/O.
    pub const UART_BASE: u64 = 0x09000000;

    // Virtio MMIO device regions (absolute addresses, not offsets from RAM_BASE).
    // Each device gets a 512-byte register region for control/data and a unique
    // GIC (Generic Interrupt Controller) SPI (Shared Peripheral Interrupt) number so
    // the kernel can identify which device triggered an interrupt.
    // The base addresses and SPI numbers are arbitrary as long as they don't overlap
    // with each other or other devices, and match the device tree. The 0x200 size is
    // the minimum required to cover all virtio MMIO registers per the virtio spec.
    pub const VIRTIO_NET_BASE: u64 = 0x0A000000;
    pub const VIRTIO_NET_SIZE: u64 = 0x200;
    pub const VIRTIO_NET_SPI: u32 = 16;

    pub const VIRTIO_BLK_BASE: u64 = 0x0A000200;
    pub const VIRTIO_BLK_SIZE: u64 = 0x200;
    pub const VIRTIO_BLK_SPI: u32 = 17;

    pub const VIRTIO_RNG_BASE: u64 = 0x0A000400;
    pub const VIRTIO_RNG_SIZE: u64 = 0x200;
    pub const VIRTIO_RNG_SPI: u32 = 18;

    // Virtiofs (FUSE over virtio) MMIO regions. Up to MAX_FS_DEVICES shared
    // directories can be mounted, each getting its own virtio device.
    pub const VIRTIOFS_BASE_START: u64 = 0x0A000600;
    pub const VIRTIOFS_SIZE: u64 = 0x200;
    pub const VIRTIOFS_SPI_START: u32 = 19;
    pub const MAX_FS_DEVICES: usize = 8;

    // Second virtio-blk device for the writable overlay disk (--disk-size).
    // Placed after the virtiofs MMIO region (0x0A000600 + 8*0x200 = 0x0A001600).
    pub const DATA_BLK_BASE: u64 = 0x0A001800;
    pub const DATA_BLK_SIZE: u64 = 0x200;
    pub const DATA_BLK_SPI: u32 = 27; // After virtiofs SPIs (19..26)

    // Virtio-console device for interactive terminal I/O (hvc0).
    // Replaces MMIO UART for all interactive I/O; UART is earlycon-only.
    pub const VIRTIO_CONSOLE_BASE: u64 = 0x0A001A00;
    pub const VIRTIO_CONSOLE_SIZE: u64 = 0x200;
    pub const VIRTIO_CONSOLE_SPI: u32 = 28;

    // SP804 Dual-Timer MMIO region — clocksource + clockevent replacement
    // for the broken ARM generic timer on Apple Silicon HVF.
    pub const SP804_BASE: u64 = 0x09010000;
    pub const SP804_SPI_1: u32 = 29; // Timer 1 (clockevent)
}

use mem_layout::*;

pub struct VmInstance {
    vm: Vm,
    memory: MmapMut,
    memory_size: usize,
    kernel_entry: u64,
    initrd_info: Option<(u64, u64)>, // (start GPA, end GPA)
    exit_code: Option<i32>,          // Set when guest signals exit via UART marker
    boot_complete: bool,             // Set once kernel finishes booting and init runs
    boot_complete_iter: u64,         // Iteration at which boot_complete became true
    command_injected: bool,          // Set once config has been sent to the guest
    // Init config fields for the compiled init binary (BRK #INIT_CONFIG protocol)
    init_disk_mode: Option<String>,        // "disk" or None
    init_shares: Vec<(String, String)>,    // virtiofs (tag, guest_path) pairs
    init_command: Vec<String>,             // command argv
    init_network: bool,                    // whether to set up networking
    init_config_injected: bool,            // set once config blob pushed via INIT_CONFIG
    forward_output: bool, // set by BRK #INIT_READY — start forwarding UART TX to stdout
    snapshot_save_path: Option<PathBuf>, // If set, save snapshot after boot
    snapshot_fingerprint: u64, // Fingerprint for the snapshot file
    snapshot_pending: u32, // Flag: set to 1 by BRK handler to trigger snapshot save
    restored_cpu_state: Option<CpuState>, // If set, restore these registers instead of boot state
    gic_state_to_restore: Option<Vec<u8>>, // GIC state blob to restore after vCPU creation
    uart_line_buf: String, // Buffer for current line being received from virtio-console TX
    uart_suppress_line: bool, // True if rest of line is suppressed (kernel/marker)
    console_out_buf: Vec<u8>, // Batched console output pending flush to stdout
    network_enabled: bool,
    virtio_net: Option<VirtioNetDevice>,
    virtio_blk: Option<VirtioBlkDevice>,
    data_blk: Option<VirtioBlkDevice>, // Overlay data disk (--disk-size / --layer / export)
    data_blk_config_changed: bool,     // Trigger config change SPI after GIC restore
    export_save_path: Option<String>,  // Path from SANDAL_EXPORT_PATH marker (for sandal-export)
    virtio_rng: Option<VirtioRngDevice>,
    virtio_console: Option<VirtioConsoleDevice>, // Interactive terminal I/O (hvc0)
    virtio_console_config_changed: bool,         // Trigger config change SPI after GIC restore
    sp804: Sp804,                                // MMIO timer for clocksource + clockevent
    virtiofs: Vec<VirtioFsDevice>,
    use_virtio_blk: bool,
    /// MMIO base of the device whose INTERRUPT_ACK was just written on this exit.
    /// Set by handle_mmio, consumed by post-vcpu polling to avoid immediately
    /// re-asserting an interrupt the guest just acked.
    irq_ack_device: u64,
    /// Consecutive CANCELED (exit_reason=0) exits with no MMIO activity.
    /// Used to detect guest hangs (kernel idle with no runnable tasks).
    consecutive_canceled: u32,
    /// Wall-clock instant when the VM boot started, used to provide a
    /// synthetic timebase for CNTVCT_EL0 reads.
    boot_instant: Instant,
    /// Last observed ICC_PMR_EL1 value for diagnostic tracing.
    last_pmr: u64,
    /// Counter for sampling untracked sysreg trap logs.
    sysreg_trap_count: u64,
    /// Counter for sampling synthetic counter-register read logs.
    counter_trap_count: u64,
    /// GPA of an ERET instruction (0xd69f03e0) in the kernel image,
    /// used by STUCK_KICK to force PSTATE restoration from SPSR_EL1.
    eret_insn_gpa: Option<u64>,
    /// Wall-clock of the last vtimer-offset advance (to make CNTVCT move).
    last_vt_advance: std::time::Instant,
    /// Whether the vCPU is parked in the idle loop's WFI (safe to force-exit for
    /// timer wake) vs. actively computing (avoid slicing it with force_exit).
    /// Shared with the stdin poller thread so it can adapt its wake cadence.
    guest_idle: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Idle-region lower/upper bounds for the guest's `cpu_do_idle` (kernel build
/// 6.12.13, loaded at the KIMAGE_VADDR mapping).  The WFI ret is at 0x...a02c.
const IDLE_REGION_LO: u64 = 0xffff_8000_8035_a000;
const IDLE_REGION_HI: u64 = 0xffff_8000_8035_a200;

// ============= Terminal raw mode =============

mod termios {
    use super::RawFd;
    use std::mem;

    /// Put the terminal in raw mode: disable echo, canonical mode, signals.
    /// Returns the original termios for restoring later.
    pub fn enable_raw_mode(fd: RawFd) -> Option<libc::termios> {
        unsafe {
            let mut orig: libc::termios = mem::zeroed();
            if libc::tcgetattr(fd, &mut orig) != 0 {
                return None;
            }
            let mut raw = orig;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_iflag &= !(libc::ICRNL | libc::IXON);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
            Some(orig)
        }
    }

    pub fn restore_mode(fd: RawFd, orig: &libc::termios) {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, orig);
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn set_blocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
}

/// Poll stdin for data or hangup.
/// Returns (ready, hungup) — `ready` is true if POLLIN is set,
/// `hungup` is true if POLLHUP is set (pipe write-end closed).
///
/// The poll timeout is short (2 ms) because this function doubles as the
/// periodic vCPU wake source.  On Apple Silicon HVF a vCPU that executes
/// WFI is parked inside `hv_vcpu_run` and is NOT woken by a pending GIC
/// SPI (`hv_gic_set_spi`/GICD_ISPENDR) nor by `hv_vcpu_set_pending_interrupt`
/// (the pending bit is only consumed at run entry).  The ONLY way to wake
/// it is `hv_vcpus_exit` from another thread, so the poller force-exits on
/// this cadence.  With a 100 ms timeout the guest clockevent ticked at
/// ~10 Hz (50x slow); 2 ms keeps it near the SP804 250 Hz clockevent rate.
fn poll_stdin_once_timeout(fd: RawFd, timeout_ms: i32) -> (bool, bool) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if n < 0 {
        return (false, true); // error → treat as hangup
    }
    let ready = (pfd.revents & libc::POLLIN) != 0;
    let hungup = (pfd.revents & libc::POLLHUP) != 0;
    (ready, hungup)
}

impl VmInstance {
    /// Write to a guest general-purpose register by index (0-30 = X0-LR, 31 = XZR).
    fn write_guest_register(vcpu: &Vcpu, rt: u8, value: u64) -> Result<()> {
        match HvReg::from_gpr(rt) {
            Some(reg) => vcpu.write_register(reg, value),
            None => Ok(()), // XZR (zero register) - writes are discarded
        }
    }

    /// Read from a guest general-purpose register by index (0-30 = X0-LR, 31 = XZR).
    fn read_guest_register(vcpu: &Vcpu, rt: u8) -> Result<u64> {
        match HvReg::from_gpr(rt) {
            Some(reg) => vcpu.read_register(reg),
            None => Ok(0), // XZR (zero register) - always reads 0
        }
    }

    pub fn new(memory_mb: usize) -> Result<Self> {
        // Initialize hypervisor
        hypervisor::init().context("Failed to initialize hypervisor")?;

        // Create VM
        let vm = Vm::new().context("Failed to create VM")?;

        // Allocate main memory
        let memory_size = memory_mb * 1024 * 1024;
        let memory = MmapMut::map_anon(memory_size).context("Failed to allocate VM memory")?;

        Ok(VmInstance {
            vm,
            memory,
            memory_size,
            kernel_entry: 0,
            initrd_info: None,
            exit_code: None,
            boot_complete: false,
            boot_complete_iter: 0,
            command_injected: false,
            init_disk_mode: None,
            init_shares: Vec::new(),
            init_command: Vec::new(),
            init_network: false,
            init_config_injected: false,
            forward_output: false,
            snapshot_save_path: None,
            snapshot_fingerprint: 0,
            snapshot_pending: 0,
            restored_cpu_state: None,
            gic_state_to_restore: None,
            uart_line_buf: String::new(),
            uart_suppress_line: false,
            console_out_buf: Vec::with_capacity(4096),
            network_enabled: false,
            virtio_net: None,
            virtio_blk: None,
            data_blk: None,
            data_blk_config_changed: false,
            export_save_path: None,
            virtio_rng: None,
            virtio_console: None,
            virtio_console_config_changed: false,
            sp804: Sp804::new(),
            virtiofs: Vec::new(),
            use_virtio_blk: false,
            irq_ack_device: 0,
            consecutive_canceled: 0,
            boot_instant: Instant::now(),
            last_pmr: 0xff,
            sysreg_trap_count: 0,
            counter_trap_count: 0,
            eret_insn_gpa: None,
            last_vt_advance: Instant::now(),
            guest_idle: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub fn setup(&mut self) -> Result<()> {
        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;

        // Map main memory
        self.vm
            .map_memory(
                self.memory.as_mut_ptr() as *mut c_void,
                RAM_BASE,
                self.memory_size,
                flags,
            )
            .context("Failed to map main memory")?;
        debug!(
            "Main memory mapped at 0x{:x} ({} MB)",
            RAM_BASE,
            self.memory_size / (1024 * 1024)
        );

        Ok(())
    }

    pub fn load_kernel(&mut self, kernel_data: &[u8]) -> Result<()> {
        // Read the text_offset from the ARM64 Image header (bytes 8-15, little-endian).
        // The ARM64 boot protocol requires the Image at text_offset bytes from a
        // 2MB-aligned base.  Older kernels (4.14) use text_offset=0x80000; modern
        // kernels (>= 5.x) set text_offset=0 and are position-independent.
        // When text_offset is 0, we use 0x200000 (2MB) to satisfy alignment and
        // avoid overlapping with our bootloader trampoline at offset 0.
        let text_offset = if kernel_data.len() >= 16 {
            let offset = u64::from_le_bytes(kernel_data[8..16].try_into().unwrap());
            if offset == 0 {
                0x200000
            } else {
                offset
            }
        } else {
            KERNEL_OFFSET
        };

        // Bootloader trampoline at RAM_BASE.
        //
        // The Linux ARM64 boot protocol requires X0 = DTB address, X1-X3 = 0, and
        // PC = kernel entry. Since we can't atomically set all registers before the
        // vCPU starts, this small stub runs first: it loads the DTB and kernel
        // addresses from its embedded data section, sets up registers, then jumps
        // to the kernel.
        let dtb_gpa: u64 = RAM_BASE + DTB_OFFSET;
        let kernel_entry_gpa: u64 = RAM_BASE + text_offset;

        let bootloader: [u32; 10] = [
            0x580000c0, // ldr x0, [pc, #0x18]  → load DTB address into X0
            0xaa1f03e1, // mov x1, xzr
            0xaa1f03e2, // mov x2, xzr
            0xaa1f03e3, // mov x3, xzr
            0x58000084, // ldr x4, [pc, #0x10]  → load kernel entry into X4
            0xd61f0080, // br x4                → jump to kernel
            // Embedded data: guest physical addresses
            (dtb_gpa & 0xFFFFFFFF) as u32,
            ((dtb_gpa >> 32) & 0xFFFFFFFF) as u32,
            (kernel_entry_gpa & 0xFFFFFFFF) as u32,
            ((kernel_entry_gpa >> 32) & 0xFFFFFFFF) as u32,
        ];

        self.kernel_entry = kernel_entry_gpa;

        unsafe {
            let ptr = self.memory.as_mut_ptr() as *mut u32;
            for (i, &instr) in bootloader.iter().enumerate() {
                *ptr.add(i) = instr;
            }
        }

        // Load kernel at the text_offset read from the Image header
        let kernel_offset = text_offset as usize;

        if kernel_offset + kernel_data.len() > self.memory_size {
            anyhow::bail!(
                "Kernel too large for VM memory ({} bytes, memory {} bytes)",
                kernel_data.len(),
                self.memory_size
            );
        }

        self.memory[kernel_offset..kernel_offset + kernel_data.len()].copy_from_slice(kernel_data);

        debug!(
            "Kernel loaded at offset 0x{:x} ({} bytes = {} MB)",
            kernel_offset,
            kernel_data.len(),
            kernel_data.len() / (1024 * 1024)
        );

        // Load device tree at RAM_BASE + DTB_OFFSET
        self.load_device_tree()?;

        debug!("Bootloader configured:");
        debug!("   Kernel at GPA: 0x{kernel_entry_gpa:x} (text_offset=0x{text_offset:x})");
        debug!("   DTB at GPA: 0x{dtb_gpa:x}");

        // Scan the kernel image for an ERET instruction (0xd69f03e0).
        // STUCK_KICK uses it to restore PSTATE from SPSR_EL1 when the
        // guest is hung with CPSR.I=1 (IRQs masked).  ERET atomically
        // loads PSTATE from SPSR_EL1 and jumps to ELR_EL1, which we
        // set to the current PC before redirecting.
        const ERET: u32 = 0xd69f03e0;
        let kernel_slice = &self.memory[kernel_offset..kernel_offset + kernel_data.len()];
        let eret_offset = kernel_slice
            .chunks_exact(4)
            .position(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()) == ERET);
        self.eret_insn_gpa = eret_offset.map(|i| RAM_BASE + kernel_offset as u64 + (i * 4) as u64);
        if self.eret_insn_gpa.is_some() {
            debug!("ERET instruction found at GPA 0x{:x}", self.eret_insn_gpa.unwrap());
        } else {
            debug!("WARNING: no ERET instruction found in kernel image — STUCK_KICK ERET redirect disabled");
        }

        Ok(())
    }

    /// Load an initrd/initramfs into guest memory
    pub fn load_initrd(&mut self, data: &[u8]) -> Result<()> {
        let offset = INITRD_OFFSET as usize;
        if offset + data.len() > self.memory_size {
            anyhow::bail!(
                "Initrd too large ({} bytes) for VM memory ({} bytes)",
                data.len(),
                self.memory_size
            );
        }

        self.memory[offset..offset + data.len()].copy_from_slice(data);

        let start_gpa = RAM_BASE + INITRD_OFFSET;
        let end_gpa = start_gpa + data.len() as u64;
        self.initrd_info = Some((start_gpa, end_gpa));

        debug!(
            "Initrd loaded at GPA 0x{:x}-0x{:x} ({} bytes = {} KB)",
            start_gpa,
            end_gpa,
            data.len(),
            data.len() / 1024
        );

        Ok(())
    }

    fn load_device_tree(&mut self) -> Result<()> {
        // Query GIC parameters from HVF for accurate device tree
        let (gic_dist_base, gic_dist_size, gic_redist_base, gic_redist_size) =
            Vm::query_gic_params();

        let virtio_net_dt = if self.network_enabled {
            Some((VIRTIO_NET_BASE, VIRTIO_NET_SPI))
        } else {
            None
        };

        let virtio_blk_dt = if self.use_virtio_blk {
            Some((VIRTIO_BLK_BASE, VIRTIO_BLK_SPI))
        } else {
            None
        };

        // Exclude virtio-rng from the DT to avoid the kernel 4.14 virtio-rng
        // driver race (hwrng kthread completion vs ISR).  The rng-seed property
        // in /chosen plus random.trust_bootloader=on provides initial CRNG
        // seeding without the driver.
        let virtio_rng_dt: Option<(u64, u32)> = None;

        // Always include ALL MAX_FS_DEVICES virtiofs entries in the DT so
        // the kernel probes every slot during cold boot.  This lets the same
        // snapshot be reused regardless of which --share args are supplied.
        let virtiofs_dt: Vec<(u64, u32)> = (0..MAX_FS_DEVICES)
            .map(|i| {
                (
                    VIRTIOFS_BASE_START + (i as u64) * VIRTIOFS_SIZE,
                    VIRTIOFS_SPI_START + i as u32,
                )
            })
            .collect();

        // Always include the second virtio-blk device in the DT so the
        // kernel probes the slot during cold boot.  This produces a
        // snapshot reusable regardless of whether --disk-size is supplied.
        let data_blk_dt = Some((DATA_BLK_BASE, DATA_BLK_SPI));

        // Virtio-console device for interactive terminal I/O
        let virtio_console_dt = Some((VIRTIO_CONSOLE_BASE, VIRTIO_CONSOLE_SPI));

        // Seed the kernel CRNG at early boot so /dev/urandom never blocks.
        let rng_seed = {
            let mut buf = vec![0u8; 256];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                .ok()
                .map(|_| buf)
        };
        let dtb = DeviceTree::build(
            self.memory_size as u64,
            UART_BASE,
            gic_dist_base,
            gic_dist_size,
            gic_redist_base,
            gic_redist_size,
            self.initrd_info,
            virtio_net_dt,
            virtio_blk_dt,
            data_blk_dt,
            virtio_rng_dt,
            &virtiofs_dt,
            virtio_console_dt,
            log::log_enabled!(log::Level::Debug),
            None, // no overlay bootarg — init script detects via /dev/vdb size
            rng_seed.as_deref(),
        )?;

        let dtb_offset = DTB_OFFSET as usize;
        if dtb_offset + dtb.len() > self.memory.len() {
            anyhow::bail!("Not enough memory for device tree at offset 0x{dtb_offset:x}");
        }

        self.memory[dtb_offset..dtb_offset + dtb.len()].copy_from_slice(&dtb);

        // Verify DTB magic
        let magic = u32::from_be_bytes([dtb[0], dtb[1], dtb[2], dtb[3]]);
        debug!(
            "Device tree loaded at GPA 0x{:x} ({} bytes, magic=0x{:08x})",
            RAM_BASE + DTB_OFFSET,
            dtb.len(),
            magic
        );

        Ok(())
    }

    pub fn run_command(&mut self, _command: &[String]) -> Result<i32> {
        let trc = Instant::now();
        debug!("=== Starting Linux kernel execution ===");

        // Create VCPU
        let vcpu = Vcpu::new().context("Failed to create vCPU")?;
        debug!(
            "[bench] Vcpu::new: {:.2}ms",
            trc.elapsed().as_secs_f64() * 1000.0
        );

        // If we have restored CPU state (snapshot restore), apply it.
        // Otherwise set up fresh boot state.
        if let Some(ref cpu_state) = self.restored_cpu_state {
            let t = Instant::now();
            snapshot::restore_cpu_state(&vcpu, cpu_state)?;
            debug!(
                "[bench] restore_cpu_state: {:.2}ms",
                t.elapsed().as_secs_f64() * 1000.0
            );
            debug!(
                "vCPU state restored from snapshot (PC=0x{:x}, CPSR=0x{:x})",
                cpu_state.pc, cpu_state.cpsr
            );

            // Defer GIC state restore until the vCPU has run.
            // HVF's internal GIC routing tables may not be ready
            // until the vCPU has executed at least once.
            // GIC state will be restored from self.gic_state_to_restore
            // in the main loop after the first few iterations.

            // Note: The snapshot is taken from userspace (EL0) after the
            // init script runs sandal-signal (BRK #0x5D1).  IRQs are
            // enabled and no kernel locks are held, so on restore the
            // guest can immediately handle interrupts and proceed with
            // reading the injected command from the UART.

            debug!("--- Entering VCPU run loop (restored) ---");
        } else {
            // Configure VCPU state for fresh boot

            // PC → bootloader at RAM_BASE
            let bootloader_gpa = RAM_BASE;
            vcpu.write_register(HvReg::Pc, bootloader_gpa)?;

            // CPSR → EL1h with all interrupts masked (DAIF)
            vcpu.write_register(HvReg::Cpsr, 0x3C5)?;

            // SCTLR_EL1 → 0 (MMU off, caches off)
            vcpu.write_sys_register(HvSysReg::SctlrEl1, 0)?;

            // Stack pointers
            let sp_addr = RAM_BASE + (self.memory_size as u64) - 0x10000; // Near top of RAM
            vcpu.write_sys_register(HvSysReg::SpEl0, sp_addr)?;
            vcpu.write_sys_register(HvSysReg::SpEl1, sp_addr)?;

            // Set MPIDR_EL1 for GIC redistributor mapping
            // Bit 31 is RES1 on AArch64, Aff0=0 for CPU 0
            vcpu.write_sys_register(HvSysReg::MpidrEl1, 0x80000000)?;

            // Trap debug exceptions
            vcpu.set_trap_debug_exceptions(true)?;

            // NOTE: Do NOT call set_vtimer_offset(0) here.  HVF manages the
            // vtimer offset internally; overriding it to 0 breaks the virtual
            // counter comparison, preventing the vtimer from ever firing
            // (exit_reason=2 count stays 0).


            debug!("--- Entering VCPU run loop ---");
        }

        debug!(
            "[bench] run_command setup (vcpu+state): {:.2}ms",
            trc.elapsed().as_secs_f64() * 1000.0
        );

        let mut iteration: u64 = 0;
        let mut stdin_eof = false;
        let max_iterations: u64 = 100_000_000; // 100M iterations for kernel boot

        // Put the terminal in raw mode so we can forward stdin to the guest
        // character-by-character (needed for interactive programs like Python REPL).
        let stdin_fd = io::stdin().as_raw_fd();
        let stdin_is_tty = unsafe { libc::isatty(stdin_fd) } != 0;
        let orig_termios = if stdin_is_tty {
            let orig = termios::enable_raw_mode(stdin_fd);
            set_nonblocking(stdin_fd);
            orig
        } else {
            set_nonblocking(stdin_fd);
            None
        };

        // Spawn an event-driven I/O poller thread. It monitors host-side
        // sockets (and stdin) via kqueue and kicks the vcpu (hv_vcpus_exit)
        // only when data actually arrives.  Without this, a tickless kernel
        // (NO_HZ) may idle the vcpu in WFI indefinitely, stalling network
        // I/O and interactive input.
        //
        // When networking is enabled we use the NetPoller (which already has
        // kqueue set up for network sockets).  Otherwise we create a minimal
        // stdin-only poller.
        //
        // The stdin poller is always created (TTY or pipe) so that the vcpu
        // wakes from WFI when input arrives.  For pipes the poller exits
        // cleanly on POLLHUP; for TTYs it runs until the process ends.
        // Spawn a stdin poller thread that kicks the vcpu when stdin has
        // data.  Without this, a tickless kernel (NO_HZ_FULL) may park the
        // vcpu in WFI indefinitely, stalling interactive input.
        //
        // For TTYs registered with the NetPoller's kqueue this is
        // redundant but harmless (two wakeup sources for the same event).
        // For pipes/redirects the kqueue-based NetPoller can spin (the
        // pipe fd reports always-readable on macOS kqueue), so a
        // poll()-based poller is the only reliable approach.
        let stdin_poller_thread = {
            let vcpu_id = vcpu.id() as u64;
            let guest_idle = self.guest_idle.clone();
            Some(thread::spawn(move || {
                Self::stdin_poller(vcpu_id, stdin_fd, guest_idle);
            }))
        };

        let net_poller_thread = if let Some(ref mut net) = self.virtio_net {
            let poller = net.create_poller(vcpu.id() as u64);
            // Register stdin with kqueue so keypresses kick the vcpu
            // (TTY only — pipes report as always-readable on kqueue
            // which would spin the poller).
            if stdin_is_tty {
                let fd_tx = poller.fd_sender();
                fd_tx.send(stdin_fd).ok();
            }
            Some(thread::spawn(move || poller.run()))
        } else {
            None
        };

        debug!(
            "[bench] run_command ready (tty+threads): {:.2}ms",
            trc.elapsed().as_secs_f64() * 1000.0
        );

        let mut lp_watch_wall = Instant::now();
        let mut lp_watch_iter: u64 = 0;

        loop {
            iteration += 1;

            if iteration > max_iterations {
                warn!("Stopped after {} iterations", iteration - 1);
                break;
            }

            // Minimal progress logging (only at major milestones, verbose only)
            if iteration.is_multiple_of(1000000) {
                let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                debug!("iter={}M, PC=0x{:x}", iteration / 1000000, pc);
            }

            // Track iterations after boot_complete
            if self.boot_complete && self.boot_complete_iter == 0 {
                self.boot_complete_iter = iteration;
                debug!(
                    "[bench] boot_complete at iter {iteration}: {:.2}ms",
                    trc.elapsed().as_secs_f64() * 1000.0
                );
            }

            // Deferred GIC state restore: apply before the first vcpu.run()
            // in the main loop.  HVF initializes its GIC routing tables
            // during VM/vCPU creation, so this works at iteration==1.
            if iteration == 1 {
                if let Some(gic_data) = self.gic_state_to_restore.take() {
                    match Vm::restore_gic_state(&gic_data) {
                        Ok(()) => debug!("GIC state restored (deferred, {} bytes)", gic_data.len()),
                        Err(e) => {
                            // GIC state is required for interrupt routing (UART TX,
                            // vtimer, virtio).  Without it the VM will hang or produce
                            // no output.  Return an error so the caller can fall back
                            // to a full boot.
                            return Err(anyhow::anyhow!("GIC state restore failed: {e}"));
                        }
                    }
                    // Re-apply ICC registers after GIC state restore, because
                    // hv_gic_set_state may have reset the CPU interface to defaults.
                    if let Some(ref cpu_state) = self.restored_cpu_state {
                        if cpu_state.icc_pmr_el1 != 0 || cpu_state.icc_igrpen1_el1 != 0 {
                            vcpu.set_icc_reg(HvGicIccReg::SreEl1, cpu_state.icc_sre_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::PmrEl1, cpu_state.icc_pmr_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Bpr0El1, cpu_state.icc_bpr0_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Bpr1El1, cpu_state.icc_bpr1_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::CtlrEl1, cpu_state.icc_ctlr_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Ap0r0El1, cpu_state.icc_ap0r0_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Ap1r0El1, cpu_state.icc_ap1r0_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Igrpen0El1, cpu_state.icc_igrpen0_el1)?;
                            vcpu.set_icc_reg(HvGicIccReg::Igrpen1El1, cpu_state.icc_igrpen1_el1)?;
                            debug!("ICC regs re-applied after GIC state restore");
                        }
                    }
                }

                // If the virtio-console config changed (e.g. on restore),
                // assert the SPI so the kernel re-reads the config.
                if self.virtio_console_config_changed {
                    self.virtio_console_config_changed = false;
                    Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, true);
                    debug!("Asserted virtio-console config change SPI");
                }

                // If the overlay disk capacity changed (--disk-size on a
                // snapshot that cold-booted with the 1MB stub), assert the
                // config change SPI so the kernel re-reads the block size.
                if self.data_blk_config_changed {
                    self.data_blk_config_changed = false;
                    Vm::set_gic_spi(DATA_BLK_SPI, true);
                    debug!("Asserted data_blk config change SPI for capacity resize");
                }
            }

            if self.boot_complete && self.command_injected {
                // During RNG-driven work the guest kernel may defer the vtimer
                // far into the future (NO_HZ).  Use a short kick interval so
                // the VMM can force timer ticks and let the hwrng kthread run.
                // Keep it short (5ms) at all times: HVF does not wake a
                // WFI-suspended vCPU on a pending SPI, so the ONLY way the
                // guest's clockevent fires is when the VMM force-exits it and
                // the main loop re-pends the SP804 timer.  A 100ms kick makes
                // the guest tick at 10 Hz (very slow); 5ms keeps it near-normal.
                let kick_interval_ms: u64 = 5;
                if lp_watch_wall.elapsed() >= Duration::from_millis(kick_interval_ms) {
                    let delta = iteration.saturating_sub(lp_watch_iter);
                    let guest_idle = {
                        use std::sync::atomic::Ordering;
                        self.guest_idle.load(Ordering::Relaxed)
                    };
                    // Only force-exit when the guest is parked in the idle WFI
                    // (or genuinely stalled).  A low iteration delta while the
                    // guest is actively computing just means hv_vcpu_run blocked
                    // on one long run; force-exiting there slices active guest
                    // code and can preempt a critical section (uv startup block).
                    if delta < 250 && (guest_idle || self.consecutive_canceled > 2000) {
                        crate::vmm_trace::write_console_io(format_args!(
                            "LOW_PROGRESS_KICK delta={delta} iter={iteration}"
                        ));
                        let _ = self.poll_stdin(stdin_fd, &mut stdin_eof);
                        let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
                    }
                    // If the RNG IRQ was ACKed by the guest ISR but the
                    // hwrng kthread lost the completion signal (race between
                    // reinit_completion and complete), re-assert the SPI and
                    // set interrupt_status so the ISR sees a used-ring update
                    // and calls complete() to unblock the kthread.
                    if let Some(ref mut rng) = self.virtio_rng {
                        if rng.interrupt_status == 0 && rng.queues[0].ready {
                            let avail =
                                crate::virtio::read_avail_idx(&self.memory, RAM_BASE, rng.queues[0].avail_addr).unwrap_or(0);
                            crate::vmm_trace::write_console_io(format_args!(
                                "RNG_KICK_RACE avail_idx={avail}"
                            ));
                            rng.interrupt_status |= 1;
                            Vm::set_gic_spi(VIRTIO_RNG_SPI, true);
                        }
                    }
                    lp_watch_wall = Instant::now();
                    lp_watch_iter = iteration;
                }

                // Interleave console TX with stdin so large transmitq bursts do not starve RX.
                const MAX_CONSOLE_TX_SLICES: u32 = 64;
                let mut tx_slices = 0u32;
                while tx_slices < MAX_CONSOLE_TX_SLICES {
                    let mut tx_chunk = Vec::new();
                    if let Some(c) = self.virtio_console.as_mut() {
                        if c.tx_queue_has_pending(&self.memory, RAM_BASE) {
                            tx_chunk = c.process_tx(&mut self.memory, RAM_BASE);
                            Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, c.interrupt_status != 0);
                        }
                    }
                    if tx_chunk.is_empty() {
                        break;
                    }
                    tx_slices += 1;
                    self.process_console_tx(&tx_chunk);
                    if self.poll_stdin(stdin_fd, &mut stdin_eof) {
                        let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
                    }
                }
                if self.poll_stdin(stdin_fd, &mut stdin_eof) {
                    let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
                }
            }

            // Poll RNG proactively before vcpu.run() so buffers posted
            // by the guest without a subsequent QueueNotify (e.g. between
            // virtqueue_add_inbuf and virtqueue_kick) are filled promptly.
            // Use a full memory barrier to ensure guest stores are visible.
            if let Some(ref mut rng) = self.virtio_rng {
                if rng.queues[0].ready {
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                    if rng.process_queue(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, true);
                        // HVF's set_gic_spi doesn't pend the interrupt; pend the
                        // RNG SPI too so uv/python entropy (getrandom) completes.
                        if self.boot_complete {
                            let _ = Vm::set_distributor_reg(
                                HvGicDistributorReg::Ispendr1,
                                1u64 << 18, // INTID 50 = SPI 18 (rng)
                            );
                        }
                    } else {
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, rng.interrupt_status != 0);
                    }
                }
            }

            // SP804 timer: check if clockevent (Timer 1) expired and assert SPI.
            // HVF's hv_gic_set_spi does not create pending state (GICD_ISPENDR
            // stays 0), so also set the pending bit directly via the distributor
            // register.  Without this the guest's clockevent never fires and the
            // idle loop waits forever.
            //
            // Pend SPI 29 on the RISING EDGE only: while the timer is expired
            // `check_timer1_irq()` returns true on every main-loop iteration
            // (irq_pending1 stays set until the guest ACKs it).  Re-writing
            // GICD_ISPENDR1 each iteration floods the guest with timer
            // interrupts at the poll cadence (e.g. 500 Hz with a 2 ms kick)
            // instead of the SP804's natural 250 Hz, which can preempt a
            // critical section holding a spinlock and deadlock the exit path.
            if self.sp804.check_timer1_irq() && !self.sp804.timer1_spi_pended() {
                self.sp804.mark_timer1_spi_pended();
                Vm::set_gic_spi(SP804_SPI_1, true);
                if self.boot_complete {
                    let _ = Vm::set_distributor_reg(
                        HvGicDistributorReg::Ispendr1,
                        1u64 << 29, // INTID 61 = SPI 29 (timer)
                    );
                }
            }

            // The arch timer counters read as 0 on Apple Silicon HVF, so if the
            // guest's clocksource is CNTVCT (advertised by the dtb), ktime is
            // frozen and any kernel delay spins.  Advance the guest's virtual
            // counter by setting a growing negative vtimer offset: CNTVCT =
            // CNTPCT - CNTVOFF, so CNTVOFF = -elapsed makes CNTVCT advance even
            // with CNTPCT frozen.
            if self.boot_complete && self.last_vt_advance.elapsed().as_millis() >= 2 {
                self.last_vt_advance = Instant::now();
                let elapsed_ns = self.boot_instant.elapsed().as_nanos() as u64;
                let ticks = elapsed_ns * 24_000_000 / 1_000_000_000; // 24MHz
                let _ = vcpu.set_vtimer_offset(u64::MAX - ticks + 1); // -ticks
            }

            // Poll data_blk before vcpu.run() to catch requests whose avail-ring
            // writes were not visible at QueueNotify time.  Use a full memory
            // barrier to ensure guest stores are visible (same pattern as RNG).
            if self.boot_complete && self.command_injected {
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                if let Some(ref mut dev) = self.data_blk {
                    if dev.poll_pending(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(DATA_BLK_SPI, true);
                    }
                }
                if let Some(ref mut blk) = self.virtio_blk {
                    if blk.poll_pending(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(VIRTIO_BLK_SPI, true);
                    }
                }
                // Poll virtiofs before vcpu.run() for the same reason.
                for dev_idx in 0..self.virtiofs.len() {
                    let spi = VIRTIOFS_SPI_START + dev_idx as u32;
                    let dev = &mut self.virtiofs[dev_idx];
                    if dev.queues[0].ready || dev.queues[1].ready {
                        let had_work0 = dev.process_queue(0, &mut self.memory, RAM_BASE);
                        let had_work1 = dev.process_queue(1, &mut self.memory, RAM_BASE);
                        if had_work0 || had_work1 {
                            Vm::set_gic_spi(spi, true);
                        }
                    }
                }
            }

            // Raise the virtual IRQ line before hv_vcpu_run whenever a device
            // has a pending interrupt.  On Apple HVF a vCPU parked in WFI is
            // NOT woken by GIC distributor pending state (ISPENDR) alone; the
            // pending state must be armed via hv_vcpu_set_pending_interrupt
            // BEFORE every hv_vcpu_run (it auto-clears after the run returns).
            // Gate it on real device work so the guest's IAR read returns a
            // valid INTID rather than 1023 (spurious).
            let pending_irq = self.sp804.timer1_irq_asserted()
                || self
                    .virtio_console
                    .as_ref()
                    .map_or(false, |c| c.interrupt_status != 0)
                || self
                    .virtio_rng
                    .as_ref()
                    .map_or(false, |r| r.interrupt_status != 0);
            if pending_irq && self.boot_complete {
                match vcpu.set_pending_interrupt(0, true) {
                    Ok(()) => {
                        crate::vmm_trace::write_console_io(format_args!(
                            "PENDING_IRQ_OK timer={} console={}",
                            self.sp804.timer1_irq_asserted(),
                            self.virtio_console.as_ref().map_or(0, |c| c.interrupt_status),
                        ));
                    }
                    Err(e) => {
                        crate::vmm_trace::write_console_io(format_args!(
                            "PENDING_IRQ_ERR {e}"
                        ));
                    }
                }
            }

            let vcpu_entry = Instant::now();
            let exit_reason = match vcpu.run() {
                Ok(r) => r,
                Err(e) => {
                    let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                    error!("hv_vcpu_run error at PC=0x{pc:x}: {e}");
                    return Err(e);
                }
            };
            let vcpu_dur = vcpu_entry.elapsed();

            // ===== Broken vtimer on Apple Silicon HVF =====
            // CNTVCT_EL0, CNTPCT_EL0, CNTFRQ_EL0 all read as 0 from VMM.
            // The hardware comparator never fires on its own.
            // CNTV_CVAL_EL0 is banked — VMM writes go to EL2 copy and don't
            // affect the guest's EL1 view.  We rely on SP804 Timer 2 as the
            // clockevent source instead.
            vcpu.set_vtimer_mask(false)?;

            // Reset per-exit IRQ ACK tracker; handle_mmio will set it if the
            // guest writes INTERRUPT_ACK, so post-vcpu polling can skip that device.
            self.irq_ack_device = 0;

            // Only reset consecutive_canceled on productive exits (MMIO, vtimer,
            // HVC, sysreg traps, etc.), not on WFI which just means the kernel is
            // idle/spinning, and not on SP804 timer MMIO which only means the
            // timer ISR is running without making I/O forward progress.
            // This allows cc to build up and trigger stuck detection.
            if exit_reason == 2 {
                // VTIMER_ACTIVATED — productive exit
                self.consecutive_canceled = 0;
            } else if exit_reason == 1 {
                let syndrome = vcpu.read_exception_syndrome().unwrap_or(0);
                let ec = (syndrome >> 26) & 0x3F;
                if ec != 0x01 {
                    let is_sp804 = (ec == 0x24 || ec == 0x25)
                        && vcpu
                            .read_fault_address()
                            .map(|fa| (SP804_BASE..SP804_BASE + 0x1000).contains(&fa))
                            .unwrap_or(false);
                    if !is_sp804 {
                        self.consecutive_canceled = 0;
                    }
                }
            }

            // Track PMR transitions to identify when kernel enters IRQ-off state.
            let cur_pmr = vcpu.get_icc_reg(HvGicIccReg::PmrEl1).unwrap_or(0);
            if cur_pmr != self.last_pmr {
                let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                let elr = vcpu.read_sys_register(HvSysReg::ElrEl1).unwrap_or(0);
                crate::vmm_trace::write_console_io(format_args!(
                    "PMR_TRANSITION 0x{old:x}→0x{new:x} iter={iteration} exit_reason={exit_reason} PC=0x{pc:x} ELR=0x{elr:x}",
                    old = self.last_pmr, new = cur_pmr
                ));
                self.last_pmr = cur_pmr;
            }

            // Update whether the vCPU is parked in the idle WFI so the stdin
            // poller can back off force-exits while the guest is actively
            // computing (prevents preempting a critical section — the cause of
            // the phase-2 uv startup block after heavy Tab/readline traffic).
            {
                let guest_pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                let is_idle_pc = (IDLE_REGION_LO..IDLE_REGION_HI).contains(&guest_pc);
                use std::sync::atomic::Ordering;
                self.guest_idle.store(is_idle_pc, Ordering::Relaxed);
            }

            match exit_reason {
                0 => {
                    // HV_EXIT_REASON_CANCELED — hv_vcpus_exit() was called
                    // (e.g. by the stdin/network poller to wake a WFI-parked vCPU).
                    self.consecutive_canceled += 1;
                    let cc = self.consecutive_canceled;

                    crate::vmm_trace::write_console_io(format_args!(
                        "CANCELED iter={iteration} dur_us={} cc={cc}",
                        vcpu_dur.as_micros()
                    ));

                    // When the kernel is stuck in a WFI loop without
                    // productive progress, lower the GIC PMR (which the kernel
                    // may have raised to block interrupts in a critical section)
                    // and assert the IRQ line so the GIC delivers the highest-
                    // priority pending interrupt (SP804 timer on SPI 29).  This
                    // lets the kernel's timer ISR update jiffies, run the
                    // scheduler, and unstick any I/O wait.
                    if cc >= 3 && self.boot_complete {
                        // Process console queues during STUCK_KICK — the
                        // kernel may be waiting for TX completions.
                        let mut tx_bytes = Vec::new();
                        if let Some(ref mut console) = self.virtio_console {
                            tx_bytes = console.process_tx(&mut self.memory, RAM_BASE);
                            let _ = console.drain_rx_backlog(&mut self.memory, RAM_BASE);
                            Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, console.interrupt_status != 0);
                        }
                        if !tx_bytes.is_empty() {
                            self.process_console_tx(&tx_bytes);
                        }
                        // Re-check and assert SP804 timer IRQ if expired.
                        if self.sp804.check_timer1_irq() {
                            Vm::set_gic_spi(SP804_SPI_1, true);
                        }

                        // Poll all block devices so any completed I/O
                        // asserts its SPI and wakes waiters.
                        if let Some(ref mut dev) = self.data_blk {
                            if dev.poll_pending(&mut self.memory, RAM_BASE) {
                                Vm::set_gic_spi(DATA_BLK_SPI, true);
                            }
                        }
                        if let Some(ref mut blk) = self.virtio_blk {
                            if blk.poll_pending(&mut self.memory, RAM_BASE) {
                                Vm::set_gic_spi(VIRTIO_BLK_SPI, true);
                            }
                        }
                        if let Some(ref mut rng) = self.virtio_rng {
                            if rng.queues[0].ready {
                                if rng.process_queue(&mut self.memory, RAM_BASE) {
                                    Vm::set_gic_spi(VIRTIO_RNG_SPI, true);
                                }
                            }
                        }

                        // The guest is stuck in the idle loop's WFI (or a
                        // driver WFI) and no interrupt is being delivered.
                        // During the hang, HVF rejects all ICC register access
                        // (HV_BAD_ARGUMENT), so the GIC CPU interface cannot be
                        // read or written.  What still works: set_gic_spi
                        // (VM-level level assert), set_pending_interrupt, and
                        // GPR/CPSR/PC writes.
                        //
                        // NOTE: we deliberately do NOT pulse every managed SPI
                        // low→high here.  The "stuck Active SPI" theory this was
                        // built on was disproven (AP0R0/AP1R0 read 0 during the
                        // hang), and the pulse is a spurious-interrupt source:
                        // lowering a level line under a guest that is mid-EOIR
                        // can inject an interrupt whose IAR read returns 1023,
                        // and enough spurious interrupts make the kernel disable
                        // the line.  Pending delivery is handled by the gated
                        // GICD_ISPENDR1 writes below.

                        // Do NOT clear PSTATE.I here.  The guest may be inside a
                        // critical section that holds a spinlock with IRQs masked;
                        // unmasking I lets a pending timer/console interrupt be
                        // taken inside that critical section, and the IRQ handler
                        // then spins forever on the same lock (the exit-cycle
                        // deadlock).  The fast periodic force_exit already wakes a
                        // WFI'd vCPU; when the guest later unmasks I on its own it
                        // takes the pending interrupt naturally.
                        // Re-enable the timer/console SPIs in the GIC distributor
                        // if the kernel disabled them (disable_irq after a
                        // Work around HVF's `hv_gic_set_spi` not creating pending
                        // state by writing GICD_ISPENDR1 directly.  IMPORTANT:
                        // only pend an SPI whose device actually has work —
                        // pending a console SPI with interrupt_status==0 makes
                        // the guest's ISR read 0 and return IRQ_NONE (spurious),
                        // and enough spurious interrupts make the kernel disable
                        // the console line entirely.
                        if cc >= 3 {
                            let mut want: u64 = 0;
                            if self.sp804.check_timer1_irq()
                                && !self.sp804.timer1_spi_pended()
                            {
                                self.sp804.mark_timer1_spi_pended();
                                want |= 1u64 << 29; // INTID 61 = timer
                            }
                            if let Some(ref console) = self.virtio_console {
                                if console.interrupt_status != 0 {
                                    want |= 1u64 << 28; // INTID 60 = console
                                }
                            }
                            if want != 0 {
                                let _ = Vm::set_distributor_reg(
                                    HvGicDistributorReg::Ispendr1,
                                    want,
                                );
                            }
                        }
                    }

                    // Clear PSTATE.I ONLY when the vCPU is parked at the idle
                    // loop's WFI (cpu_do_idle).  In that state the guest is
                    // genuinely idle — the IRQ-exit path entered the idle WFI
                    // without restoring I (SPSR_EL1.I=0), so the pending timer
                    // interrupt can never be taken and the guest spins forever.
                    // Clearing I there is safe (nothing is protected) and lets
                    // the armed pending interrupt be delivered on the next run.
                    // We deliberately do NOT clear I in other contexts: the
                    // guest may be inside a critical section holding a spinlock,
                    // and unmasking IRQs there lets a pending interrupt preempt
                    // the lock holder → exit-cycle deadlock.
                    if self.boot_complete && cc >= 2 {
                        let pc_idle = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                        let cpsr_idle = vcpu.read_register(HvReg::Cpsr).unwrap_or(0);
                        // cpu_do_idle WFI at 0xffff80008035a028, ret at 0x...a02c.
                        const IDLE_WFI_RET: u64 = 0xffff_8000_8035_a02c;
                        if pc_idle == IDLE_WFI_RET && (cpsr_idle >> 7) & 1 == 1 {
                            let _ = vcpu.write_register(HvReg::Cpsr, cpsr_idle & !(1 << 7));
                        }
                    }
                    // Read PC on CANCELED exits every 25 iterations to diagnose execution.
                    // More frequent during early boot and hang phases.
                    if cc == 1 || cc % 25 == 0 {
                        let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                        let sp_el0 = vcpu.read_sys_register(HvSysReg::SpEl0).unwrap_or(0);
                        let sp_el1 = vcpu.read_sys_register(HvSysReg::SpEl1).unwrap_or(0);
                        let spsr = vcpu.read_sys_register(HvSysReg::SpsrEl1).unwrap_or(0);
                        let el = spsr & 0xF;
                        let irq_masked = (spsr >> 7) & 1;
                        // Read CPSR (actual PSTATE) to compare against SPSR_EL1.
                        let cpsr = vcpu.read_register(HvReg::Cpsr).unwrap_or(0);
                        let cpsr_irq_masked = (cpsr >> 7) & 1;
                        // Read 4 instructions at PC to identify function
                        let ttbr1 = vcpu.read_sys_register(HvSysReg::Ttbr1El1).unwrap_or(0);
                        let tcr = vcpu.read_sys_register(HvSysReg::TcrEl1).unwrap_or(0);
                        let t1sz = tcr & 0x3F;
                        let mut insn_str = String::new();
                        if let Some(pc_pa) = self.translate_va_to_pa(pc, ttbr1, t1sz) {
                            if pc_pa >= RAM_BASE && (pc_pa as usize) + 16 <= RAM_BASE as usize + self.memory.len() {
                                let off = (pc_pa - RAM_BASE) as usize;
                                let i0 = u32::from_le_bytes(self.memory[off..off+4].try_into().unwrap());
                                let i1 = u32::from_le_bytes(self.memory[off+4..off+8].try_into().unwrap());
                                let i2 = u32::from_le_bytes(self.memory[off+8..off+12].try_into().unwrap());
                                let i3 = u32::from_le_bytes(self.memory[off+12..off+16].try_into().unwrap());
                                use std::fmt::Write;
                                let _ = write!(insn_str, "ins=[0x{i0:08x} 0x{i1:08x} 0x{i2:08x} 0x{i3:08x}]");
                            }
                        }
                        crate::vmm_trace::write_console_io(format_args!(
                            "CANCELED_PC cc={cc} PC=0x{pc:x} SP_EL0=0x{sp_el0:x} SP_EL1=0x{sp_el1:x} SPSR.EL={el} SPSR.I={irq_masked} CPSR=0x{cpsr:x} CPSR.I={cpsr_irq_masked} {insn_str}",
                        ));
                    }
                    // Dump console queue state every ~1 second of pure CANCELED.
                    if cc == 3 || cc % 50 == 0 {
                        if let Some(ref c) = self.virtio_console {
                            let tx = &c.queues[1];
                            let rx = &c.queues[0];
                            let tx_avail = crate::virtio::read_avail_idx(&self.memory, RAM_BASE, tx.avail_addr);
                            let rx_avail = crate::virtio::read_avail_idx(&self.memory, RAM_BASE, rx.avail_addr);
                            let tx_used = crate::virtio::read_used_idx(&self.memory, RAM_BASE, tx.used_addr);
                            let rx_used = crate::virtio::read_used_idx(&self.memory, RAM_BASE, rx.used_addr);
                            let guest_pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                            let cval = vcpu.read_sys_register(HvSysReg::CntvCvalEl0).unwrap_or(0);
                            let ctl = vcpu.read_sys_register(HvSysReg::CntvCtlEl0).unwrap_or(0);
                            let cntvct = vcpu.read_sys_register(HvSysReg::CntvCtEl0).unwrap_or(0);
                            let cntfrq = vcpu.read_sys_register(HvSysReg::CntfrqEl0).unwrap_or(0);
                            let vtimer_masked = vcpu.get_vtimer_mask().unwrap_or(false);
                            crate::vmm_trace::write_console_io(format_args!(
                                "HANG_DIAG cc={cc} iter={iteration} PC=0x{guest_pc:x}",
                            ));
                            crate::vmm_trace::write_console_io(format_args!(
                                "  TX: avail={:?} used={:?} last_avail={} ready={} num={}",
                                tx_avail, tx_used, tx.last_avail_idx, tx.ready, tx.num,
                            ));
                            crate::vmm_trace::write_console_io(format_args!(
                                "  RX: avail={:?} used={:?} last_avail={} ready={} num={}",
                                rx_avail, rx_used, rx.last_avail_idx, rx.ready, rx.num,
                            ));
                            crate::vmm_trace::write_console_io(format_args!(
                                "  irq_status={} irq_acked={} backlog={} vtimer_masked={} ctl=0x{ctl:x} cval=0x{cval:x}",
                                c.interrupt_status, c.irq_acked, c.rx_backlog.len(), vtimer_masked,
                            ));
                            crate::vmm_trace::write_console_io(format_args!(
                                "  cntvct=0x{cntvct:x} cntfrq=0x{cntfrq:x} cval_delta={}",
                                cval.wrapping_sub(cntvct) as i64,
                            ));
                            let icc_pmr = vcpu.get_icc_reg(HvGicIccReg::PmrEl1).unwrap_or(0);
                            let igrpen0 = vcpu.get_icc_reg(HvGicIccReg::Igrpen0El1).unwrap_or(0);
                            let igrpen1 = vcpu.get_icc_reg(HvGicIccReg::Igrpen1El1).unwrap_or(0);
                            let icc_ctlr = vcpu.get_icc_reg(HvGicIccReg::CtlrEl1).unwrap_or(0);
                            // Active priority registers: non-zero AP1R0/AP0R0
                            // means an interrupt is stuck Active (guest took it
                            // but never EOIR'd) — this blocks lower-priority
                            // delivery and would explain total starvation.
                            let ap1 = vcpu
                                .get_icc_reg(HvGicIccReg::Ap1r0El1)
                                .unwrap_or(0xFFFF_FFFF);
                            let ap0 = vcpu
                                .get_icc_reg(HvGicIccReg::Ap0r0El1)
                                .unwrap_or(0xFFFF_FFFF);
                            crate::vmm_trace::write_console_io(format_args!(
                                "  GIC: pmr=0x{icc_pmr:x} igrpen0=0x{igrpen0:x} igrpen1=0x{igrpen1:x} ctlr=0x{icc_ctlr:x} ap1=0x{ap1:x} ap0=0x{ap0:x}",
                            ));
                            // Distributor registers: verify the ISPENDR pending-bit
                            // workaround actually pends the timer (INTID 61=bit29)
                            // and console (INTID 60=bit28) SPIs.
                            let dist_isen1 = Vm::get_distributor_reg(HvGicDistributorReg::Isenabler1).unwrap_or(0xFFFF_FFFF_FFFF_FFFF);
                            let dist_ispendr1 = Vm::get_distributor_reg(HvGicDistributorReg::Ispendr1).unwrap_or(0xFFFF_FFFF_FFFF_FFFF);
                            let dist_icpendr1 = Vm::get_distributor_reg(HvGicDistributorReg::Icpendr1).unwrap_or(0xFFFF_FFFF_FFFF_FFFF);
                            crate::vmm_trace::write_console_io(format_args!(
                                "  DIST: isen1=0x{dist_isen1:08x} ispendr1=0x{dist_ispendr1:08x} icpendr1=0x{dist_icpendr1:08x} (timer b29 cons b28)",
                            ));
                            // SP804 timer state
                            let t1_ctrl = self.sp804.mmio_read(0x08);
                            let t1_load = self.sp804.mmio_read(0x00);
                            let t1_val = self.sp804.mmio_read(0x04);
                            let t1_ris = self.sp804.mmio_read(0x10);
                            let t1_mis = self.sp804.mmio_read(0x14);
                            let t1_enabled = t1_ctrl & 0x80 != 0;
                            crate::vmm_trace::write_console_io(format_args!(
                                "  SP804 T1: enabled={t1_enabled} ctrl=0x{t1_ctrl:08x} load=0x{t1_load:08x} val=0x{t1_val:08x} ris={t1_ris} mis={t1_mis}",
                            ));
                            // Timer 2 (clocksource) state — if the guest's time
                            // base is frozen, timeout loops spin forever.
                            let t2_ctrl = self.sp804.mmio_read(0x28);
                            let t2_load = self.sp804.mmio_read(0x20);
                            let t2_val = self.sp804.mmio_read(0x24);
                            crate::vmm_trace::write_console_io(format_args!(
                                "  SP804 T2: ctrl=0x{t2_ctrl:08x} load=0x{t2_load:08x} val=0x{t2_val:08x}",
                            ));
                            let sp_el0 = vcpu.read_sys_register(HvSysReg::SpEl0).unwrap_or(0);
                            let sp_el1 = vcpu.read_sys_register(HvSysReg::SpEl1).unwrap_or(0);
                            let lr = vcpu.read_sys_register(HvSysReg::ElrEl1).unwrap_or(0);
                            let x0 = vcpu.read_register(HvReg::X0).unwrap_or(0);
                            let x1 = vcpu.read_register(HvReg::X1).unwrap_or(0);
                            let x2 = vcpu.read_register(HvReg::X2).unwrap_or(0);
                            let x3 = vcpu.read_register(HvReg::X3).unwrap_or(0);
                            let x4 = vcpu.read_register(HvReg::X4).unwrap_or(0);
                            let tpidr = vcpu.read_sys_register(HvSysReg::TpidrEl1).unwrap_or(0);
                            let esr = vcpu.read_sys_register(HvSysReg::EsrEl1).unwrap_or(0);
                            let fault_addr = vcpu.read_fault_address().unwrap_or(0);
                            let tcr = vcpu.read_sys_register(HvSysReg::TcrEl1).unwrap_or(0);
                            let spsr = vcpu.read_sys_register(HvSysReg::SpsrEl1).unwrap_or(0);
                            let irq_masked = (spsr >> 7) & 1;
                            crate::vmm_trace::write_console_io(format_args!(
                                "  CPU: SP_EL0=0x{sp_el0:x} SP_EL1=0x{sp_el1:x} ELR_EL1=0x{lr:x} X0=0x{x0:x} X1=0x{x1:x} X2=0x{x2:x} X3=0x{x3:x} X4=0x{x4:x} TPIDR=0x{tpidr:x} ESR=0x{esr:x} FAR=0x{fault_addr:x} TCR=0x{tcr:x} T1SZ={} SPSR=0x{spsr:x} IRQ_MASKED={irq_masked}",
                                tcr & 0x3F,
                            ));
                            // Dump the kernel stack to find the stuck call chain.
                            let ttbr1_stack = vcpu
                                .read_sys_register(HvSysReg::Ttbr1El1)
                                .unwrap_or(0);
                            let t1sz_stack = tcr & 0x3F;
                            let mut frames: Vec<u64> = Vec::new();
                            let mut sp = sp_el1;
                            for _ in 0..24 {
                                if let Some(sp_pa) =
                                    self.translate_va_to_pa(sp, ttbr1_stack, t1sz_stack)
                                {
                                    if sp_pa < RAM_BASE
                                        || sp_pa + 8 > RAM_BASE + self.memory_size as u64
                                    {
                                        break;
                                    }
                                    let o = (sp_pa - RAM_BASE) as usize;
                                    let w = u64::from_le_bytes(
                                        self.memory[o..o + 8].try_into().unwrap(),
                                    );
                                    if (w & 0xFFFF_0000_0000_0000) == 0xFFFF_0000_0000_0000 {
                                        frames.push(w);
                                    }
                                    sp = sp.wrapping_add(8);
                                } else {
                                    break;
                                }
                            }
                            let mut fs = String::new();
                            for f in frames.iter().take(12) {
                                use std::fmt::Write;
                                let _ = write!(fs, "0x{f:x} ");
                            }
                            crate::vmm_trace::write_console_io(format_args!(
                                "  STACK_SP1: {fs}"
                            ));
                            // Dump instructions at the stuck PC
                            let ttbr1 = vcpu.read_sys_register(HvSysReg::Ttbr1El1).unwrap_or(0);
                            let t1sz = tcr & 0x3F;
                            if let Some(pc_pa) = self.translate_va_to_pa(guest_pc, ttbr1, t1sz) {
                                let mem_len = self.memory.len();
                                if pc_pa >= RAM_BASE && (pc_pa as usize) + 64 <= RAM_BASE as usize + mem_len {
                                    let off = (pc_pa - RAM_BASE) as usize;
                                    let i0 = u32::from_le_bytes(self.memory[off..off+4].try_into().unwrap());
                                    let i1 = u32::from_le_bytes(self.memory[off+4..off+8].try_into().unwrap());
                                    let i2 = u32::from_le_bytes(self.memory[off+8..off+12].try_into().unwrap());
                                    let i3 = u32::from_le_bytes(self.memory[off+12..off+16].try_into().unwrap());
                                    let i4 = u32::from_le_bytes(self.memory[off+16..off+20].try_into().unwrap());
                                    let i5 = u32::from_le_bytes(self.memory[off+20..off+24].try_into().unwrap());
                                    let i6 = u32::from_le_bytes(self.memory[off+24..off+28].try_into().unwrap());
                                    let i7 = u32::from_le_bytes(self.memory[off+28..off+32].try_into().unwrap());
                                    // Read the function that BL calls (BL target at PC-20)
                                    let pre_off = off.saturating_sub(0x20);
                                    let p0 = u32::from_le_bytes(self.memory[pre_off..pre_off+4].try_into().unwrap());
                                    let p1 = u32::from_le_bytes(self.memory[pre_off+4..pre_off+8].try_into().unwrap());
                                    let p2 = u32::from_le_bytes(self.memory[pre_off+8..pre_off+12].try_into().unwrap());
                                    let p3 = u32::from_le_bytes(self.memory[pre_off+12..pre_off+16].try_into().unwrap());
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  STUCK: PC=0x{guest_pc:x} PA=0x{pc_pa:x} INS=[0x{i0:08x} 0x{i1:08x} 0x{i2:08x} 0x{i3:08x} 0x{i4:08x} 0x{i5:08x} 0x{i6:08x} 0x{i7:08x}]",
                                    ));
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  BL_TGT: PA=0x{:x} INS=[0x{p0:08x} 0x{p1:08x} 0x{p2:08x} 0x{p3:08x}]",
                                        pc_pa.saturating_sub(0x20),
                                    ));
                                }
                            }
                            // If stuck in a spinlock wait (ldxrb [x3] + wfi/wfe),
                            // dump the lock word at X3 so we can identify it.
                            if let Some(x3_pa) = self.translate_va_to_pa(x3, ttbr1, t1sz) {
                                if x3_pa >= RAM_BASE && (x3_pa as usize) + 8 <= RAM_BASE as usize + self.memory.len() {
                                    let off = (x3_pa - RAM_BASE) as usize;
                                    let lock_val = u64::from_le_bytes(self.memory[off..off+8].try_into().unwrap());
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  LOCK@X3: va=0x{x3:x} pa=0x{x3_pa:x} val=0x{lock_val:x}",
                                    ));
                                }
                            }
                        }
                        // Dump virtio-blk queue state to diagnose I/O stalls.
                        if let Some(ref blk) = self.virtio_blk {
                            for qi in 0..blk.queues.len() {
                                let q = &blk.queues[qi];
                                if q.ready {
                                    let blk_avail = crate::virtio::read_avail_idx(&self.memory, RAM_BASE, q.avail_addr);
                                    let blk_used = crate::virtio::read_used_idx(&self.memory, RAM_BASE, q.used_addr);
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  BLK q{qi}: avail={blk_avail:?} used={blk_used:?} last_avail={} irq={}",
                                        q.last_avail_idx, blk.interrupt_status,
                                    ));
                                }
                            }
                        }
                        if let Some(ref dev) = self.data_blk {
                            for qi in 0..dev.queues.len() {
                                let q = &dev.queues[qi];
                                if q.ready {
                                    let blk_avail = crate::virtio::read_avail_idx(&self.memory, RAM_BASE, q.avail_addr);
                                    let blk_used = crate::virtio::read_used_idx(&self.memory, RAM_BASE, q.used_addr);
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  DATABLK q{qi}: avail={blk_avail:?} used={blk_used:?} last_avail={} irq={}",
                                        q.last_avail_idx, dev.interrupt_status,
                                    ));
                                }
                            }
                        }
                        if let Some(ref rng) = self.virtio_rng {
                            let q = &rng.queues[0];
                            if q.ready {
                                let rng_avail = crate::virtio::read_avail_idx(&self.memory, RAM_BASE, q.avail_addr);
                                let rng_used = crate::virtio::read_used_idx(&self.memory, RAM_BASE, q.used_addr);
                                crate::vmm_trace::write_console_io(format_args!(
                                    "  RNG: avail={rng_avail:?} used={rng_used:?} last_avail={} irq={}",
                                    q.last_avail_idx, rng.interrupt_status,
                                ));
                            }
                        }
                        // Scan guest RAM for kernel panic/oops markers and dump context.
                        // Gives the guest kernel's own view of why it is stuck.
                        if cc == 100 {
                            const NEEDLES: [&[u8]; 10] = [
                                b"Kernel panic",
                                b"Oops",
                                b"BUG:",
                                b"Unable to handle kernel",
                                b"Call trace",
                                b"scheduling while atomic",
                                b"attempted to kill",
                                b"soft lockup",
                                b"rcu_sched self-detected",
                                b"bad page state",
                            ];
                            let mem = &self.memory[..self.memory.len().min(64 << 20)]; // first 64MB: kernel image + log buf
                            for needle in NEEDLES {
                                if let Some(pos) = mem.windows(needle.len()).position(|w| w == needle) {
                                    let start = pos.saturating_sub(64);
                                    let end = (pos + needle.len() + 384).min(mem.len());
                                    let text: String = mem[start..end]
                                        .iter()
                                        .map(|&b| if b == b'\n' { '|' } else if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                                        .collect();
                                    crate::vmm_trace::write_console_io(format_args!(
                                        "  KLOG[{}]@0x{:x}: {}", String::from_utf8_lossy(needle),
                                        RAM_BASE + start as u64, text
                                    ));
                                }
                            }
                        }
                        // Dump task list so we can see which tasks are stuck.
                        let ttbr1 = vcpu.read_sys_register(HvSysReg::Ttbr1El1).unwrap_or(0);
                        let tcr_val = vcpu.read_sys_register(HvSysReg::TcrEl1).unwrap_or(0);
                        let t1sz = tcr_val & 0x3F;
                        let sp_el0 = vcpu.read_sys_register(HvSysReg::SpEl0).unwrap_or(0);
                        if let Some(idle_pa) = self.translate_va_to_pa(sp_el0, ttbr1, t1sz) {
                            let idle_off = (idle_pa - RAM_BASE) as usize;
                            let list_off = idle_off + 0x300;
                            if list_off + 16 <= self.memory.len() {
                                let first = u64::from_le_bytes(self.memory[list_off..list_off+8].try_into().unwrap());
                                let mut cursor = first;
                                let mut tasks: Vec<(String, u64, u64)> = Vec::new();
                                for _ in 0..48 {
                                    let task_va = cursor.saturating_sub(0x300);
                                    let task_pa = match self.translate_va_to_pa(task_va, ttbr1, t1sz) {
                                        Some(pa) => pa, None => break,
                                    };
                                    if task_pa < RAM_BASE { break; }
                                    let t_off = (task_pa - RAM_BASE) as usize;
                                    if t_off + 0x30 > self.memory.len() { break; }
                                    let fl = u64::from_le_bytes(self.memory[t_off..t_off+8].try_into().unwrap());
                                    let st = u64::from_le_bytes(self.memory[t_off+0x18..t_off+0x20].try_into().unwrap());
                                    // comm at 0x5a8 on this kernel
                                    let c_start = t_off + 0x5a8;
                                    let c_end = (c_start + 16).min(self.memory.len());
                                    let comm_bytes = &self.memory[c_start..c_end];
                                    let comm = String::from_utf8_lossy(comm_bytes).trim_end_matches('\0').to_string();
                                    let clean = if comm.is_empty() { "?".to_string() } else { comm.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect() };
                                    tasks.push((clean, fl, st));
                                    let c_pa = match self.translate_va_to_pa(cursor, ttbr1, t1sz) {
                                        Some(pa) => pa, None => break,
                                    };
                                    if c_pa < RAM_BASE || c_pa + 8 > RAM_BASE + self.memory_size as u64 { break; }
                                    let c_off = (c_pa - RAM_BASE) as usize;
                                    let next = u64::from_le_bytes(self.memory[c_off..c_off+8].try_into().unwrap());
                                    if next == first { break; }
                                    cursor = next;
                                }
                                let mut ts = String::new();
                                let mut uv_task_pa: Option<u64> = None;
                                for (i, (name, fl, st)) in tasks.iter().enumerate() {
                                    use std::fmt::Write;
                                    let _ = write!(ts, "{i}:{name}(fl=0x{fl:x},st=0x{st:x}) ");
                                    if name.contains("uv") && uv_task_pa.is_none() {
                                        // Re-walk to get uv's task_struct PA
                                        let mut c2 = first;
                                        for j in 0..=i {
                                            let tv = c2.saturating_sub(0x300);
                                            if let Some(tp) = self.translate_va_to_pa(tv, ttbr1, t1sz) {
                                                uv_task_pa = Some(tp);
                                            }
                                            if j < i {
                                                let cp = self.translate_va_to_pa(c2, ttbr1, t1sz);
                                                if let Some(cp) = cp {
                                                    if cp >= RAM_BASE && cp + 8 <= RAM_BASE + self.memory_size as u64 {
                                                        let co = (cp - RAM_BASE) as usize;
                                                        c2 = u64::from_le_bytes(self.memory[co..co+8].try_into().unwrap());
                                                    } else { break; }
                                                } else { break; }
                                            }
                                        }
                                    }
                                }
                                crate::vmm_trace::write_console_io(format_args!(
                                    "  TASKS({}): {ts}", tasks.len()
                                ));
                                // Dump uv kernel state to see call trace.
                                if let Some(uv_pa) = uv_task_pa {
                                    let uv_off = (uv_pa - RAM_BASE) as usize;
                                    // Try stack at multiple offsets (thread_info may be 16 or 24 bytes)
                                    let mut stack_va = 0u64;
                                    for &soff in &[0x18u64, 0x20u64] {
                                        let addr = uv_off + soff as usize;
                                        if addr + 8 <= self.memory.len() {
                                            let v = u64::from_le_bytes(self.memory[addr..addr+8].try_into().unwrap());
                                            // Valid stack VA is in vmalloc range
                                            if v >= 0xffff000000000000 && v < 0xffff800000000000 {
                                                stack_va = v;
                                                crate::vmm_trace::write_console_io(format_args!(
                                                    "  UV_INFO: stack_va@0x{soff:x}=0x{stack_va:x}",
                                                ));
                                                break;
                                            }
                                        }
                                    }
                                    if stack_va == 0 {
                                        // Fallback: read raw bytes at 0x18 and 0x20
                                        let v18 = if uv_off + 0x20 <= self.memory.len() {
                                            u64::from_le_bytes(self.memory[uv_off+0x18..uv_off+0x20].try_into().unwrap())
                                        } else { 0 };
                                        let v20 = if uv_off + 0x28 <= self.memory.len() {
                                            u64::from_le_bytes(self.memory[uv_off+0x20..uv_off+0x28].try_into().unwrap())
                                        } else { 0 };
                                        crate::vmm_trace::write_console_io(format_args!(
                                            "  UV_INFO: offset_0x18=0x{v18:x} offset_0x20=0x{v20:x}",
                                        ));
                                    }

                                    // Scan task_struct for thread.cpu_context by trying every
                                    // 8-byte-aligned offset from 0x200 to 0x5a0 and looking for
                                    // valid sp (vmalloc) + pc (kernel text) at +0x60,+0x68.
                                    let mut found_ctx: Option<(u64, u64, u64, u64)> = None;
                                    // Verify a candidate PC really points at code: the 4 bytes
                                    // there must be a plausible AArch64 opcode (not a kernel
                                    // pointer / not zeros).  The naive sp+pc scan matches data
                                    // tables (e.g. function-pointer arrays) whose slots look
                                    // like a saved sp+pc, producing pc=0xffff800080462448 (data).
                                    for off in (0x200u64..0x5a0u64).step_by(8) {
                                        let ctx = uv_off + off as usize;
                                        if ctx + 0x70 > self.memory.len() { break; }
                                        let sp = u64::from_le_bytes(self.memory[ctx+0x60..ctx+0x68].try_into().unwrap());
                                        let pc = u64::from_le_bytes(self.memory[ctx+0x68..ctx+0x70].try_into().unwrap());
                                        let sp_ok = sp >= 0xffff000000000000 && sp <= 0xffffffffffffefff && sp & 0xf == 0;
                                        let pc_ok = pc >= 0xffff800000000000 && pc <= 0xffffffffffffefff && (pc & 3) == 0;
                                        let mut code_ok = false;
                                        if pc_ok {
                                            if let Some(ppa) = self.translate_va_to_pa(pc, ttbr1, t1sz) {
                                                let po = (ppa - RAM_BASE) as usize;
                                                if po + 4 <= self.memory.len() {
                                                    let insn = u32::from_le_bytes(self.memory[po..po+4].try_into().unwrap());
                                                    // Code-like: not a kernel pointer, not zero,
                                                    // top byte not 0x1f (SVCR/garbage from data).
                                                    code_ok = insn != 0
                                                        && insn >> 20 != 0xffff8
                                                        && insn >> 28 != 0x1f
                                                        && (insn >> 24) & 0xff != 0x80;
                                                }
                                            }
                                        }
                                        if sp_ok && pc_ok && code_ok {
                                            let fp = u64::from_le_bytes(self.memory[ctx+0x58..ctx+0x60].try_into().unwrap());
                                            found_ctx = Some((off, fp, sp, pc));
                                            break;
                                        }
                                    }

                                    if let Some((ctx_off, fp, sp, pc)) = found_ctx {
                                        // Convert PC to physical to identify the blocking function
                                        let pc_pa = self.translate_va_to_pa(pc, ttbr1, t1sz);
                                        let mut pc_info = String::new();
                                        if let Some(ppa) = pc_pa {
                                            let po = (ppa - RAM_BASE) as usize;
                                            if po + 4 <= self.memory.len() {
                                                let insn = u32::from_le_bytes(self.memory[po..po+4].try_into().unwrap());
                                                use std::fmt::Write;
                                                let _ = write!(pc_info, " pc_pa=0x{ppa:x} insn=0x{insn:08x}");
                                            }
                                        }
                                        crate::vmm_trace::write_console_io(format_args!(
                                            "  UV_CTX@0x{ctx_off:x}: fp=0x{fp:x} sp=0x{sp:x} pc=0x{pc:x}{pc_info}",
                                        ));
                                        // Dump raw stack context around sp
                                        if let Some(sp_pa) = self.translate_va_to_pa(sp, ttbr1, t1sz) {
                                            let sp_off = (sp_pa - RAM_BASE) as usize;
                                            if sp_off + 0x80 <= self.memory.len() {
                                                let mut raw = String::new();
                                                for j in 0..8 {
                                                    let addr = sp_off + j * 8;
                                                    let v = u64::from_le_bytes(self.memory[addr..addr+8].try_into().unwrap());
                                                    use std::fmt::Write;
                                                    let _ = write!(raw, " [{j}]=0x{v:x}");
                                                }
                                                crate::vmm_trace::write_console_io(format_args!(
                                                    "  UV_STACK: sp_pa=0x{sp_pa:x}{raw}",
                                                ));
                                            }
                                        }
                                        // Try walking frame pointers with verbose error
                                        if let Some(fp_pa) = self.translate_va_to_pa(fp, ttbr1, t1sz) {
                                            if fp_pa >= RAM_BASE && fp_pa + 16 <= RAM_BASE + self.memory_size as u64 {
                                                let fo = (fp_pa - RAM_BASE) as usize;
                                                let next_fp = u64::from_le_bytes(self.memory[fo..fo+8].try_into().unwrap());
                                                let lr = u64::from_le_bytes(self.memory[fo+8..fo+16].try_into().unwrap());
                                                crate::vmm_trace::write_console_io(format_args!(
                                                    "  UV_FRAME: fp_pa=0x{fp_pa:x} next_fp=0x{next_fp:x} lr=0x{lr:x}",
                                                ));
                                                let mut cur_fp = fp;
                                                let mut trace = String::new();
                                                for _j in 0..12 {
                                                    if let Some(fpa) = self.translate_va_to_pa(cur_fp, ttbr1, t1sz) {
                                                        if fpa >= RAM_BASE && fpa + 16 <= RAM_BASE + self.memory_size as u64 {
                                                            let fo = (fpa - RAM_BASE) as usize;
                                                            let nfp = u64::from_le_bytes(self.memory[fo..fo+8].try_into().unwrap());
                                                            let lrv = u64::from_le_bytes(self.memory[fo+8..fo+16].try_into().unwrap());
                                                            if nfp == 0 || nfp <= cur_fp { break; }
                                                            // Convert LR to PA for function identification
                                                            let mut lr_info = format!("0x{lrv:x}");
                                                            if let Some(lr_pa) = self.translate_va_to_pa(lrv, ttbr1, t1sz) {
                                                                lr_info = format!("0x{lrv:x}(pa=0x{lr_pa:x})");
                                                            }
                                                            use std::fmt::Write;
                                                            let _ = write!(trace, "lr={lr_info} ");
                                                            cur_fp = nfp;
                                                        } else { break; }
                                                    } else { break; }
                                                }
                                                if !trace.is_empty() {
                                                    crate::vmm_trace::write_console_io(format_args!(
                                                        "  UV_TRACE: {trace}"
                                                    ));
                                                }
                                            } else {
                                                crate::vmm_trace::write_console_io(format_args!(
                                                    "  UV_FRAME: fp=0x{fp:x} fp_pa out of range"
                                                ));
                                            }
                                        } else {
                                            crate::vmm_trace::write_console_io(format_args!(
                                                "  UV_FRAME: fp=0x{fp:x} translation failed"
                                            ));
                                        }
                                    } else {
                                        crate::vmm_trace::write_console_io(format_args!(
                                            "  UV_CTX: no cpu_context found in [0x200..0x5a0]"
                                        ));
                                    }

                                    // Try pt_regs from stack top
                                    if stack_va != 0 {
                                        if let Some(stack_pa) = self.translate_va_to_pa(stack_va, ttbr1, t1sz) {
                                            let top = stack_pa.wrapping_add(16384u64);
                                            let prb = top.wrapping_sub(0x110);
                                            if prb >= RAM_BASE && prb + 0x110 <= RAM_BASE + self.memory_size as u64 {
                                                let pr = (prb - RAM_BASE) as usize;
                                                let usr_x8 = u64::from_le_bytes(self.memory[pr+64..pr+72].try_into().unwrap());
                                                let usr_pc = u64::from_le_bytes(self.memory[pr+256..pr+264].try_into().unwrap());
                                                let usr_sp = u64::from_le_bytes(self.memory[pr+248..pr+256].try_into().unwrap());
                                                // Also dump 4 words at stack_pa to see raw content
                                                let s0 = u64::from_le_bytes(self.memory[(stack_pa-RAM_BASE) as usize..(stack_pa-RAM_BASE) as usize+8].try_into().unwrap());
                                                crate::vmm_trace::write_console_io(format_args!(
                                                    "  UV_REGS: x8=0x{usr_x8:x} usr_sp=0x{usr_sp:x} usr_pc=0x{usr_pc:x} stack_pa=0x{stack_pa:x} stack[0]=0x{s0:x}",
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                1 => {
                    // HV_EXIT_REASON_EXCEPTION
                    let pc = vcpu.read_register(HvReg::Pc)?;
                    let syndrome = vcpu.read_exception_syndrome()?;
                    let ec = (syndrome >> 26) & 0x3F;
                    let iss = syndrome & 0x1FFFFFF;

                    // Detailed logging for first 30 iterations during boot
                    if iteration <= 30 {
                        let ec_name = match ec {
                            0x01 => "WFI/WFE",
                            0x16 => "HVC",
                            0x17 => "SMC",
                            0x18 => "SysReg",
                            0x20 => "InstrAbort(lower)",
                            0x24 => "DataAbort(lower)",
                            0x3C => "BRK",
                            _ => "Other",
                        };
                        let fault_addr = vcpu.read_fault_address().unwrap_or(0);
                        trace!(
                            "#{iteration}: PC=0x{pc:x} EC=0x{ec:x}({ec_name}) ISS=0x{iss:x} fault=0x{fault_addr:x}"
                        );
                    }

                    match ec {
                        0x01 => {
                            // WFI/WFE — the kernel is idle.
                            // Just advance past the WFI instruction.
                            vcpu.write_register(HvReg::Pc, pc + 4)?;
                        }

                        0x16 | 0x17 => {
                            // HVC (0x16) or SMC (0x17) - PSCI handling
                            let x0 = vcpu.read_register(HvReg::X0)?;
                            let x1 = vcpu.read_register(HvReg::X1)?;
                            let x2 = vcpu.read_register(HvReg::X2)?;
                            let x3 = vcpu.read_register(HvReg::X3)?;

                            let lr = vcpu.read_register(HvReg::Lr)?;

                            // Read registers needed for SMCCC workaround
                            let sp_el1 = vcpu.read_sys_register(HvSysReg::SpEl1).unwrap_or(0);
                            let ttbr1 = vcpu.read_sys_register(HvSysReg::Ttbr1El1).unwrap_or(0);
                            let tcr = vcpu.read_sys_register(HvSysReg::TcrEl1).unwrap_or(0);
                            let t1sz = (tcr >> 16) & 0x3F;
                            let sp = sp_el1;

                            let result = self.handle_psci(x0, x1, x2, x3)?;

                            if result == 0xDEAD_DEAD {
                                // Shutdown/reboot requested — return the exit code from guest
                                let code = self.exit_code.unwrap_or(0);
                                debug!("System shutdown requested, exit code: {code}");
                                return Ok(code);
                            }

                            // Set the PSCI return value in X0
                            vcpu.write_register(HvReg::X0, result)?;

                            // CRITICAL WORKAROUND: HVF has a cache coherency issue after HVC VMEXIT.
                            // The first load from stack after resuming reads stale (zero) data.
                            // __arm_smccc_hvc does:
                            //   HVC #0            ; +0x04
                            //   LDR X4, [SP, #0]  ; +0x08 ← reads stale 0!
                            //   STP X0, X1, [X4]  ; +0x0c ← crashes writing to [0x0]
                            //
                            // Fix: Emulate the entire __arm_smccc_hvc post-HVC body by:
                            // 1. Read result struct pointer from [SP+0] in guest physical memory
                            // 2. Write X0-X3 results directly into the result struct
                            // 3. Set PC = LR to return from __arm_smccc_hvc to caller

                            let mut emulated_smccc = false;

                            if t1sz > 0 && t1sz < 64 {
                                // Read [SP+0] from guest physical memory to get result struct pointer
                                if let Some(sp_pa) = self.translate_va_to_pa(sp, ttbr1, t1sz) {
                                    if sp_pa >= RAM_BASE
                                        && sp_pa + 16 <= RAM_BASE + self.memory_size as u64
                                    {
                                        let sp_off = (sp_pa - RAM_BASE) as usize;
                                        let res_ptr_va = u64::from_le_bytes(
                                            self.memory[sp_off..sp_off + 8].try_into().unwrap(),
                                        );

                                        if res_ptr_va != 0 {
                                            // Translate the result struct VA to PA and write results
                                            if let Some(res_pa) =
                                                self.translate_va_to_pa(res_ptr_va, ttbr1, t1sz)
                                            {
                                                if res_pa >= RAM_BASE
                                                    && res_pa + 32
                                                        <= RAM_BASE + self.memory_size as u64
                                                {
                                                    let res_off = (res_pa - RAM_BASE) as usize;
                                                    // Write X0-X3 into struct arm_smccc_res { a0, a1, a2, a3 }
                                                    self.memory[res_off..res_off + 8]
                                                        .copy_from_slice(&result.to_le_bytes());
                                                    self.memory[res_off + 8..res_off + 16]
                                                        .copy_from_slice(&x1.to_le_bytes());
                                                    self.memory[res_off + 16..res_off + 24]
                                                        .copy_from_slice(&x2.to_le_bytes());
                                                    self.memory[res_off + 24..res_off + 32]
                                                        .copy_from_slice(&x3.to_le_bytes());

                                                    // Skip entire __arm_smccc_hvc body: set PC = LR
                                                    vcpu.write_register(HvReg::Pc, lr)?;
                                                    emulated_smccc = true;

                                                    trace!("[HVC] Emulated SMCCC: a0=0x{result:x}, PC -> LR 0x{lr:x}");
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if !emulated_smccc {
                                // Fallback: just advance past HVC
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                            }
                        }

                        0x18 => {
                            // MSR/MRS - System register access trap
                            self.handle_sysreg_trap(&vcpu, pc, iss)?;
                            vcpu.write_register(HvReg::Pc, pc + 4)?;
                        }

                        0x24 | 0x25 => {
                            // Data Abort - MMIO
                            let fault_addr = vcpu.read_fault_address().unwrap_or(0);
                            self.handle_mmio(&vcpu, pc, iss, fault_addr, stdin_fd, &mut stdin_eof)?;
                            vcpu.write_register(HvReg::Pc, pc + 4)?;
                        }

                        0x20 | 0x21 => {
                            // Instruction Abort
                            let fault_addr = vcpu.read_fault_address().unwrap_or(0);
                            error!("Instruction Abort at PC=0x{pc:x}, fault_addr=0x{fault_addr:x}");
                            error!("ISS=0x{iss:x}");
                            // Dump register state
                            self.dump_registers(&vcpu)?;
                            return Err(anyhow::anyhow!("Instruction Abort at PC=0x{pc:x}"));
                        }

                        0x3C => {
                            // BRK - breakpoint/semihosting/snapshot signal
                            let imm = iss & 0xFFFF;
                            if imm == initramfs::SNAPSHOT_SIGNAL_IMM as u64 {
                                // Snapshot-ready signal from init binary.
                                // The guest is in EL0 with IRQs enabled and
                                // no kernel locks — advance past BRK and
                                // trigger snapshot save in this iteration.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                self.boot_complete = true;
                                if !self.init_config_injected && self.snapshot_save_path.is_some() {
                                    debug!("Snapshot-ready BRK signal received from guest");
                                    self.snapshot_pending = 1;
                                }
                            } else if imm == initramfs::EXPORT_RESIZE_IMM as u64 {
                                // Export resize: grow /dev/vdb to 128 MB for tar writing.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                self.handle_export_resize();
                            } else if imm == initramfs::EXPORT_DONE_IMM as u64 {
                                // Export done: read tar from /dev/vdb, gzip, save as .layer.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                self.handle_export_done();
                            } else if imm == initramfs::INIT_CONFIG_IMM as u64 {
                                // Init config request: the init binary asks
                                // for its runtime configuration (disk mode,
                                // virtiofs mounts, command argv, etc.).
                                // Build the config blob and push it into the
                                // UART RX buffer for the guest to read.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                self.handle_init_config(&vcpu)?;
                            } else if imm == initramfs::INIT_READY_IMM as u64 {
                                // Init ready: the init binary has finished
                                // processing the config blob and is about to
                                // fork+exec the user command.  Start
                                // forwarding UART TX to stdout now.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                self.forward_output = true;
                                debug!("Init ready — forwarding UART output to stdout");
                            } else if imm == 0xF000 {
                                // ARM semihosting
                                let op = vcpu.read_register(HvReg::X0)?;
                                let param = vcpu.read_register(HvReg::X1)?;

                                match op {
                                    0x18 => {
                                        debug!("Semihosting: SYS_EXIT");
                                        return Ok(0);
                                    }
                                    0x03 => {
                                        // SYS_WRITEC
                                        if param >= RAM_BASE
                                            && param < RAM_BASE + self.memory_size as u64
                                        {
                                            let offset = (param - RAM_BASE) as usize;
                                            if offset < self.memory_size {
                                                let ch = self.memory[offset];
                                                print!("{}", ch as char);
                                            }
                                        }
                                    }
                                    _ => {
                                        if iteration <= 20 {
                                            debug!("Semihosting op=0x{op:x}, param=0x{param:x}");
                                        }
                                    }
                                }
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                            } else {
                                debug!("BRK #{imm} at PC=0x{pc:x}");
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                            }
                        }

                        _ => {
                            if iteration <= 100 {
                                warn!("Unhandled EC=0x{ec:x} at PC=0x{pc:x}, ISS=0x{iss:x}");
                            }
                            vcpu.write_register(HvReg::Pc, pc + 4)?;
                        }
                    }
                }

                2 => {
                    // HV_EXIT_REASON_VTIMER_ACTIVATED
                    // Advance CVAL far into the future to prevent immediate
                    // re-fire while the guest processes the injected IRQ.
                    // The guest's timer handler will reprogram CVAL to the
                    // correct next-tick value.
                    self.consecutive_canceled = 0;
                    let _ = vcpu.write_sys_register(HvSysReg::CntvCvalEl0, u64::MAX);
                    let _ = vcpu.set_pending_interrupt(0, true);
                    crate::vmm_trace::write_console_io(format_args!(
                        "VTIMER iter={iteration} irq_ack_device=0x{ack:x}",
                        ack = self.irq_ack_device
                    ));
                }

                _ => {
                    warn!("Unknown exit reason: {exit_reason}");
                    break;
                }
            }

            // ── Poll virtio-blk queues for missed requests ──────────
            // The guest CPU writes to the avail ring then writes to
            // QueueNotify (MMIO).  In rare cases the avail-ring store
            // is not yet visible when the VMM reads it at QueueNotify
            // time.  Polling here catches any such deferred writes on
            // every subsequent vCPU exit.
            if self.boot_complete
                && self.command_injected
                && self.poll_stdin(stdin_fd, &mut stdin_eof)
            {
                let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
            }
            if self.irq_ack_device != VIRTIO_BLK_BASE {
                if let Some(ref mut blk) = self.virtio_blk {
                    if blk.poll_pending(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(VIRTIO_BLK_SPI, true);
                    }
                }
            }
            if self.irq_ack_device != DATA_BLK_BASE {
                if let Some(ref mut dev) = self.data_blk {
                    if dev.poll_pending(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(DATA_BLK_SPI, true);
                    }
                }
            }
            if self.irq_ack_device != VIRTIO_RNG_BASE {
                if let Some(ref mut rng) = self.virtio_rng {
                    if rng.process_queue(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, true);
                    } else {
                        // Orphan IRQ may have been cleared by process_queue.
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, rng.interrupt_status != 0);
                    }
                }
            }
            // Poll virtio-console queues for missed work (same race as blk:
            // the guest's avail-ring write may not be visible at QueueNotify
            // time, or QueueNotify may not have arrived yet).
            if self.irq_ack_device != VIRTIO_CONSOLE_BASE {
                let mut tx_bytes = Vec::new();
                if let Some(ref mut console) = self.virtio_console {
                    tx_bytes = console.process_tx(&mut self.memory, RAM_BASE);
                    let _ = console.drain_rx_backlog(&mut self.memory, RAM_BASE);
                    Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, console.interrupt_status != 0);
                }
                if !tx_bytes.is_empty() {
                    self.process_console_tx(&tx_bytes);
                }
            }
            if self.boot_complete
                && self.command_injected
                && self.poll_stdin(stdin_fd, &mut stdin_eof)
            {
                let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
            }

            // ── Guest-cooperative snapshot trigger ─────────────────
            // The init script runs sandal-signal which executes
            // BRK #0x5D1 from userspace right before `read`.  The
            // BRK handler sets snapshot_pending=1, and we save HERE
            // — in the same iteration, before the next vcpu.run() —
            // so the guest state is exactly: EL0, IRQs enabled, no
            // kernel locks, PC right after the BRK instruction.
            if self.snapshot_pending > 0 && self.boot_complete && !self.init_config_injected {
                self.snapshot_pending = 0;
                self.save_snapshot(&vcpu, &trc)?;
            }

            // Poll stdin for input and inject into the virtio-console RX queue.
            // Delay until after the command has been injected so that
            // (a) piped data isn't consumed by the kernel's console
            //     driver during init, and
            // (b) stdin EOF (Ctrl-D) doesn't reach the guest's `read`
            //     before the command data when running without a TTY.
            if self.boot_complete
                && self.command_injected
                && self.poll_stdin(stdin_fd, &mut stdin_eof)
            {
                let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
            }

            // Poll network backend and deliver incoming packets to guest RX queue
            if self.irq_ack_device != VIRTIO_NET_BASE {
                if let Some(ref mut net) = self.virtio_net {
                    net.poll_backend();
                    if net.process_rx(&mut self.memory, RAM_BASE) {
                        Vm::set_gic_spi(VIRTIO_NET_SPI, true);
                    }
                }
            }

            // Poll virtiofs devices for missed FUSE requests (same race as blk
            // where avail-ring writes may not be visible at QueueNotify time).
            for dev_idx in 0..self.virtiofs.len() {
                let spi = VIRTIOFS_SPI_START + dev_idx as u32;
                let dev = &mut self.virtiofs[dev_idx];
                if dev.queues[0].ready || dev.queues[1].ready {
                    // Poll hiprio queue (0) and request queue (1)
                    let had_work0 = dev.process_queue(0, &mut self.memory, RAM_BASE);
                    let had_work1 = dev.process_queue(1, &mut self.memory, RAM_BASE);
                    if had_work0 || had_work1 {
                        Vm::set_gic_spi(spi, true);
                    }
                }
            }

            // (vtimer is unmasked at the top of the loop, before vcpu.run())

            // Exit immediately once the exit marker has been received
            // (no need to wait for the guest to poweroff)
            if self.exit_code.is_some() {
                debug!(
                    "[bench] exit_code received at iter {iteration}: {:.2}ms",
                    trc.elapsed().as_secs_f64() * 1000.0
                );
                break;
            }
        }

        // Restore terminal mode before any other cleanup or output.
        if stdin_is_tty {
            set_blocking(stdin_fd);
            if let Some(ref orig) = orig_termios {
                termios::restore_mode(stdin_fd, orig);
            }
        }

        // Shut down the network poller thread.
        // Dropping the VirtioNetDevice (which holds UserNet) triggers
        // UserNet::drop, which writes the shutdown sentinel to the wakeup
        // pipe, unblocking the kevent() loop. We drop first, then join.
        drop(self.virtio_net.take());
        if let Some(t) = net_poller_thread {
            t.join().ok();
        }
        // The stdin poller thread exits on POLLHUP (pipe closed) or when
        // the process is exiting. We don't join it — it's harmless to
        // let it be cleaned up on process exit.
        drop(stdin_poller_thread);

        // Flush any remaining partial line in the UART buffer
        if !self.uart_line_buf.is_empty() {
            let line = mem::take(&mut self.uart_line_buf);
            self.process_uart_line(&line);
        }

        let code = self.exit_code.unwrap_or(0);

        if log::log_enabled!(log::Level::Debug) {
            let final_pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
            debug!("Final PC: 0x{final_pc:x}");
            debug!("Total iterations: {iteration}");
            debug!("Exit code: {code}");
        }

        Ok(code)
    }

    /// Minimal poller for stdin when networking is disabled.
    /// Uses poll() to block until stdin has data or the periodic kick fires,
    /// then kicks the vcpu.  The periodic kick (every 100 ms) prevents the
    /// guest from running unbounded without a VMM scheduling point, which
    /// matters when NO_HZ defers the vtimer during CPU-bound stretches.
    /// Exits when stdin reaches EOF/POLLHUP or an error occurs.
    fn stdin_poller(
        vcpu_id: u64,
        stdin_fd: RawFd,
        guest_idle: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::Ordering;
        loop {
            // Adaptive wake cadence: when the guest is parked in the idle WFI,
            // force-exit every 10 ms so it can take timer ticks; when it is
            // actively computing, back off to 100 ms so we do NOT slice active
            // guest code (which can preempt a critical section and deadlock the
            // guest — the phase-2 uv startup block).  stdin data is polled
            // regardless and wakes the vCPU immediately.
            let timeout_ms = if guest_idle.load(Ordering::Relaxed) { 10 } else { 100 };
            let (_ready, hungup) = poll_stdin_once_timeout(stdin_fd, timeout_ms);
            Vcpu::force_exit(&[vcpu_id]).ok();
            if hungup {
                break;
            }
        }
    }

    /// Read host stdin until `EAGAIN` (up to 16 KiB per call), inject into virtio-console RX.
    /// Returns whether the vCPU should be kicked (`force_exit`): data reached the guest, is
    /// queued in [`VirtioConsoleDevice::rx_backlog`], or EOF was queued.
    fn poll_stdin(&mut self, stdin_fd: RawFd, stdin_eof: &mut bool) -> bool {
        if *stdin_eof {
            return false;
        }
        const MAX_PER_CALL: usize = 16 * 1024;
        const CHUNK: usize = 4096;
        let mut buf = [0u8; CHUNK];
        let mut total_read = 0usize;
        let mut need_kick = false;

        loop {
            let n =
                unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                total_read += n as usize;
                let chunk = &buf[..n as usize];
                if let Some(ref mut console) = self.virtio_console {
                    let progressed = console.push_rx_and_drain(&mut self.memory, RAM_BASE, chunk);
                    need_kick |= progressed || !console.rx_backlog.is_empty();
                    let irq = console.interrupt_status != 0;
                    Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, irq);
                    // HVF's set_gic_spi doesn't pend the interrupt; pend the
                    // console SPI directly when it has work so the guest's ISR
                    // actually fires and wakes the blocked shell.
                    if irq {
                        let _ = Vm::set_distributor_reg(
                            HvGicDistributorReg::Ispendr1,
                            1u64 << 28, // INTID 60 = console
                        );
                    }
                    crate::vmm_trace::write_console_io(format_args!(
                        "STDIN_READ n={} progressed={} backlog={} irq_pending={} preview=\"{}\"",
                        n,
                        progressed,
                        console.rx_backlog.len(),
                        irq,
                        crate::vmm_trace::bytes_preview(chunk, 48)
                    ));
                }
                if total_read >= MAX_PER_CALL {
                    need_kick = true;
                    break;
                }
                continue;
            }
            if n == 0 {
                *stdin_eof = true;
                if let Some(ref mut console) = self.virtio_console {
                    let progressed = console.push_rx_and_drain(&mut self.memory, RAM_BASE, &[0x04]);
                    need_kick |= progressed || !console.rx_backlog.is_empty();
                    crate::vmm_trace::write_console_io(format_args!(
                        "STDIN_EOF progressed={} backlog={}",
                        progressed,
                        console.rx_backlog.len()
                    ));
                    Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, console.interrupt_status != 0);
                }
                return need_kick;
            }
            let err = io::Error::last_os_error();
            let raw = err.raw_os_error().unwrap_or(0);
            if raw == libc::EINTR {
                continue;
            }
            if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK {
                break;
            }
            crate::vmm_trace::write_console_io(format_args!(
                "STDIN_READ_ERR errno={raw} err={err}"
            ));
            break;
        }
        need_kick
    }

    /// Process bytes received from the virtio-console TX queue.
    /// Feeds them through the same line-buffered marker detection and output
    /// filtering that previously ran per-byte in the UART TX handler.
    /// Output is batched: bytes are accumulated and only flushed to stdout
    /// on newline or when the buffer reaches FLUSH_THRESHOLD bytes.  This
    /// avoids per-byte write+flush that could block the VMM thread when the
    /// receiving pty/pipe buffer fills up (especially during high-volume
    /// output like python REPL exits).
    fn process_console_tx(&mut self, data: &[u8]) {
        const FLUSH_THRESHOLD: usize = 256;

        for &ch in data {
            if ch.is_ascii() || ch == b'\n' || ch == b'\r' {
                self.uart_line_buf.push(ch as char);

                if self.forward_output && !self.uart_suppress_line {
                    let buf_len = self.uart_line_buf.len();
                    let buf_bytes = self.uart_line_buf.as_bytes();
                    let is_prefix_of_marker = |buf: &[u8]| -> bool {
                        let markers: &[&[u8]] = &[
                            initramfs::EXIT_MARKER.as_bytes(),
                            initramfs::EXPORT_PATH_MARKER.as_bytes(),
                        ];
                        markers
                            .iter()
                            .any(|m| buf.len() <= m.len() && buf == &m[..buf.len()])
                    };
                    let is_full_marker = |buf: &[u8]| -> bool {
                        buf == initramfs::EXIT_MARKER.as_bytes()
                            || buf == initramfs::EXPORT_PATH_MARKER.as_bytes()
                    };

                    if is_full_marker(buf_bytes) {
                        self.uart_suppress_line = true;
                    } else if is_prefix_of_marker(buf_bytes) {
                        // Still matching a marker prefix — keep buffering.
                    } else if buf_len > 1 && is_prefix_of_marker(&buf_bytes[..buf_len - 1]) {
                        // Was matching a prefix but no longer — flush the queued bytes.
                        self.console_out_buf.extend_from_slice(buf_bytes);
                    } else {
                        self.console_out_buf.push(ch);
                    }
                }

                if ch == b'\n' {
                    self.uart_suppress_line = false;
                    let line = mem::take(&mut self.uart_line_buf);
                    self.process_uart_line(&line);
                    // Flush on newline so the reader sees complete lines promptly.
                    if !self.console_out_buf.is_empty() {
                        Self::flush_console_out(&mut self.console_out_buf);
                    }
                } else if self.console_out_buf.len() >= FLUSH_THRESHOLD {
                    Self::flush_console_out(&mut self.console_out_buf);
                }
            }
        }
        // Flush any buffered output that didn't end with a newline,
        // e.g. shell prompt ("/ # ") or DSR ("\x1b[6n").
        if !self.console_out_buf.is_empty() {
            Self::flush_console_out(&mut self.console_out_buf);
        }
    }

    /// Write buffered console output to stdout.
    /// Batched writes reduce syscall overhead vs the old per-byte flush.
    fn flush_console_out(buf: &mut Vec<u8>) {
        if buf.is_empty() {
            return;
        }
        let _ = io::stdout().write_all(buf);
        let _ = io::stdout().flush();
        buf.clear();
    }

    /// Process a complete line of console output.
    /// Extracts exit code marker, export path marker, and detects boot completion.
    fn process_uart_line(&mut self, line: &str) {
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

        // Check for exit marker
        if let Some(marker_pos) = trimmed.find(initramfs::EXIT_MARKER) {
            let after = &trimmed[marker_pos + initramfs::EXIT_MARKER.len()..];
            if let Ok(code) = after.trim().parse::<i32>() {
                self.exit_code = Some(code);
            }
            return;
        }

        // Check for export path marker (from sandal-export <path>)
        if let Some(marker_pos) = trimmed.find(initramfs::EXPORT_PATH_MARKER) {
            let path = &trimmed[marker_pos + initramfs::EXPORT_PATH_MARKER.len()..];
            let path = path.trim();
            if !path.is_empty() {
                debug!("Export path received from guest: {path}");
                self.export_save_path = Some(path.to_string());
            }
            return; // Don't forward to stdout
        }

        // Before boot is complete: only show in debug mode.
        // Boot completion is signaled by BRK #SNAPSHOT_SIGNAL or BRK #INIT_CONFIG.
        if !self.boot_complete {
            debug!("{trimmed}");
        }

        if self.boot_complete && self.command_injected {
            crate::vmm_trace::write_console_io(format_args!(
                "GUEST_LINE len={} text=\"{}\"",
                trimmed.len(),
                crate::vmm_trace::text_preview(trimmed, 200)
            ));
        }

        // After boot: characters were already written directly to stdout
        // by the UART write handler, so nothing more to print here.
    }

    /// Handle BRK #INIT_CONFIG: build the config blob and inject it into
    /// the virtio-console RX queue.  Sets x0 = blob size so the guest knows how much to read.
    fn handle_init_config(&mut self, vcpu: &Vcpu) -> Result<()> {
        if self.init_config_injected {
            return Ok(());
        }
        let now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let blob = initramfs::build_init_config(
            self.init_disk_mode.as_deref(),
            &self.init_shares,
            &self.init_command,
            self.init_network,
            now,
        );
        debug!(
            "Pushing init config blob ({} bytes): disk={:?}, shares={}, argv={}, net={}",
            blob.len(),
            self.init_disk_mode,
            self.init_shares.len(),
            self.init_command.len(),
            self.init_network,
        );
        let blob_len = blob.len() as u64;
        if let Some(ref mut console) = self.virtio_console {
            let _ = console.push_rx_and_drain(&mut self.memory, RAM_BASE, &blob);
            Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, console.interrupt_status != 0);
        }
        vcpu.write_register(HvReg::X0, blob_len)?;
        self.init_config_injected = true;
        self.boot_complete = true;
        self.command_injected = true; // Enable stdin polling
        Ok(())
    }

    /// Save snapshot to disk.
    /// Called when the guest signals snapshot-ready via BRK #0x5D1.
    fn save_snapshot(&mut self, vcpu: &Vcpu, trc: &Instant) -> Result<()> {
        let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
        debug!("Saving snapshot (PC=0x{pc:x})");

        let Some(ref save_path) = self.snapshot_save_path.clone() else {
            return Ok(());
        };

        let t_total = Instant::now();
        let device_state = self.capture_device_state();
        if device_state.gic_state.is_none() {
            warn!("Skipping snapshot save: GIC state not available (macOS 15.0+ required)");
            return Ok(());
        }

        let cpu_state = read_cpu_state(vcpu)?;
        let t_snap = Instant::now();
        match snapshot::save_snapshot(
            save_path,
            &self.memory,
            &cpu_state,
            &device_state,
            self.snapshot_fingerprint,
        ) {
            Ok(()) => {
                info!(
                    "Snapshot saved to {} ({:.1}ms)",
                    save_path.display(),
                    t_snap.elapsed().as_secs_f64() * 1000.0,
                );
                if let Some(ref blk) = self.virtio_blk {
                    if let Ok(disk_path) = snapshot::disk_image_path(self.snapshot_fingerprint) {
                        let t_disk = Instant::now();
                        let tmp = disk_path.with_extension("tmp");
                        match fs::write(&tmp, &blk.disk_image) {
                            Ok(()) => {
                                if let Err(e) = fs::rename(&tmp, &disk_path) {
                                    warn!("Failed to rename disk image: {e}");
                                }
                                debug!(
                                    "[bench] save_disk_image ({}MB): {:.1}ms",
                                    blk.disk_image.len() / (1024 * 1024),
                                    t_disk.elapsed().as_secs_f64() * 1000.0
                                );
                            }
                            Err(e) => warn!("Failed to save disk image: {e}"),
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to save snapshot: {e}"),
        }
        debug!(
            "[bench] snapshot+disk: {:.1}ms, save at: {:.0}ms",
            t_total.elapsed().as_secs_f64() * 1000.0,
            trc.elapsed().as_secs_f64() * 1000.0,
        );
        // No inject_command here — the init binary will request config
        // via BRK #INIT_CONFIG after resuming from snapshot.
        Ok(())
    }

    /// Handle BRK #EXPORT_RESIZE: grow /dev/vdb to 128 MB so the guest
    /// can write a tar archive for `sandal-export`.
    fn handle_export_resize(&mut self) {
        const EXPORT_DISK_SIZE: usize = 128 * 1024 * 1024; // 128 MB

        if let Some(ref mut dev) = self.data_blk {
            let current_size = dev.disk_image.len();
            if current_size < EXPORT_DISK_SIZE {
                debug!(
                    "Export resize: growing data_blk from {} to {} bytes",
                    current_size, EXPORT_DISK_SIZE
                );
                dev.disk_image.resize(EXPORT_DISK_SIZE, 0);
                // Update the capacity reported by the device
                dev.update_capacity();
                // Signal config change so the kernel re-reads the block count
                dev.config_generation = dev.config_generation.wrapping_add(1);
                dev.interrupt_status |= 2; // VIRTIO_MMIO_INT_CONFIG
                                           // Assert the config change SPI so the kernel processes it
                Vm::set_gic_spi(DATA_BLK_SPI, true);
                debug!("Export resize complete, config change SPI asserted");
            }
        } else {
            warn!("Export resize: no data_blk device");
        }
    }

    /// Handle BRK #EXPORT_DONE: read the tar archive from /dev/vdb,
    /// gzip-compress it, and save as a .layer file.
    fn handle_export_done(&mut self) {
        let disk_data = if let Some(ref dev) = self.data_blk {
            &dev.disk_image
        } else {
            warn!("Export done: no data_blk device");
            return;
        };

        // Determine the end of the tar archive in the raw disk data.
        // The guest writes an uncompressed tar to /dev/vdb.
        let tar_end = tar::find_tar_end(disk_data);
        if tar_end == 0 || tar_end > disk_data.len() {
            warn!("Export done: no valid tar archive found on data_blk");
            return;
        }
        let tar_data = &disk_data[..tar_end];
        debug!("Export: found {} bytes of tar data on data_blk", tar_end);

        // Gzip-compress the tar data
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        if let Err(e) = io::Write::write_all(&mut encoder, tar_data) {
            error!("Export: failed to gzip tar data: {e}");
            return;
        }
        let gz_data = match encoder.finish() {
            Ok(data) => data,
            Err(e) => {
                error!("Export: failed to finish gzip: {e}");
                return;
            }
        };

        // Determine save path
        let save_path = if let Some(ref path) = self.export_save_path {
            PathBuf::from(path)
        } else {
            // Auto-generate: layer-<hash>.layer in CWD
            let hash = {
                let mut h = DefaultHasher::new();
                gz_data.hash(&mut h);
                h.finish()
            };
            PathBuf::from(format!("layer-{hash:016x}.layer"))
        };

        // Save to disk
        match fs::write(&save_path, &gz_data) {
            Ok(()) => {
                info!(
                    "Layer exported: {} ({} bytes, {:.1}x compression)",
                    save_path.display(),
                    gz_data.len(),
                    tar_end as f64 / gz_data.len() as f64,
                );
                // Print to stderr so the user sees it even without --verbose
                eprintln!("Layer saved to: {}", save_path.display());
            }
            Err(e) => {
                error!("Export: failed to write layer file: {e}");
                eprintln!("sandal: failed to save layer: {e}");
            }
        }

        // Reset export path for next use
        self.export_save_path = None;
    }

    /// Build the device state snapshot from current device states.
    fn capture_device_state(&self) -> DeviceState {
        let net_mmio = self.virtio_net.as_ref().map(VirtioMmioSnapshot::from_net);
        let rng_mmio = self.virtio_rng.as_ref().map(VirtioMmioSnapshot::from_rng);
        let blk_mmio = self.virtio_blk.as_ref().map(VirtioMmioSnapshot::from_blk);
        let data_blk_mmio = self.data_blk.as_ref().map(VirtioMmioSnapshot::from_blk);
        let console_mmio = self
            .virtio_console
            .as_ref()
            .map(VirtioMmioSnapshot::from_console);

        // Save GIC state (macOS 15.0+)
        let gic_state = Vm::save_gic_state();
        if let Some(ref state) = gic_state {
            debug!("GIC state saved ({} bytes)", state.len());
        } else {
            warn!("GIC state save not available (macOS 15.0+ required for snapshot restore)");
        }

        let fs_mmio = self
            .virtiofs
            .iter()
            .map(VirtioMmioSnapshot::from_fs)
            .collect();

        DeviceState {
            network_enabled: self.network_enabled,
            net_mmio,
            rng_mmio,
            blk_mmio,
            use_virtio_blk: self.use_virtio_blk,
            fs_mmio,
            gic_state,
            data_blk_mmio,
            console_mmio,
        }
    }

    /// Handle PSCI calls (Power State Coordination Interface)
    fn handle_psci(&self, func: u64, x1: u64, x2: u64, x3: u64) -> Result<u64> {
        match func {
            0x84000000 => {
                // PSCI_VERSION → v1.1
                Ok(0x00010001)
            }
            0x84000001 | 0xC4000001 => {
                // PSCI_CPU_SUSPEND
                Ok(0)
            }
            0x84000002 => {
                // PSCI_CPU_OFF — on a single-CPU VM, turning off the
                // only CPU is equivalent to system shutdown.  Treat it
                // like SYSTEM_OFF so the VM exits cleanly.
                Ok(0xDEAD_DEAD)
            }
            0x84000003 | 0xC4000003 => {
                // PSCI_CPU_ON
                debug!("[PSCI] CPU_ON(cpu={x1}, entry=0x{x2:x}, ctx=0x{x3:x}) -> ALREADY_ON");
                Ok((-4i64) as u64) // PSCI_RET_ALREADY_ON
            }
            0x84000004 | 0xC4000004 => {
                // PSCI_AFFINITY_INFO
                Ok(0)
            }
            0x84000008 => {
                // PSCI_SYSTEM_OFF
                Ok(0xDEAD_DEAD)
            }
            0x84000009 => {
                // PSCI_SYSTEM_RESET
                Ok(0xDEAD_DEAD)
            }
            0x8400000A => {
                // PSCI_FEATURES
                match x1 {
                    0x84000000..=0x8400000A => Ok(0),
                    0xC4000000..=0xC4000005 => Ok(0),
                    _ => Ok((-1i64) as u64),
                }
            }
            _ => {
                debug!("[PSCI] Unknown function: 0x{func:x}");
                Ok((-1i64) as u64) // NOT_SUPPORTED
            }
        }
    }

    /// Handle system register trap (EC=0x18)
    fn handle_sysreg_trap(&mut self, vcpu: &Vcpu, pc: u64, iss: u64) -> Result<()> {
        // ARM64 ISS encoding for MSR/MRS (EC=0x18):
        //   ISS[23:22] = Op0   (2 bits)
        //   ISS[21:19] = Op1   (3 bits)
        //   ISS[18:14] = CRn   (5 bits, upper bit is reserved on some encodings)
        //   ISS[13:10] = CRm   (4 bits)
        //   ISS[9:5]   = Rt    (5 bits)
        //   ISS[4:1]   = Op2   (3 bits)
        //   ISS[0]     = Direction (1=Read/MRS, 0=Write/MSR)
        let is_read = (iss & 1) != 0;
        let rt = ((iss >> 5) & 0x1F) as u8;
        let op0 = (iss >> 22) & 3;
        let op1 = (iss >> 19) & 7;
        let crn = (iss >> 14) & 0xF;
        let crm = (iss >> 10) & 0xF;
        let op2 = (iss >> 1) & 7;

        // ── ICC (GIC CPU Interface) register forwarding ──────────────────
        // ICC registers are accessed as S3_0_C{crn}_C{crm}_{op2}.
        // If ICC_SRE_EL1.SRE=0 these trap to EL2 and the VMM must forward
        // them to the GIC hardware.  Even with SRE=1 some HVF versions may
        // trap individual ICC registers.
        let is_icc = op0 == 3 && op1 == 0;
        if is_icc {
            // Map (CRn, CRm, op2) → HvGicIccReg
            let icc_reg: Option<HvGicIccReg> = match (crn, crm, op2) {
                (4, 6, 0) => Some(HvGicIccReg::PmrEl1),
                (12, 12, 0) => Some(HvGicIccReg::Iar1El1),
                (12, 12, 1) => Some(HvGicIccReg::Eoir1El1),
                (12, 12, 4) => Some(HvGicIccReg::CtlrEl1),
                (12, 12, 5) => Some(HvGicIccReg::SreEl1),
                (12, 12, 6) => Some(HvGicIccReg::Igrpen0El1),
                (12, 12, 7) => Some(HvGicIccReg::Igrpen1El1),
                (12, 8, 3) => Some(HvGicIccReg::Bpr0El1),
                (12, 12, 3) => Some(HvGicIccReg::Bpr1El1),
                // ICC_AP0R0_EL1 / ICC_AP1R0_EL1 — active priority registers
                (12, 8, 4) => Some(HvGicIccReg::Ap0r0El1),
                (12, 9, 0) => Some(HvGicIccReg::Ap1r0El1),
                _ => None,
            };
            if let Some(reg) = icc_reg {
                if is_read {
                    let value = vcpu.get_icc_reg(reg).unwrap_or(0);
                    Self::write_guest_register(vcpu, rt, value)?;
                    if reg as u16 == HvGicIccReg::Iar1El1 as u16 {
                        crate::vmm_trace::write_console_io(format_args!(
                            "ICC_TRAP_RD: IAR=0x{value:x} PC=0x{pc:x} rt={rt}"
                        ));
                    }
                } else {
                    let value = Self::read_guest_register(vcpu, rt)?;
                    vcpu.set_icc_reg(reg, value)?;
                    if reg as u16 == HvGicIccReg::Eoir1El1 as u16 {
                        crate::vmm_trace::write_console_io(format_args!(
                            "ICC_TRAP_WR: EOIR=0x{value:x} PC=0x{pc:x} rt={rt}"
                        ));
                    } else if reg as u16 == HvGicIccReg::PmrEl1 as u16 {
                        crate::vmm_trace::write_console_io(format_args!(
                            "ICC_TRAP_WR: PMR=0x{value:x} PC=0x{pc:x} rt={rt}"
                        ));
                    }
                }
                return Ok(());
            }
        }

        if is_read {
            // Counter registers are broken on Apple Silicon HVF: CNTVCT_EL0,
            // CNTPCT_EL0, CNTFRQ_EL0 read as 0 from the vCPU, so any guest
            // delay/udelay/timeout that reads a cycle counter sees a frozen
            // value and busy-spins forever (observed after repeated Python
            // exit cycles: the guest spins in a counter-read loop).
            //
            // Provide a synthetic, monotonically advancing counter for ALL
            // counter register reads (regular and self-synchronized variants)
            // so guest timing code makes forward progress.
            //   CNTFRQ_EL0:   S3_3_C14_C0_0  op2=0
            //   CNTPCT_EL0:   S3_3_C14_C0_1  op2=1
            //   CNTVCT_EL0:   S3_3_C14_C0_2  op2=2
            //   CNTVCTSS_EL0: S3_3_C14_C0_4  op2=4
            //   CNTPCTSS_EL0: S3_3_C14_C0_5  op2=5
            let is_counter_cr = op0 == 3 && op1 == 3 && crn == 14 && crm == 0;
            let is_cntfrq = is_counter_cr && op2 == 0;
            let is_counter = is_counter_cr && (op2 == 1 || op2 == 2 || op2 == 4 || op2 == 5);

            let value = if is_cntfrq {
                24_000_000u64
            } else if is_counter {
                self.counter_trap_count += 1;
                if self.counter_trap_count <= 5 || self.counter_trap_count % 100 == 0 {
                    crate::vmm_trace::write_console_io(format_args!(
                        "CNT_TRAP_RD op2={op2} rt={rt} cnt={} PC=0x{pc:x}",
                        self.counter_trap_count
                    ));
                }
                let freq_hz: u64 = 24_000_000;
                let elapsed_ns = self.boot_instant.elapsed().as_nanos() as u64;
                (elapsed_ns * freq_hz) / 1_000_000_000
            } else {
                // Log untracked sysreg reads for diagnostics — only sample to
                // avoid flooding the trace.
                self.sysreg_trap_count += 1;
                if self.sysreg_trap_count <= 20 || self.sysreg_trap_count % 200 == 0 {
                    crate::vmm_trace::write_console_io(format_args!(
                        "SYSREG_TRAP_RD[{cnt}]: op0={op0} op1={op1} CRn={crn} CRm={crm} op2={op2} rt={rt} PC=0x{pc:x}",
                        cnt = self.sysreg_trap_count,
                    ));
                }
                0u64
            };
            Self::write_guest_register(vcpu, rt, value)?;
        } else {
            // MSR write — forward timer register writes to hardware.
            // CNTV_CTL_EL0: Op0=3, Op1=3, CRn=14, CRm=3, Op2=1
            // CNTV_CVAL_EL0: Op0=3, Op1=3, CRn=14, CRm=3, Op2=2
            let is_cntv_ctl = op0 == 3 && op1 == 3 && crn == 14 && crm == 3 && op2 == 1;
            let is_cntv_cval = op0 == 3 && op1 == 3 && crn == 14 && crm == 3 && op2 == 2;

            if is_cntv_ctl || is_cntv_cval {
                let value = Self::read_guest_register(vcpu, rt)?;
                let reg = if is_cntv_ctl { HvSysReg::CntvCtlEl0 } else { HvSysReg::CntvCvalEl0 };
                vcpu.write_sys_register(reg, value)?;
                crate::vmm_trace::write_console_io(format_args!(
                    "SYSREG_WRITE: rt={rt} val=0x{value:x} reg={}",
                    if is_cntv_ctl { "CTL" } else { "CVAL" }
                ));
            } else {
                // Log untracked sysreg writes for diagnostics.
                self.sysreg_trap_count += 1;
                if self.sysreg_trap_count <= 20 || self.sysreg_trap_count % 200 == 0 {
                    let value = Self::read_guest_register(vcpu, rt)?;
                    crate::vmm_trace::write_console_io(format_args!(
                        "SYSREG_TRAP_WR[{cnt}]: op0={op0} op1={op1} CRn={crn} CRm={crm} op2={op2} rt={rt} val=0x{value:x} PC=0x{pc:x}",
                        cnt = self.sysreg_trap_count,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Handle MMIO access (Data Abort)
    fn handle_mmio(
        &mut self,
        vcpu: &Vcpu,
        pc: u64,
        iss: u64,
        fault_addr: u64,
        stdin_fd: RawFd,
        stdin_eof: &mut bool,
    ) -> Result<()> {
        let is_write = (iss & (1 << 6)) != 0;
        let access_sas = ((iss >> 22) & 0x3) as u8; // 0=byte, 1=halfword, 2=word, 3=doubleword
        let rt = ((iss >> 16) & 0x1F) as u8;

        // UART at 0x09000000 — earlycon-only PL011 stub.
        // TX writes go to stderr only when debug logging is enabled.
        // This keeps early boot messages hidden by default (like before)
        // but makes kernel panic messages visible via RUST_LOG=debug.
        // No RX, no interrupt state machine.
        if (UART_BASE..UART_BASE + 0x1000).contains(&fault_addr) {
            let reg_offset = fault_addr - UART_BASE;

            if is_write {
                let value = Self::read_guest_register(vcpu, rt)?;

                // PL011 DR (offset 0x00): TX write — send to stderr in debug mode
                if reg_offset == 0 && log::log_enabled!(log::Level::Debug) {
                    let ch = (value & 0xFF) as u8;
                    let buf = [ch];
                    io::stderr().write_all(&buf).ok();
                }
                // All other writes (IMSC, ICR, LCR_H, CR, etc.) — silently ignored
            } else {
                // UART reads — return safe earlycon defaults
                let value = match reg_offset {
                    // FR (Flags Register): TX empty, RX empty
                    0x18 => 0x90u64, // TXFE | RXFE
                    // PL011 identification registers (earlycon probes these)
                    0xFE0 => 0x11, // PeriphID0
                    0xFE4 => 0x10, // PeriphID1
                    0xFE8 => 0x34, // PeriphID2
                    0xFEC => 0x00, // PeriphID3
                    0xFF0 => 0x0D, // CellID0
                    0xFF4 => 0xF0, // CellID1
                    0xFF8 => 0x05, // CellID2
                    0xFFC => 0xB1, // CellID3
                    _ => 0x00,
                };
                Self::write_guest_register(vcpu, rt, value)?;
            }
        }
        // Virtio-console MMIO region (interactive terminal I/O)
        else if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + VIRTIO_CONSOLE_SIZE)
            .contains(&fault_addr)
        {
            let offset = fault_addr - VIRTIO_CONSOLE_BASE;
            // Handle the MMIO access and collect any TX bytes, then process
            // them after releasing the virtio_console borrow.
            let mut tx_bytes = Vec::new();
            if self.boot_complete && self.command_injected && self.poll_stdin(stdin_fd, stdin_eof) {
                let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
            }
            if let Some(ref mut console) = self.virtio_console {
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(queue_idx) = console.mmio_write(offset, value) {
                        crate::vmm_trace::write_console_io(format_args!(
                            "CONSOLE_QUEUE_NOTIFY q={queue_idx}"
                        ));
                        if queue_idx == 1 {
                            // TX queue notification — collect output bytes
                            tx_bytes = console.process_tx(&mut self.memory, RAM_BASE);
                        } else {
                            let drained = console.drain_rx_backlog(&mut self.memory, RAM_BASE);
                            crate::vmm_trace::write_console_io(format_args!(
                                "CONSOLE_RX_NOTIFY drained={} backlog={}",
                                drained,
                                console.rx_backlog.len()
                            ));
                        }
                    }
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = VIRTIO_CONSOLE_BASE;
                        crate::vmm_trace::write_console_io(format_args!(
                            "CONSOLE_ACK irq_status={} backlog={}",
                            console.interrupt_status,
                            console.rx_backlog.len(),
                        ));
                    }
                    Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, console.interrupt_status != 0);
                } else {
                    let value = console.mmio_read(offset, access_sas);
                    // Trace INTERRUPT_STATUS reads to diagnose orphan IRQ loops
                    if offset == REG_INTERRUPT_STATUS {
                        crate::vmm_trace::write_console_io(format_args!(
                            "CONSOLE_READ_IRQ value={value} int_status={} backlog={}",
                            console.interrupt_status,
                            console.rx_backlog.len(),
                        ));
                    }
                    // Clear orphan interrupt on INTERRUPT_STATUS read: only if the
                    // guest has already acked (irq_acked), meaning it processed the
                    // used ring, and there's no new work pending.
                    if offset == REG_INTERRUPT_STATUS && value != 0 && console.irq_acked {
                        let tx_q = &console.queues[1]; // TX_QUEUE
                        let rx_q = &console.queues[0]; // RX_QUEUE
                        let tx_idle = !tx_q.ready
                            || tx_q.num == 0
                            || read_avail_idx(&self.memory, RAM_BASE, tx_q.avail_addr)
                                .is_some_and(|a| a == tx_q.last_avail_idx);
                        // RX is idle if there are no pending buffers with
                        // data to inject or we've already processed all of
                        // them.  An empty backlog means no pending work on
                        // the RX side regardless of how many empty buffers
                        // the guest has posted.
                        let rx_idle = console.rx_backlog.is_empty()
                            || !rx_q.ready
                            || rx_q.num == 0
                            || read_avail_idx(&self.memory, RAM_BASE, rx_q.avail_addr)
                                .is_some_and(|a| a == rx_q.last_avail_idx);
                        if tx_idle && rx_idle {
                            crate::vmm_trace::write_console_io(format_args!(
                                "CONSOLE_ORPHAN_IRQ_CLEAR irq={} tx_avail={} rx_avail={}",
                                console.interrupt_status,
                                tx_q.last_avail_idx,
                                rx_q.last_avail_idx,
                            ));
                            console.interrupt_status = 0;
                            console.irq_acked = false;
                            Vm::set_gic_spi(VIRTIO_CONSOLE_SPI, false);
                            Self::write_guest_register(vcpu, rt, 0)?;
                            return Ok(());
                        }
                    }
                    Self::write_guest_register(vcpu, rt, value)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
            // Process TX output after releasing the borrow on self.virtio_console
            if !tx_bytes.is_empty()
                && self.boot_complete
                && self.command_injected
                && self.poll_stdin(stdin_fd, stdin_eof)
            {
                let _ = Vcpu::force_exit(&[vcpu.id() as u64]);
            }
            if !tx_bytes.is_empty() {
                self.process_console_tx(&tx_bytes);
            }
        }
        // Virtio-net MMIO region
        else if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + VIRTIO_NET_SIZE).contains(&fault_addr) {
            let offset = fault_addr - VIRTIO_NET_BASE;
            if let Some(ref mut net) = self.virtio_net {
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(queue_idx) = net.mmio_write(offset, value) {
                        // QueueNotify — process the notified queue
                        if queue_idx == 1 {
                            // TX queue notification
                            if net.process_tx(&mut self.memory, RAM_BASE) {
                                Vm::set_gic_spi(VIRTIO_NET_SPI, true);
                            }
                        }
                    }
                    // After InterruptACK, deassert SPI if no more pending interrupts
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = VIRTIO_NET_BASE;
                        if net.interrupt_status == 0 {
                            Vm::set_gic_spi(VIRTIO_NET_SPI, false);
                        }
                    }
                } else {
                    let value = net.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else {
                // No virtio-net device — return 0 for reads
                if !is_write {
                    Self::write_guest_register(vcpu, rt, 0)?;
                }
            }
        }
        // Virtio-blk MMIO region
        else if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + VIRTIO_BLK_SIZE).contains(&fault_addr) {
            let offset = fault_addr - VIRTIO_BLK_BASE;
            if let Some(ref mut blk) = self.virtio_blk {
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(_queue_idx) = blk.mmio_write(offset, value) {
                        // QueueNotify — process the request and complete it.
                        crate::vmm_trace::write_console_io(format_args!("BLK_QNOTIFY"));
                        blk.process_queue(&mut self.memory, RAM_BASE);
                        if blk.interrupt_status != 0 {
                            Vm::set_gic_spi(VIRTIO_BLK_SPI, true);
                        }
                    }
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = VIRTIO_BLK_BASE;
                        crate::vmm_trace::write_console_io(format_args!(
                            "BLK_ACK irq={}", blk.interrupt_status
                        ));
                        if blk.interrupt_status == 0 {
                            Vm::set_gic_spi(VIRTIO_BLK_SPI, false);
                        }
                    }
                } else {
                    let value = blk.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
        }
        // Data block MMIO region (overlay disk)
        else if (DATA_BLK_BASE..DATA_BLK_BASE + DATA_BLK_SIZE).contains(&fault_addr) {
            let offset = fault_addr - DATA_BLK_BASE;
            if let Some(ref mut dev) = self.data_blk {
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(_queue_idx) = dev.mmio_write(offset, value) {
                        // QueueNotify — process the request and complete it.
                        crate::vmm_trace::write_console_io(format_args!("DATABLK_QNOTIFY"));
                        dev.process_queue(&mut self.memory, RAM_BASE);
                        if dev.interrupt_status != 0 {
                            Vm::set_gic_spi(DATA_BLK_SPI, true);
                        }
                    }
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = DATA_BLK_BASE;
                        crate::vmm_trace::write_console_io(format_args!(
                            "DATABLK_ACK irq={}", dev.interrupt_status
                        ));
                        if dev.interrupt_status == 0 {
                            Vm::set_gic_spi(DATA_BLK_SPI, false);
                        }
                    }
                } else {
                    let value = dev.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
        }
        // Virtio-rng MMIO region
        else if (VIRTIO_RNG_BASE..VIRTIO_RNG_BASE + VIRTIO_RNG_SIZE).contains(&fault_addr) {
            let offset = fault_addr - VIRTIO_RNG_BASE;
            if let Some(ref mut rng) = self.virtio_rng {
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(_queue_idx) = rng.mmio_write(offset, value) {
                        // QueueNotify — fill buffers with random data
                        rng.process_queue(&mut self.memory, RAM_BASE);
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, rng.interrupt_status != 0);
                    }
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = VIRTIO_RNG_BASE;
                        if rng.interrupt_status == 0 {
                            Vm::set_gic_spi(VIRTIO_RNG_SPI, false);
                        }
                    }
                } else {
                    let value = rng.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
        }
        // Virtiofs MMIO regions (shared filesystem devices)
        else if fault_addr >= VIRTIOFS_BASE_START
            && fault_addr < VIRTIOFS_BASE_START + (MAX_FS_DEVICES as u64) * VIRTIOFS_SIZE
        {
            let dev_idx = ((fault_addr - VIRTIOFS_BASE_START) / VIRTIOFS_SIZE) as usize;
            let dev_base = VIRTIOFS_BASE_START + (dev_idx as u64) * VIRTIOFS_SIZE;
            let offset = fault_addr - dev_base;

            if dev_idx < self.virtiofs.len() {
                let spi = VIRTIOFS_SPI_START + dev_idx as u32;
                let dev = &mut self.virtiofs[dev_idx];
                if is_write {
                    let value = Self::read_guest_register(vcpu, rt)? as u32;
                    if let Some(queue_idx) = dev.mmio_write(offset, value) {
                        if dev.process_queue(queue_idx, &mut self.memory, RAM_BASE) {
                            Vm::set_gic_spi(spi, true);
                        }
                    }
                    if offset == REG_INTERRUPT_ACK {
                        self.irq_ack_device = dev_base;
                        if dev.interrupt_status == 0 {
                            Vm::set_gic_spi(spi, false);
                        }
                    }
                } else {
                    let value = dev.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
        }
        // SP804 Dual-Timer MMIO region
        else if (SP804_BASE..SP804_BASE + 0x1000).contains(&fault_addr) {
            let offset = fault_addr - SP804_BASE;
            if is_write {
                let value = Self::read_guest_register(vcpu, rt)? as u32;
                crate::vmm_trace::write_console_io(format_args!(
                    "SP804_WR off=0x{offset:x} val=0x{value:x} pc=0x{:x}",
                    vcpu.read_register(HvReg::Pc).unwrap_or(0)
                ));
                let irq_was_pending = self.sp804.mmio_read(0x10) != 0; // RIS
                self.sp804.mmio_write(offset, value);
                let irq_is_pending = self.sp804.mmio_read(0x10) != 0;
                // De-assert GIC SPI whenever the timer IRQ was cleared by any
                // write (IntClr, TimerLoad w/ timer enabled, TimerControl enable).
                // Without this the SPI stays asserted while irq_pending1=0,
                // causing spurious interrupts that can accumulate and cause
                // the kernel to disable the interrupt line.
                if irq_was_pending && !irq_is_pending {
                    Vm::set_gic_spi(SP804_SPI_1, false);
                }
            } else {
                let value = self.sp804.mmio_read(offset);
                Self::write_guest_register(vcpu, rt, value as u64)?;
            }
        }
        // GIC distributor region (0x08000000 - 0x0800FFFF)
        else if (0x08000000..0x08010000).contains(&fault_addr) {
            if !is_write {
                // GIC distributor reads - return reasonable defaults
                let value = match fault_addr - 0x08000000 {
                    0x0000 => 0x00000000, // GICD_CTLR
                    0x0004 => 0x0000001F, // GICD_TYPER: ITLinesNumber=31, CPUNumber=0
                    0x0008 => 0x0200043B, // GICD_IIDR: GICv2
                    _ => 0x00000000,
                };
                Self::write_guest_register(vcpu, rt, value)?;
            }
            // GIC writes - silently ignored
        }
        // GIC redistributor region (0x080A0000 - 0x080BFFFF) or
        // GIC CPU interface (0x08010000 - 0x0801FFFF)
        else if (0x080A0000..0x080C0000).contains(&fault_addr)
            || (0x08010000..0x08020000).contains(&fault_addr)
        {
            if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
        }
        // Unknown MMIO
        else {
            if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
            }
            // Log first few unknown MMIO accesses
            static mut UNKNOWN_MMIO_COUNT: u64 = 0;
            unsafe {
                UNKNOWN_MMIO_COUNT += 1;
                if UNKNOWN_MMIO_COUNT <= 20 {
                    warn!(
                        "[MMIO] Unknown {} to 0x{:x} (X{}) at PC=0x{:x}",
                        if is_write { "WRITE" } else { "READ" },
                        fault_addr,
                        rt,
                        pc
                    );
                }
            }
        }

        Ok(())
    }

    /// Walk guest page tables to translate VA to PA
    /// For TTBR1_EL1 (kernel addresses starting with 0xFFFF...)
    fn translate_va_to_pa(&self, va: u64, ttbr1: u64, t1sz: u64) -> Option<u64> {
        // ARM64 4KB page table walk
        // Extract table base from TTBR1 (mask off ASID in bits[63:48] and page offset)
        let table_base = ttbr1 & 0x0000_FFFF_FFFF_F000;

        // VA bits used: 64 - T1SZ
        let va_bits = 64 - t1sz;
        let va_mask = (1u64 << va_bits) - 1;
        let input_addr = va & va_mask;

        // Calculate starting level based on VA bits:
        // 48-bit VA (T1SZ=16): start at level 0 (4 levels)
        // 39-bit VA (T1SZ=25): start at level 1 (3 levels)
        // 30-bit VA (T1SZ=34): start at level 2 (2 levels)
        let start_level = if va_bits <= 30 {
            2u64
        } else if va_bits <= 39 {
            1u64
        } else {
            0u64
        };

        let mut table_addr = table_base;

        for level in start_level..4 {
            let shift = (3 - level) * 9 + 12; // L3=12, L2=21, L1=30, L0=39
            let index = (input_addr >> shift) & 0x1FF;
            let entry_addr = table_addr + index * 8;

            // Read entry from guest memory
            if entry_addr < RAM_BASE || entry_addr + 8 > RAM_BASE + self.memory_size as u64 {
                return None;
            }

            let offset = (entry_addr - RAM_BASE) as usize;
            if offset + 8 > self.memory_size {
                return None;
            }

            let entry = u64::from_le_bytes(self.memory[offset..offset + 8].try_into().ok()?);

            // Check if entry is valid
            if entry & 1 == 0 {
                return None;
            }

            if level < 3 {
                // Check if it's a block entry (bit 1 = 0 for block, 1 for table)
                if entry & 2 == 0 {
                    // Block entry
                    let block_size = 1u64 << shift;
                    let block_base = entry & !(block_size - 1) & 0x0000FFFFFFFFFFFF;
                    let page_offset = input_addr & (block_size - 1);
                    return Some(block_base | page_offset);
                }
                // Table entry - get next level table address
                table_addr = entry & 0x0000FFFFFFFFF000;
            } else {
                // Level 3 - page entry
                let page_base = entry & 0x0000FFFFFFFFF000;
                let page_offset = input_addr & 0xFFF;
                return Some(page_base | page_offset);
            }
        }

        None
    }

    /// Dump CPU register state for debugging
    fn dump_registers(&self, vcpu: &Vcpu) -> Result<()> {
        error!("Register dump:");
        for i in 0..=30 {
            let val = Self::read_guest_register(vcpu, i)?;
            if val != 0 {
                error!("  X{i:<2} = 0x{val:016x}");
            }
        }
        let pc = vcpu.read_register(HvReg::Pc)?;
        let cpsr = vcpu.read_register(HvReg::Cpsr)?;
        error!("  PC   = 0x{pc:016x}");
        error!("  CPSR = 0x{:016x} (EL{})", cpsr, cpsr & 0xF);

        let sctlr = vcpu.read_sys_register(HvSysReg::SctlrEl1).unwrap_or(0);
        let elr = vcpu.read_sys_register(HvSysReg::ElrEl1).unwrap_or(0);
        let vbar = vcpu.read_sys_register(HvSysReg::VbarEl1).unwrap_or(0);
        error!("  SCTLR_EL1 = 0x{sctlr:x}");
        error!("  ELR_EL1   = 0x{elr:x}");
        error!("  VBAR_EL1  = 0x{vbar:x}");

        Ok(())
    }
}

/// Resolve a default data path by searching relative to the executable directory,
/// then two levels up (for target/release/sandal -> project root), then CWD.
pub fn resolve_data_path(relative: &str) -> Option<PathBuf> {
    if let Ok(exe) = env::current_exe() {
        // Use parent() directly instead of canonicalize() to avoid the
        // expensive realpath() syscall chain (resolves every symlink
        // component).  For finding sibling data files, the raw exe
        // directory is sufficient.
        if let Some(exe_dir) = exe.parent() {
            let path = exe_dir.join(relative);
            if path.exists() {
                return Some(path);
            }
            // Try two levels up (e.g. target/release/sandal -> project root)
            if let Some(project_dir) = exe_dir.parent().and_then(|d| d.parent()) {
                let path = project_dir.join(relative);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }
    let path = PathBuf::from(relative);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

pub fn run(args: Args) -> Result<()> {
    info!("Creating VM with {} MB memory", args.memory);
    debug!("Command: {:?}", args.command);

    let network_enabled = !args.no_network;

    // Create and set up VM
    let mut vm = VmInstance::new(args.memory)?;
    vm.network_enabled = network_enabled;
    vm.setup()?;

    // Set up networking (enabled by default)
    if network_enabled {
        info!("Initializing network...");

        let backend = UserNet::new().context("Failed to create user-space network")?;

        let mac = backend.mac_address();
        debug!(
            "Guest MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        // Build the network filter from CLI args
        let filter = {
            let mut f = NetworkFilter::new();
            f.set_protocols(NetworkFilter::parse_protocols(&args.protocols));
            if let Some(ref hosts) = args.allowed_hosts {
                f.set_allowed_hosts(NetworkFilter::parse_hosts(hosts));
            }
            f
        };

        let device = VirtioNetDevice::new(backend, filter);
        vm.virtio_net = Some(device);
    }

    // Resolve kernel path (default: vmlinux-sandal)
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => resolve_data_path("vmlinux-sandal").ok_or_else(|| {
            anyhow::anyhow!("No kernel found. Use --kernel or run: scripts/setup-image.sh")
        })?,
    };

    // Read kernel once and reuse for detection and loading
    let kernel_data = fs::read(&kernel_path)?;

    // Check kernel capabilities to decide rootfs strategy.
    // Prefer virtio-blk when the kernel supports it: mounting /dev/vda directly
    // avoids the ext2-to-cpio conversion on the host and initramfs unpacking
    // in the guest, saving ~10-20ms on cold start.
    let prefer_virtio_blk = kernel_data.windows(10).any(|w| w == b"virtio_blk");

    // Parse and set up shared directories (virtiofs).
    // We always create MAX_FS_DEVICES VirtioFsDevice instances so the
    // kernel probes every slot during cold boot, producing a snapshot
    // that is reusable regardless of --share arguments.
    let mut shares: Vec<(String, String)> = Vec::new(); // (mount_tag, guest_path)
    for (i, share_spec) in args.shared_dirs.iter().enumerate() {
        if i >= MAX_FS_DEVICES {
            anyhow::bail!("Too many shared directories (max {})", MAX_FS_DEVICES);
        }
        let (host_str, guest_str) = share_spec.split_once(':').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid --share format: {share_spec:?} (expected host_path:guest_path)"
            )
        })?;
        let host_path = PathBuf::from(host_str);
        if !host_path.exists() {
            anyhow::bail!("Shared path does not exist: {host_str:?}");
        }
        if !host_path.is_dir() {
            anyhow::bail!(
                "Shared path is not a directory: {host_str:?} (only directories are supported)"
            );
        }
        let mount_tag = format!("share{i}");
        let guest_path = guest_str.to_string();
        info!("Sharing {host_str:?} -> {guest_str} (tag={mount_tag})");
        vm.virtiofs
            .push(VirtioFsDevice::new(host_path, mount_tag.clone()));
        shares.push((mount_tag, guest_path));
    }
    // Fill remaining virtiofs slots with stub devices so the kernel
    // probes all MAX_FS_DEVICES during cold boot.  The stubs use "/"
    // as root_path but are never mounted, so no files are exposed.
    for i in args.shared_dirs.len()..MAX_FS_DEVICES {
        let mount_tag = format!("share{i}");
        vm.virtiofs
            .push(VirtioFsDevice::new(PathBuf::from("/"), mount_tag));
    }

    // Load initrd/rootfs (must be done before load_kernel, because load_kernel builds DTB)
    // Resolution order: --rootfs flag > rootfs.ext2 next to binary > built-in rootfs
    let default_rootfs = if args.rootfs.is_none() {
        resolve_data_path("rootfs.ext2")
    } else {
        None
    };
    let rootfs_arg = args.rootfs.as_ref().or(default_rootfs.as_ref());

    let mut disk_image = if let Some(rootfs_path) = rootfs_arg {
        if !rootfs_path.is_file() {
            anyhow::bail!(
                "--rootfs path {rootfs_path:?} is not a file (use `sandal pack <dir>` to create an ext2 image)"
            );
        }
        info!("Loading ext2 rootfs from {rootfs_path:?}...");
        fs::read(rootfs_path)
            .with_context(|| format!("Failed to read rootfs image {rootfs_path:?}"))?
    } else {
        info!("Using built-in rootfs");
        rootfs::load()
    };
    debug!(
        "ext2 image: {} bytes ({} KB)",
        disk_image.len(),
        disk_image.len() / 1024
    );

    {
        // Inject runtime files (/init, device nodes, CA certs, etc.)
        ext2::inject_runtime_files(&mut disk_image, network_enabled)
            .context("Failed to inject runtime files into ext2 image")?;

        if prefer_virtio_blk {
            // Fast path: kernel supports virtio-blk — load ext2 directly
            info!("Loading ext2 on virtio-blk...");
            vm.virtio_blk = Some(VirtioBlkDevice::new(disk_image));
            vm.use_virtio_blk = true;
        } else {
            // Fallback: kernel only supports initramfs — convert ext2 to cpio
            info!("Converting ext2 to cpio for initramfs...");
            let cpio_data =
                ext2::ext2_to_cpio(&disk_image).context("Failed to convert ext2 to cpio")?;
            debug!(
                "cpio archive: {} bytes ({} KB)",
                cpio_data.len(),
                cpio_data.len() / 1024
            );
            vm.load_initrd(&cpio_data)?;
        }
    }
    if let Some(initrd_path) = &args.initrd {
        info!("Loading initrd from {initrd_path:?}...");
        let initrd_data = initramfs::load_initrd(initrd_path).context("Failed to load initrd")?;
        vm.load_initrd(&initrd_data)?;
    }

    // Always provide a virtio-rng device for guest entropy
    vm.virtio_rng = Some(VirtioRngDevice::new());

    // Always provide a virtio-console device for interactive terminal I/O (hvc0)
    vm.virtio_console = Some(VirtioConsoleDevice::new(80, 24));

    // Always create a second virtio-blk device so the kernel probes /dev/vdb
    // during cold boot.  This ensures the same snapshot works regardless of
    // whether --disk-size or --layer is specified on subsequent warm restores.
    // On warm restore the data_blk is replaced with fresh layer/disk content
    // and a config change SPI is fired to notify the kernel of the new capacity.
    {
        let disk_image = build_data_disk(&args.layers, args.disk_size)?;
        vm.data_blk = Some(VirtioBlkDevice::new(disk_image));
    }

    // Load kernel (this also builds the device tree, which needs initrd info)
    vm.load_kernel(&kernel_data)?;

    // Determine disk mode for the init binary.
    // With the compiled init, layer-only mode is converted to ext2 on the host
    // side, so the guest always sees either "disk" (ext2) or nothing (tmpfs).
    let disk_mode = if args.disk_size.is_some() || !args.layers.is_empty() {
        Some("disk")
    } else {
        None
    };

    // Store init config for the BRK #INIT_CONFIG hypercall handler.
    vm.init_disk_mode = disk_mode.map(|s| s.to_string());
    vm.init_shares = shares.clone();
    vm.init_command = args.command.clone();
    vm.init_network = network_enabled;

    // Compute fingerprint for snapshot caching.
    // Uses content-based hashing (first/last 4KB) — same as the fast
    // path in try_snapshot_restore, so saved snapshots are found on
    // subsequent runs.
    let kernel_fp = snapshot::hash_file_content(&kernel_path);
    let rootfs_fp = if let Some(p) = rootfs_arg {
        snapshot::hash_file_content(p)
    } else {
        snapshot::hash_bytes(rootfs::BUILTIN_ROOTFS_GZ)
    };
    let fingerprint =
        snapshot::compute_fingerprint(kernel_fp, rootfs_fp, args.memory, network_enabled);
    vm.snapshot_fingerprint = fingerprint;

    if !args.no_cache {
        // Enable snapshot save when the snapshot doesn't already exist.
        // Virtiofs is supported: the mount is deferred to after BRK #INIT_CONFIG,
        // so no FUSE session is active at snapshot time.  On restore, fresh
        // VirtioFsDevice instances are created from --share args.
        if let Ok(snap_path) = snapshot::snapshot_path(fingerprint) {
            if !snap_path.exists() {
                vm.snapshot_save_path = Some(snap_path);
            }
        }
        // Cold boot means no valid snapshot was found — clean up stale
        // snapshots from previous cache versions so they don't pile up.
        snapshot::gc_stale_snapshots(fingerprint);
    }

    // Run the VM
    let exit_code = vm.run_command(&args.command)?;

    debug!("VM exited with code: {exit_code}");

    process::exit(exit_code);
}

/// Fast-path: restore a VM from a snapshot file and run a command.
pub fn run_from_snapshot(args: &Args, snap_path: &Path, fingerprint: u64) -> Result<()> {
    let t0 = Instant::now();

    info!("Restoring VM from snapshot...");

    let snapshot = snapshot::load_snapshot(snap_path, fingerprint)?;
    debug!(
        "[bench] load_snapshot (COW mmap): {:.2}ms",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // GIC state is required for reliable restore — without it the GIC
    // starts fresh, UART interrupts are never routed, and the guest hangs.
    if snapshot.device_state.gic_state.is_none() {
        anyhow::bail!("Snapshot missing GIC state (macOS 15.0+ required for snapshot restore)");
    }

    let network_enabled = snapshot.device_state.network_enabled;
    let memory_size = snapshot.memory_size;

    // Initialize hypervisor subsystem
    let t1 = Instant::now();
    hypervisor::init().context("Failed to initialize hypervisor")?;
    debug!(
        "[bench] hypervisor::init: {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Create VM (this also creates the GIC)
    let t1 = Instant::now();
    let vm_handle = Vm::new().context("Failed to create VM")?;
    debug!(
        "[bench] Vm::new (+ GIC): {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Use the COW (MAP_PRIVATE) memory directly from the snapshot — no
    // 256 MB memcpy.  Pages are faulted lazily and only copied when the
    // guest writes to them.
    let SnapshotRestore {
        mut memory,
        cpu_state: snapshot_cpu_state,
        device_state: snapshot_device_state,
        ..
    } = snapshot;

    // Map memory into guest
    let t1 = Instant::now();
    vm_handle.map_memory(
        memory.as_mut_ptr() as *mut c_void,
        RAM_BASE,
        memory_size,
        HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
    )?;
    debug!(
        "[bench] map_memory: {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Restore virtio-net device
    let t1 = Instant::now();
    let virtio_net = if network_enabled {
        let backend = UserNet::new().context("Failed to create user-space network")?;
        let filter = {
            let mut f = NetworkFilter::new();
            f.set_protocols(NetworkFilter::parse_protocols(&args.protocols));
            if let Some(ref hosts) = args.allowed_hosts {
                f.set_allowed_hosts(NetworkFilter::parse_hosts(hosts));
            }
            f
        };

        let mut device = VirtioNetDevice::new(backend, filter);

        // Restore MMIO state from snapshot
        if let Some(ref mmio) = snapshot_device_state.net_mmio {
            device.device_features_sel = mmio.device_features_sel;
            device.driver_features = mmio.driver_features;
            device.driver_features_sel = mmio.driver_features_sel;
            device.queue_sel = mmio.queue_sel;
            device.status = mmio.status;
            device.interrupt_status = mmio.interrupt_status;
            device.config_generation = mmio.config_generation;
            for (i, q) in mmio.queues.iter().enumerate() {
                if i < device.queues.len() {
                    device.queues[i].num_max = q.num_max;
                    device.queues[i].num = q.num;
                    device.queues[i].ready = q.ready != 0;
                    device.queues[i].desc_addr = q.desc_addr;
                    device.queues[i].avail_addr = q.avail_addr;
                    device.queues[i].used_addr = q.used_addr;
                    device.queues[i].last_avail_idx = q.last_avail_idx;
                }
            }
        }
        Some(device)
    } else {
        None
    };

    // Restore virtio-rng device
    let mut virtio_rng = VirtioRngDevice::new();
    if let Some(ref mmio) = snapshot_device_state.rng_mmio {
        virtio_rng.device_features_sel = mmio.device_features_sel;
        virtio_rng.driver_features = mmio.driver_features;
        virtio_rng.driver_features_sel = mmio.driver_features_sel;
        virtio_rng.queue_sel = mmio.queue_sel;
        virtio_rng.status = mmio.status;
        virtio_rng.interrupt_status = mmio.interrupt_status;
        for (i, q) in mmio.queues.iter().enumerate() {
            if i < virtio_rng.queues.len() {
                virtio_rng.queues[i].num_max = q.num_max;
                virtio_rng.queues[i].num = q.num;
                virtio_rng.queues[i].ready = q.ready != 0;
                virtio_rng.queues[i].desc_addr = q.desc_addr;
                virtio_rng.queues[i].avail_addr = q.avail_addr;
                virtio_rng.queues[i].used_addr = q.used_addr;
                virtio_rng.queues[i].last_avail_idx = q.last_avail_idx;
            }
        }
    }

    debug!(
        "[bench] restore net+rng devices: {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Restore virtio-blk device (load saved disk image)
    let t1 = Instant::now();
    let (virtio_blk, use_virtio_blk) = if snapshot_device_state.use_virtio_blk {
        let disk_path = snapshot::disk_image_path(fingerprint)?;
        if !disk_path.exists() {
            anyhow::bail!(
                "Snapshot requires disk image but {} not found",
                disk_path.display()
            );
        }
        let disk_image = fs::read(&disk_path).context("Failed to read snapshot disk image")?;
        debug!(
            "Disk image loaded ({} MB)",
            disk_image.len() / (1024 * 1024)
        );

        let mut device = VirtioBlkDevice::new(disk_image);

        // Restore MMIO state from snapshot
        if let Some(ref mmio) = snapshot_device_state.blk_mmio {
            device.device_features_sel = mmio.device_features_sel;
            device.driver_features = mmio.driver_features;
            device.driver_features_sel = mmio.driver_features_sel;
            device.queue_sel = mmio.queue_sel;
            device.status = mmio.status;
            device.interrupt_status = mmio.interrupt_status;
            device.config_generation = mmio.config_generation;
            for (i, q) in mmio.queues.iter().enumerate() {
                if i < device.queues.len() {
                    device.queues[i].num_max = q.num_max;
                    device.queues[i].num = q.num;
                    device.queues[i].ready = q.ready != 0;
                    device.queues[i].desc_addr = q.desc_addr;
                    device.queues[i].avail_addr = q.avail_addr;
                    device.queues[i].used_addr = q.used_addr;
                    device.queues[i].last_avail_idx = q.last_avail_idx;
                }
            }
        }
        (Some(device), true)
    } else {
        (None, false)
    };

    debug!(
        "[bench] restore blk device: {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Restore ALL MAX_FS_DEVICES virtiofs slots from snapshot MMIO state.
    // Real --share args get the actual host path; remaining slots get "/"
    // as a stub (they are never mounted, so no files are exposed).
    let mut virtiofs_devices = Vec::new();
    let mut shares: Vec<(String, String)> = Vec::new();
    for i in 0..MAX_FS_DEVICES {
        let mount_tag = format!("share{i}");
        let host_path = if let Some(share_spec) = args.shared_dirs.get(i) {
            if let Some((host_str, guest_str)) = share_spec.split_once(':') {
                let p = PathBuf::from(host_str);
                if p.is_dir() {
                    shares.push((mount_tag.clone(), guest_str.to_string()));
                    p
                } else {
                    log::warn!("Shared path is not a directory (skipped): {host_str:?}");
                    PathBuf::from("/")
                }
            } else {
                log::warn!("Invalid --share format (skipped): {share_spec:?}");
                PathBuf::from("/")
            }
        } else {
            PathBuf::from("/")
        };
        let mut device = VirtioFsDevice::new(host_path, mount_tag);

        // Restore MMIO state from snapshot
        if let Some(mmio) = snapshot_device_state.fs_mmio.get(i) {
            device.device_features_sel = mmio.device_features_sel;
            device.driver_features = mmio.driver_features;
            device.driver_features_sel = mmio.driver_features_sel;
            device.queue_sel = mmio.queue_sel;
            device.status = mmio.status;
            device.interrupt_status = mmio.interrupt_status;
            device.config_generation = mmio.config_generation;
            for (qi, q) in mmio.queues.iter().enumerate() {
                if qi < device.queues.len() {
                    device.queues[qi].num_max = q.num_max;
                    device.queues[qi].num = q.num;
                    device.queues[qi].ready = q.ready != 0;
                    device.queues[qi].desc_addr = q.desc_addr;
                    device.queues[qi].avail_addr = q.avail_addr;
                    device.queues[qi].used_addr = q.used_addr;
                    device.queues[qi].last_avail_idx = q.last_avail_idx;
                }
            }
        }
        virtiofs_devices.push(device);
    }
    debug!(
        "[bench] restore virtiofs devices ({}): {:.2}ms",
        virtiofs_devices.len(),
        t1.elapsed().as_secs_f64() * 1000.0
    );

    // Determine disk mode for the init binary.
    // With the compiled init, layer-only mode is converted to ext2 on the host
    // side, so the guest always sees either "disk" (ext2) or nothing (tmpfs).
    let has_layers = !args.layers.is_empty();
    let has_disk_size = args.disk_size.is_some();
    let disk_mode = if has_disk_size || has_layers {
        Some("disk")
    } else {
        None
    };

    // Restore virtio-console device
    let mut virtio_console = VirtioConsoleDevice::new(80, 24);
    if let Some(ref mmio) = snapshot_device_state.console_mmio {
        virtio_console.device_features_sel = mmio.device_features_sel;
        virtio_console.driver_features = mmio.driver_features;
        virtio_console.driver_features_sel = mmio.driver_features_sel;
        virtio_console.queue_sel = mmio.queue_sel;
        virtio_console.status = mmio.status;
        virtio_console.interrupt_status = mmio.interrupt_status;
        for (i, q) in mmio.queues.iter().enumerate() {
            if i < virtio_console.queues.len() {
                virtio_console.queues[i].num_max = q.num_max;
                virtio_console.queues[i].num = q.num;
                virtio_console.queues[i].ready = q.ready != 0;
                virtio_console.queues[i].desc_addr = q.desc_addr;
                virtio_console.queues[i].avail_addr = q.avail_addr;
                virtio_console.queues[i].used_addr = q.used_addr;
                virtio_console.queues[i].last_avail_idx = q.last_avail_idx;
            }
        }
    }

    // Build the VmInstance struct with restored state
    // Scan the snapshot memory for an ERET instruction (needed by STUCK_KICK).
    // Do this before constructing VmInstance so `memory` is still borrowable.
    let eret_insn_gpa: Option<u64> = {
        const ERET: u32 = 0xd69f03e0;
        let scan_start = 0x200000usize;
        let scan_end = memory_size.min(64 * 1024 * 1024);
        memory[scan_start..scan_end]
            .chunks_exact(4)
            .position(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()) == ERET)
            .map(|i| RAM_BASE + scan_start as u64 + (i * 4) as u64)
    };
    if eret_insn_gpa.is_some() {
        debug!("ERET instruction found at GPA 0x{:x} (snapshot restore)", eret_insn_gpa.unwrap());
    }

    let mut vm = VmInstance {
        vm: vm_handle,
        memory,
        memory_size,
        kernel_entry: 0, // Not needed for restore
        initrd_info: None,
        exit_code: None,
        boot_complete: true, // Already booted
        boot_complete_iter: 0,
        command_injected: false,
        init_disk_mode: disk_mode.map(|s| s.to_string()),
        init_shares: shares.clone(),
        init_command: args.command.clone(),
        init_network: network_enabled,
        init_config_injected: false,
        forward_output: false, // Set by BRK #INIT_READY after config processing
        snapshot_save_path: None,
        snapshot_fingerprint: fingerprint,
        snapshot_pending: 0,
        restored_cpu_state: Some(snapshot_cpu_state),
        gic_state_to_restore: snapshot_device_state.gic_state,
        uart_line_buf: String::new(),
        uart_suppress_line: false,
        console_out_buf: Vec::with_capacity(4096),
        network_enabled,
        virtio_net,
        virtio_rng: Some(virtio_rng),
        virtio_blk,
        data_blk: None, // Restored below with fresh disk
        data_blk_config_changed: false,
        export_save_path: None,
        virtio_console: Some(virtio_console),
        virtio_console_config_changed: false,
        sp804: Sp804::new(),
        use_virtio_blk,
        virtiofs: virtiofs_devices,
        irq_ack_device: 0,
        consecutive_canceled: 0,
        boot_instant: Instant::now(),
        last_pmr: 0xff,
        sysreg_trap_count: 0,
        counter_trap_count: 0,
        eret_insn_gpa,
        last_vt_advance: Instant::now(),
        guest_idle: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    // Restore second virtio-blk device (overlay disk).  The disk data is
    // ephemeral (fresh ext2 on every run), but the MMIO state must match
    // what the kernel's driver saw during cold boot.
    {
        let disk_image = build_data_disk(&args.layers, args.disk_size)?;
        let mut device = VirtioBlkDevice::new(disk_image);

        // Restore MMIO state from snapshot so the kernel driver stays consistent
        if let Some(ref mmio) = snapshot_device_state.data_blk_mmio {
            device.device_features_sel = mmio.device_features_sel;
            device.driver_features = mmio.driver_features;
            device.driver_features_sel = mmio.driver_features_sel;
            device.queue_sel = mmio.queue_sel;
            device.status = mmio.status;
            device.interrupt_status = mmio.interrupt_status;
            device.config_generation = mmio.config_generation;
            for (i, q) in mmio.queues.iter().enumerate() {
                if i < device.queues.len() {
                    device.queues[i].num_max = q.num_max;
                    device.queues[i].num = q.num;
                    device.queues[i].ready = q.ready != 0;
                    device.queues[i].desc_addr = q.desc_addr;
                    device.queues[i].avail_addr = q.avail_addr;
                    device.queues[i].used_addr = q.used_addr;
                    device.queues[i].last_avail_idx = q.last_avail_idx;
                }
            }
        }

        // If the new disk has a different capacity than the cold-boot stub,
        // signal a virtio config change so the kernel re-reads the size.
        // The interrupt will be delivered when the vCPU resumes.
        if has_disk_size || has_layers {
            device.config_generation = device.config_generation.wrapping_add(1);
            // Bit 1 = config change notification (VIRTIO_MMIO_INT_CONFIG)
            device.interrupt_status |= 2;
            vm.data_blk_config_changed = true;
        }

        vm.data_blk = Some(device);
        if has_layers && has_disk_size {
            info!(
                "Created {}MB overlay disk with {} layer(s) pre-populated",
                args.disk_size.unwrap(),
                args.layers.len()
            );
        } else if has_disk_size {
            info!(
                "Created {}MB overlay disk (/dev/vdb)",
                args.disk_size.unwrap()
            );
        } else if has_layers {
            info!("Loaded {} layer(s) into /dev/vdb", args.layers.len());
        }
    }

    // No inject_command here — the init binary will request config
    // via BRK #INIT_CONFIG after resuming from snapshot.

    debug!(
        "Snapshot restored in {:.2}ms",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // Run the VM from the restored state
    let exit_code = vm.run_command(&args.command)?;

    debug!("VM exited with code: {exit_code}");
    process::exit(exit_code);
}

/// Build the data disk (overlay /dev/vdb) from layers and/or --disk-size.
///
/// Four modes:
///   --disk-size N + --layer: merge layers into N MB ext2 disk (or larger)
///   --disk-size N:           create an N MB ext2 disk
///   --layer:                 create an ext2 disk sized to fit layer content
///   (neither):               1 MB stub
fn build_data_disk(layers: &[PathBuf], disk_size: Option<usize>) -> Result<Vec<u8>> {
    let has_layers = !layers.is_empty();
    let has_disk_size = disk_size.is_some();

    if has_layers {
        let mut all_entries = Vec::new();
        for layer_path in layers {
            let gz_data = fs::read(layer_path)
                .with_context(|| format!("Failed to read layer file: {}", layer_path.display()))?;
            info!(
                "Loading layer: {} ({} bytes)",
                layer_path.display(),
                gz_data.len()
            );
            let entries = tar::read_tar_gz(&gz_data)
                .with_context(|| format!("Failed to parse layer: {}", layer_path.display()))?;
            all_entries.extend(entries);
        }
        let layer_data_size = tar::total_data_size(&all_entries);
        let layer_need_bytes = ((layer_data_size * 2) + 16 * 1024 * 1024).max(16 * 1024 * 1024);
        let final_size = if has_disk_size {
            let disk_size_bytes = disk_size.unwrap() * 1024 * 1024;
            disk_size_bytes.max(layer_need_bytes)
        } else {
            layer_need_bytes
        };
        info!(
            "Creating {}MB disk with {} layer entries (layer data: {} bytes)",
            final_size / (1024 * 1024),
            all_entries.len(),
            layer_data_size,
        );
        let mut image = ext2::create_empty_ext2(final_size)?;
        ext2::inject_tar_entries(&mut image, &all_entries)?;
        Ok(image)
    } else {
        let data_blk_bytes = disk_size.unwrap_or(1) * 1024 * 1024;
        ext2::create_empty_ext2(data_blk_bytes)
    }
}
