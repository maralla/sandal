use crate::cli::Args;
use crate::devicetree::DeviceTree;
use crate::hypervisor::{
    self, HvGicIccReg, HvReg, HvSysReg, Vcpu, Vm, HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE,
};
use crate::net::NetworkFilter;
use crate::snapshot::{
    self, read_cpu_state, CpuState, DeviceState, SnapshotRestore, VirtioMmioSnapshot,
};
use crate::unet::UserNet;
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;
use crate::{ext2, initramfs, rootfs};
use anyhow::{Context, Result};
use log::{debug, error, info, trace, warn};
use memmap2::MmapMut;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Instant;

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

    pub const UART_SPI: u32 = 1;
}

use mem_layout::*;

/// Interrupt state for the 8250/16550 UART emulation.
#[derive(Debug, Default)]
pub(crate) struct Uart8250State {
    /// Interrupt Enable Register: bit 0 = receive data available, bit 1 = THRE.
    ier: u8,
    /// Transmit Holding Register (THR) was written; a THRE (Transmit Holding Register
    /// Empty) interrupt will be raised after the ISR exits.
    thr_written: bool,
    /// THRE interrupt is pending, ready to be reported via IIR (Interrupt Identification
    /// Register).
    thre_pending: bool,
    /// SPI has been asserted to the GIC, waiting for the ISR to acknowledge by reading IIR.
    irq_asserted: bool,
}

/// Interrupt state for the PL011 UART emulation.
#[derive(Debug, Default)]
pub(crate) struct Pl011State {
    /// IMSC (Interrupt Mask Set/Clear): bits set here enable the corresponding interrupt.
    ///   Bit 4: RXIM (receive)
    ///   Bit 5: TXIM (transmit)
    ///   Bit 6: RTIM (receive timeout)
    imsc: u32,
}

/// UART type detected from the kernel binary
#[derive(Debug)]
pub enum UartType {
    /// ARM PL011 UART, the standard ARM serial controller.
    PL011(Pl011State),
    /// 8250/16550-compatible UART, the legacy PC serial standard.
    Uart8250(Uart8250State),
}

pub struct VmInstance {
    vm: Vm,
    memory: MmapMut,
    memory_size: usize,
    uart_type: UartType,
    kernel_entry: u64,
    initrd_info: Option<(u64, u64)>,       // (start GPA, end GPA)
    exit_code: Option<i32>,                // Set when guest signals exit via UART marker
    boot_complete: bool,                   // Set once kernel finishes booting and init runs
    boot_complete_iter: u64,               // Iteration at which boot_complete became true
    command_injected: bool, // Set once the command has been sent to the guest via UART
    pending_mount_setup: Option<String>, // Mount setup line to inject before command
    pending_command: Option<String>, // Shell-escaped command line to inject after BOOT_MARKER
    snapshot_save_path: Option<PathBuf>, // If set, save snapshot after boot
    snapshot_fingerprint: u64, // Fingerprint for the snapshot file
    snapshot_pending: u32,  // Flag: set to 1 by BRK handler to trigger snapshot save
    restored_cpu_state: Option<CpuState>, // If set, restore these registers instead of boot state
    gic_state_to_restore: Option<Vec<u8>>, // GIC state blob to restore after vCPU creation
    is_restored: bool,      // True if VM was restored from a snapshot
    uart_line_buf: String,  // Buffer for current line being received
    uart_suppress_line: bool, // True if rest of line is suppressed (kernel/marker)
    uart_rx_buf: VecDeque<u8>, // Buffered stdin data for the guest to read (shared by both UART types)
    network_enabled: bool,
    virtio_net: Option<VirtioNetDevice>,
    virtio_blk: Option<VirtioBlkDevice>,
    data_blk: Option<VirtioBlkDevice>, // Overlay data disk (--disk-size)
    data_blk_config_changed: bool,     // Trigger config change SPI after GIC restore
    virtio_rng: Option<VirtioRngDevice>,
    virtiofs: Vec<VirtioFsDevice>,
    use_virtio_blk: bool,
}

// ============= Terminal raw mode =============

mod termios {
    use super::RawFd;

    /// Put the terminal in raw mode: disable echo, canonical mode, signals.
    /// Returns the original termios for restoring later.
    pub fn enable_raw_mode(fd: RawFd) -> Option<libc::termios> {
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
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
fn poll_stdin_once(fd: RawFd) -> (bool, bool) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Block up to 1 second then re-check (allows thread to notice shutdown)
    let n = unsafe { libc::poll(&mut pfd, 1, 1000) };
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

    /// Returns true if using the 8250 UART.
    fn is_uart_8250(&self) -> bool {
        matches!(self.uart_type, UartType::Uart8250(_))
    }

    /// Compute PL011 raw interrupt status from current hardware state.
    ///   Bit 4: RXIS — RX FIFO has data
    ///   Bit 5: TXIS — TX FIFO ready (always true — we process TX instantly)
    fn pl011_ris(&self) -> u32 {
        let mut ris = 1u32 << 5; // TXIS: TX always ready
        if !self.uart_rx_buf.is_empty() {
            ris |= 1 << 4; // RXIS: data available
        }
        ris
    }

    /// Update the GIC SPI level for PL011 based on current MIS.
    /// Must be called whenever RIS or IMSC changes.
    fn pl011_update_irq(&self) {
        if let UartType::PL011(ref state) = self.uart_type {
            let mis = self.pl011_ris() & state.imsc;
            Vm::set_gic_spi(UART_SPI, mis != 0);
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
            uart_type: UartType::PL011(Pl011State::default()), // Default, auto-detected in detect_uart_type
            kernel_entry: 0,
            initrd_info: None,
            exit_code: None,
            boot_complete: false,
            boot_complete_iter: 0,
            command_injected: false,
            pending_mount_setup: None,
            pending_command: None,
            snapshot_save_path: None,
            snapshot_fingerprint: 0,
            snapshot_pending: 0,
            restored_cpu_state: None,
            gic_state_to_restore: None,
            is_restored: false,
            uart_line_buf: String::new(),
            uart_suppress_line: false,
            uart_rx_buf: VecDeque::new(),
            network_enabled: false,
            virtio_net: None,
            virtio_blk: None,
            data_blk: None,
            data_blk_config_changed: false,
            virtio_rng: None,
            virtiofs: Vec::new(),
            use_virtio_blk: false,
        })
    }

    /// Detect the UART type from the kernel binary data.
    /// Must be called before building the initramfs if using rootfs.
    pub fn detect_uart_type(&mut self, kernel_data: &[u8]) {
        let has_pl011 = kernel_data.windows(5).any(|w| w == b"pl011");
        let has_8250 = kernel_data.windows(4).any(|w| w == b"8250")
            || kernel_data.windows(10).any(|w| w == b"serial8250");

        if has_8250 && !has_pl011 {
            self.uart_type = UartType::Uart8250(Uart8250State::default());
        } else {
            self.uart_type = UartType::PL011(Pl011State::default());
        }

        debug!(
            "UART type: {:?} (pl011={}, 8250={})",
            self.uart_type, has_pl011, has_8250
        );
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

        let virtio_rng_dt = if self.virtio_rng.is_some() {
            Some((VIRTIO_RNG_BASE, VIRTIO_RNG_SPI))
        } else {
            None
        };

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

        let use_8250 = self.is_uart_8250();
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
            use_8250,
            log::log_enabled!(log::Level::Debug),
            None, // no overlay bootarg — init script detects via /dev/vdb size
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
        let stdin_fd = std::io::stdin().as_raw_fd();
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
            Some(std::thread::spawn(move || {
                Self::stdin_poller(vcpu_id, stdin_fd);
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
            Some(std::thread::spawn(move || poller.run()))
        } else {
            None
        };

        debug!(
            "[bench] run_command ready (tty+threads): {:.2}ms",
            trc.elapsed().as_secs_f64() * 1000.0
        );

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

                // On restore, assert the UART RX interrupt so the
                // guest can read the injected command data.
                if !self.uart_rx_buf.is_empty() {
                    if let UartType::Uart8250(ref state) = self.uart_type {
                        if (state.ier & 0x01) != 0 {
                            Vm::set_gic_spi(UART_SPI, true);
                        }
                    } else {
                        self.pl011_update_irq();
                    }
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

            let exit_reason = match vcpu.run() {
                Ok(r) => r,
                Err(e) => {
                    let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                    error!("hv_vcpu_run error at PC=0x{pc:x}: {e}");
                    return Err(e);
                }
            };

            // Unmask the vtimer after any non-VTIMER exit.
            if exit_reason != 2 {
                vcpu.set_vtimer_mask(false)?;
            }

            match exit_reason {
                0 => {
                    // HV_EXIT_REASON_CANCELED — hv_vcpus_exit() was called
                    // (e.g. by the stdin/network poller to wake a WFI-parked vCPU)
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
                            self.handle_mmio(&vcpu, pc, iss, fault_addr)?;
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
                                // Snapshot-ready signal from sandal-signal.
                                // The guest is in EL0 with IRQs enabled and
                                // no kernel locks — advance past BRK and
                                // trigger snapshot save in this iteration.
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                if self.boot_complete
                                    && !self.command_injected
                                    && self.snapshot_save_path.is_some()
                                {
                                    debug!("Snapshot-ready BRK signal received from guest");
                                    self.snapshot_pending = 1;
                                }
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
                    vcpu.set_vtimer_mask(true)?;
                    vcpu.set_pending_interrupt(0, true)?;
                }

                _ => {
                    warn!("Unknown exit reason: {exit_reason}");
                    break;
                }
            }

            // ── Guest-cooperative snapshot trigger ─────────────────
            // The init script runs sandal-signal which executes
            // BRK #0x5D1 from userspace right before `read`.  The
            // BRK handler sets snapshot_pending=1, and we save HERE
            // — in the same iteration, before the next vcpu.run() —
            // so the guest state is exactly: EL0, IRQs enabled, no
            // kernel locks, PC right after the BRK instruction.
            if self.snapshot_pending > 0 && self.boot_complete && !self.command_injected {
                self.snapshot_pending = 0;
                self.save_snapshot_and_inject(&vcpu, &trc)?;
            }

            // Poll stdin for input and buffer it for the guest UART.
            // Delay until after the command has been injected so that
            // (a) piped data isn't consumed by the kernel's console
            //     driver during init (PL011 polls DR during probe), and
            // (b) stdin EOF (Ctrl-D) doesn't reach the guest's `read`
            //     before the command data when running without a TTY.
            if self.boot_complete && self.command_injected {
                self.poll_stdin(stdin_fd, &mut stdin_eof);
            }

            // Fire UART interrupt if any source is pending.
            {
                if let UartType::Uart8250(ref mut state) = self.uart_type {
                    let rx_pending = !self.uart_rx_buf.is_empty() && (state.ier & 0x01) != 0;
                    let tx_pending =
                        state.thre_pending && (state.ier & 0x02) != 0 && !state.irq_asserted;
                    if rx_pending || tx_pending {
                        if tx_pending {
                            state.irq_asserted = true;
                        }
                        Vm::set_gic_spi(UART_SPI, true);
                    }
                } else {
                    // PL011: update IRQ level based on current state.
                    // Asserts SPI when MIS != 0, deasserts when MIS == 0.
                    self.pl011_update_irq();
                }
            }

            // Poll network backend and deliver incoming packets to guest RX queue
            if let Some(ref mut net) = self.virtio_net {
                net.poll_backend();
                if net.process_rx(&mut self.memory, RAM_BASE) {
                    Vm::set_gic_spi(VIRTIO_NET_SPI, true);
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
            let line = std::mem::take(&mut self.uart_line_buf);
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
    /// Uses poll() to block until stdin has data, then kicks the vcpu.
    /// Exits when stdin reaches EOF/POLLHUP or an error occurs.
    fn stdin_poller(vcpu_id: u64, stdin_fd: RawFd) {
        loop {
            let (ready, hungup) = poll_stdin_once(stdin_fd);
            if ready || hungup {
                Vcpu::force_exit(&[vcpu_id]).ok();
            }
            if hungup {
                break;
            }
        }
    }

    /// Read available bytes from host stdin into the UART RX buffer.
    /// When stdin reaches EOF (pipe closed), sends Ctrl-D (0x04) so the
    /// guest's TTY layer signals end-of-file to user-space readers.
    fn poll_stdin(&mut self, stdin_fd: RawFd, stdin_eof: &mut bool) {
        if *stdin_eof {
            return;
        }
        let mut buf = [0u8; 256];
        let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            for &b in &buf[..n as usize] {
                self.uart_rx_buf.push_back(b);
            }
        } else if n == 0 {
            // EOF — send Ctrl-D to guest
            self.uart_rx_buf.push_back(0x04);
            *stdin_eof = true;
        }
        // n < 0 → EAGAIN (no data), ignore
    }

    /// Process a complete line of UART output.
    /// Extracts exit code marker and detects boot completion.
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

        // Detect boot completion — the init script prints this marker
        // right before reading the command from the UART.
        // Skip on restored VMs: boot is already complete and the command
        // has been injected.  Without this guard, user command output that
        // happens to contain BOOT_MARKER would re-trigger inject_command
        // (harmless but wasteful) and log misleading messages.
        if !self.is_restored && trimmed.contains(initramfs::BOOT_MARKER) {
            self.boot_complete = true;
            // boot_complete_iter is set by the caller (run_command) after calling process_uart_line
            debug!("{trimmed}");

            if self.snapshot_save_path.is_some() {
                // The init script runs sandal-signal which executes
                // BRK #0x5D1.  The VMM traps the BRK from EL0 and
                // saves the snapshot in the same iteration.
                debug!("BOOT_MARKER detected, waiting for BRK snapshot signal");
            } else {
                // No snapshot saving; inject the command immediately.
                self.inject_command();
            }
            return;
        }

        // Before boot is complete: only show in debug mode
        if !self.boot_complete {
            debug!("{trimmed}");
        }

        // After boot: characters were already written directly to stdout
        // by the UART write handler, so nothing more to print here.
    }

    /// Inject the pending command into the UART RX buffer so the guest
    /// init script's `read` call receives it.
    fn inject_command(&mut self) {
        if self.command_injected {
            return;
        }
        if let Some(mount_setup) = self.pending_mount_setup.take() {
            // Line 1: mount setup commands (may be empty)
            debug!("Injecting mount setup via UART: {mount_setup}");
            for byte in mount_setup.as_bytes() {
                self.uart_rx_buf.push_back(*byte);
            }
            self.uart_rx_buf.push_back(b'\n');
        }
        if let Some(cmd_line) = self.pending_command.take() {
            // Line 2: the actual command
            debug!("Injecting command via UART: {cmd_line}");
            for byte in cmd_line.as_bytes() {
                self.uart_rx_buf.push_back(*byte);
            }
            self.uart_rx_buf.push_back(b'\n');
            self.command_injected = true;
        }
    }

    /// Save snapshot to disk and inject the pending command into the UART.
    /// Called when the guest signals snapshot-ready via BRK #0x5D1.
    fn save_snapshot_and_inject(&mut self, vcpu: &Vcpu, trc: &Instant) -> Result<()> {
        let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
        debug!("Saving snapshot (PC=0x{pc:x})");

        let Some(ref save_path) = self.snapshot_save_path.clone() else {
            self.inject_command();
            return Ok(());
        };

        let t_total = Instant::now();
        let device_state = self.capture_device_state();
        if device_state.gic_state.is_none() {
            warn!("Skipping snapshot save: GIC state not available (macOS 15.0+ required)");
            self.inject_command();
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
                        match std::fs::write(&tmp, &blk.disk_image) {
                            Ok(()) => {
                                if let Err(e) = std::fs::rename(&tmp, &disk_path) {
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
            "[bench] snapshot+disk: {:.1}ms, inject_command at: {:.0}ms",
            t_total.elapsed().as_secs_f64() * 1000.0,
            trc.elapsed().as_secs_f64() * 1000.0,
        );
        self.inject_command();
        Ok(())
    }

    /// Build the device state snapshot from current device states.
    fn capture_device_state(&self) -> DeviceState {
        let uart_is_8250 = matches!(self.uart_type, UartType::Uart8250(_));
        let uart_8250_ier = if let UartType::Uart8250(ref state) = self.uart_type {
            state.ier
        } else {
            0
        };
        let pl011_imsc = if let UartType::PL011(ref state) = self.uart_type {
            state.imsc
        } else {
            0
        };

        let net_mmio = self.virtio_net.as_ref().map(VirtioMmioSnapshot::from_net);
        let rng_mmio = self.virtio_rng.as_ref().map(VirtioMmioSnapshot::from_rng);
        let blk_mmio = self.virtio_blk.as_ref().map(VirtioMmioSnapshot::from_blk);
        let data_blk_mmio = self.data_blk.as_ref().map(VirtioMmioSnapshot::from_blk);

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
            uart_is_8250,
            uart_8250_ier,
            pl011_imsc,
            network_enabled: self.network_enabled,
            net_mmio,
            rng_mmio,
            blk_mmio,
            use_virtio_blk: self.use_virtio_blk,
            fs_mmio,
            gic_state,
            data_blk_mmio,
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
    fn handle_sysreg_trap(&self, vcpu: &Vcpu, _pc: u64, iss: u64) -> Result<()> {
        let is_read = (iss & 1) != 0; // Bit 0: direction (1=read/MRS, 0=write/MSR)
        let rt = ((iss >> 5) & 0x1F) as u8;

        if is_read {
            // MRS - provide emulated value
            let value = 0u64;
            Self::write_guest_register(vcpu, rt, value)?;
        }
        // MSR writes are silently ignored (trapped regs are usually debug/ICC regs)

        Ok(())
    }

    /// Handle MMIO access (Data Abort)
    fn handle_mmio(&mut self, vcpu: &Vcpu, pc: u64, iss: u64, fault_addr: u64) -> Result<()> {
        let is_write = (iss & (1 << 6)) != 0;
        let _sas = (iss >> 22) & 0x3; // Access size: 0=byte, 1=halfword, 2=word, 3=doubleword
        let rt = ((iss >> 16) & 0x1F) as u8;

        // UART at 0x09000000
        if (UART_BASE..UART_BASE + 0x1000).contains(&fault_addr) {
            let reg_offset = fault_addr - UART_BASE;

            if is_write {
                let value = Self::read_guest_register(vcpu, rt)?;

                // Both PL011 DR and 8250 THR are at offset 0x00
                if reg_offset == 0 {
                    let ch = (value & 0xFF) as u8;

                    if ch.is_ascii() || ch == b'\n' || ch == b'\r' {
                        self.uart_line_buf.push(ch as char);

                        // After boot: write each character directly to stdout
                        // so interactive echo and prompts appear immediately.
                        // Kernel console messages are already suppressed via
                        // the "quiet" boot parameter.  We only need to filter
                        // the exit marker here.
                        if self.boot_complete && !self.uart_suppress_line {
                            let buf_len = self.uart_line_buf.len();
                            let marker = initramfs::EXIT_MARKER.as_bytes();
                            if buf_len <= marker.len()
                                && self.uart_line_buf.as_bytes() == &marker[..buf_len]
                            {
                                // Matches exit marker prefix — keep buffering.
                                // Once fully matched, suppress the rest of the line.
                                if buf_len == marker.len() {
                                    self.uart_suppress_line = true;
                                }
                            } else if buf_len <= marker.len()
                                && buf_len > 1
                                && self.uart_line_buf.as_bytes()[..buf_len - 1]
                                    == marker[..buf_len - 1]
                            {
                                // Was matching marker prefix but diverged —
                                // flush all buffered characters as user output.
                                let buffered = self.uart_line_buf.as_bytes().to_vec();
                                std::io::stdout().write_all(&buffered).ok();
                                std::io::stdout().flush().ok();
                            } else {
                                let out = [ch];
                                std::io::stdout().write_all(&out).ok();
                                std::io::stdout().flush().ok();
                            }
                        }

                        // Process complete lines (for exit marker detection
                        // and pre-boot filtering)
                        if ch == b'\n' {
                            self.uart_suppress_line = false;
                            let line = std::mem::take(&mut self.uart_line_buf);
                            self.process_uart_line(&line);
                        }
                    }
                    // Mark that THR was written.  In our emulation the
                    // character is "transmitted" immediately (written to
                    // host stdout), so the Transmit Holding Register is
                    // empty again.  Set thre_pending directly so the
                    // post-exit interrupt check fires the THRE SPI,
                    // driving the kernel's TTY output path.
                    if let UartType::Uart8250(ref mut state) = self.uart_type {
                        state.thr_written = true;
                        if (state.ier & 0x02) != 0 {
                            state.thre_pending = true;
                        }
                    }
                } else if reg_offset == 0x04 {
                    if let UartType::Uart8250(ref mut state) = self.uart_type {
                        // IER write — track interrupt enable state
                        let old_ier = state.ier;
                        state.ier = value as u8;
                        // If THRE interrupt just enabled, set pending immediately
                        // (TX holding register is always empty in our emulation)
                        if (old_ier & 0x02) == 0 && (state.ier & 0x02) != 0 {
                            state.thre_pending = true;
                        }
                    }
                } else if matches!(self.uart_type, UartType::PL011(_)) {
                    let mut update_irq = false;
                    if let UartType::PL011(ref mut state) = self.uart_type {
                        match reg_offset {
                            // IMSC (Interrupt Mask Set/Clear): enable/disable interrupt
                            // sources.  Changing the mask can make MIS transition
                            // to/from zero, so update the IRQ level afterward.
                            0x38 => {
                                let old_imsc = state.imsc;
                                state.imsc = value as u32;
                                update_irq = true;
                                let rx_len = self.uart_rx_buf.len();
                                let mut ris = 1u32 << 5; // TXIS
                                if rx_len > 0 {
                                    ris |= 1 << 4; // RXIS
                                }
                                let mis = ris & state.imsc;
                                trace!(
                                    "PL011 IMSC: 0x{:x} -> 0x{:x}, RIS=0x{:x}, MIS=0x{:x}, rx_buf={}",
                                    old_imsc, state.imsc, ris, mis, rx_len
                                );
                            }
                            // ICR (Interrupt Clear Register): on real hardware,
                            // write-1-to-clear latches in RIS.  Our RIS is purely
                            // combinational (derived from buffer state), so ICR is
                            // effectively a no-op.  We still update the IRQ level
                            // in case the driver expects the SPI to deassert.
                            0x44 => {
                                update_irq = true;
                            }
                            // Other PL011 registers (LCR_H, CR, IFLS, etc.) - ignored
                            _ => {}
                        }
                    }
                    if update_irq {
                        self.pl011_update_irq();
                    }
                }
                // Other UART registers (control, baud rate, etc.) - ignored
            } else {
                // UART read — handle both PL011 and 8250 register layouts
                let has_rx_data = !self.uart_rx_buf.is_empty();
                let value = if let UartType::Uart8250(ref mut state) = self.uart_type {
                    // 8250/16550 registers (reg-shift=2, so 4-byte aligned)
                    match reg_offset {
                        0x00 => {
                            // RBR: read the next byte from the input buffer.
                            // The RX interrupt clears naturally when the buffer
                            // is drained (checked via is_empty() in the IIR path).
                            self.uart_rx_buf.pop_front().unwrap_or(0) as u64
                        }
                        0x04 => state.ier as u64, // IER: return current state
                        0x08 => {
                            // IIR (Interrupt Identification Register)
                            // Priority: RX data ready > THRE
                            if !self.uart_rx_buf.is_empty() && (state.ier & 0x01) != 0 {
                                // RX data available (ID bits = 10, highest priority).
                                // Reading IIR does NOT clear this — reading RBR does.
                                0xC4u64 // FIFO enabled + RX data available
                            } else if state.thre_pending && (state.ier & 0x02) != 0 {
                                // THRE interrupt pending → report it, clear, and deassert SPI
                                state.thre_pending = false;
                                state.irq_asserted = false;
                                Vm::set_gic_spi(UART_SPI, false);
                                0xC2u64 // FIFO enabled + THRE (ID bits = 01)
                            } else {
                                // No interrupt pending — deassert the SPI line so
                                // the GIC doesn't re-trigger after EOI.
                                Vm::set_gic_spi(UART_SPI, false);
                                state.irq_asserted = false;
                                // If a THR was written, promote it to THRE pending
                                // for the NEXT interrupt cycle.
                                if state.thr_written {
                                    state.thr_written = false;
                                    state.thre_pending = true;
                                }
                                0xC1u64 // FIFO enabled + no interrupt pending
                            }
                        }
                        0x0C => 0x00, // LCR: line control
                        0x10 => 0x00, // MCR: modem control
                        // LSR (Line Status Register):
                        //   Bit 0: DR  (Data Ready) = 1 if rx_buf has data
                        //   Bit 5: THRE (TX Holding Register Empty) = 1
                        //   Bit 6: TEMT (Transmitter Empty) = 1
                        0x14 => {
                            let mut lsr = 0x60u64; // THRE | TEMT
                            if has_rx_data {
                                lsr |= 0x01;
                            } // DR
                            lsr
                        }
                        0x18 => 0x00, // MSR: modem status
                        0x1C => 0x00, // SCR: scratch
                        _ => 0x00,
                    }
                } else if let UartType::PL011(ref state) = self.uart_type {
                    // PL011 registers (ARM PrimeCell UART)
                    // RIS and MIS are computed dynamically from hardware state:
                    //   Bit 4: RXIS — RX FIFO has data
                    //   Bit 5: TXIS — TX FIFO ready (always true)
                    let ris = self.pl011_ris();
                    let mis = ris & state.imsc;

                    match reg_offset {
                        0x00 => {
                            // DR: read the next byte from the input buffer.
                            // After popping, update IRQ level since RXIS may clear.
                            let byte = self.uart_rx_buf.pop_front().unwrap_or(0) as u64;
                            // Deassert SPI immediately if buffer is now empty and
                            // no other masked interrupts remain, preventing an
                            // interrupt storm between the ISR exit and main loop.
                            if self.uart_rx_buf.is_empty() {
                                self.pl011_update_irq();
                            }
                            byte
                        }
                        // FR (Flags Register):
                        //   Bit 4: RXFE (RX FIFO Empty)
                        //   Bit 5: TXFF (TX FIFO Full) — never set
                        //   Bit 7: TXFE (TX FIFO Empty) — always set
                        0x18 => {
                            let mut fr = 0x80u64; // TXFE
                            if !has_rx_data {
                                fr |= 0x10;
                            } // RXFE
                            fr
                        }
                        0x24 => 0x00,              // IBRD: integer baud rate
                        0x28 => 0x00,              // FBRD: fractional baud rate
                        0x2C => 0x00,              // LCR_H: line control
                        0x30 => 0x0301,            // CR: UART enabled, TX enabled, RX enabled
                        0x34 => 0x12,              // IFLS: interrupt FIFO level (default 1/2)
                        0x38 => state.imsc as u64, // IMSC: interrupt mask
                        0x3C => ris as u64,        // RIS: raw interrupt status
                        0x40 => mis as u64,        // MIS: masked interrupt status
                        0x44 => 0x00,              // ICR: write-only, reads as 0
                        0xFE0 => 0x11,             // PeriphID0: PL011 identification
                        0xFE4 => 0x10,             // PeriphID1
                        0xFE8 => 0x34,             // PeriphID2: revision 3, PL011
                        0xFEC => 0x00,             // PeriphID3
                        0xFF0 => 0x0D,             // CellID0 (PrimeCell component ID)
                        0xFF4 => 0xF0,             // CellID1
                        0xFF8 => 0x05,             // CellID2
                        0xFFC => 0xB1,             // CellID3
                        _ => 0x00,
                    }
                } else {
                    0x00
                };
                Self::write_guest_register(vcpu, rt, value)?;
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
                    if offset == crate::virtio::REG_INTERRUPT_ACK && net.interrupt_status == 0 {
                        Vm::set_gic_spi(VIRTIO_NET_SPI, false);
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
                        // QueueNotify — process the request and complete it
                        if blk.process_queue(&mut self.memory, RAM_BASE) {
                            Vm::set_gic_spi(VIRTIO_BLK_SPI, true);
                        }
                    }
                    if offset == crate::virtio::REG_INTERRUPT_ACK && blk.interrupt_status == 0 {
                        Vm::set_gic_spi(VIRTIO_BLK_SPI, false);
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
                        if dev.process_queue(&mut self.memory, RAM_BASE) {
                            Vm::set_gic_spi(DATA_BLK_SPI, true);
                        }
                    }
                    if offset == crate::virtio::REG_INTERRUPT_ACK && dev.interrupt_status == 0 {
                        Vm::set_gic_spi(DATA_BLK_SPI, false);
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
                        if rng.process_queue(&mut self.memory, RAM_BASE) {
                            Vm::set_gic_spi(VIRTIO_RNG_SPI, true);
                        }
                    }
                    if offset == crate::virtio::REG_INTERRUPT_ACK && rng.interrupt_status == 0 {
                        Vm::set_gic_spi(VIRTIO_RNG_SPI, false);
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
                    if offset == crate::virtio::REG_INTERRUPT_ACK && dev.interrupt_status == 0 {
                        Vm::set_gic_spi(spi, false);
                    }
                } else {
                    let value = dev.mmio_read(offset);
                    Self::write_guest_register(vcpu, rt, value as u64)?;
                }
            } else if !is_write {
                Self::write_guest_register(vcpu, rt, 0)?;
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
    if let Ok(exe) = std::env::current_exe() {
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
    let kernel_data = std::fs::read(&kernel_path)?;

    // Detect UART type from kernel (needed for initramfs device nodes)
    vm.detect_uart_type(&kernel_data);

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

    let use_8250 = vm.is_uart_8250();
    let mut disk_image = if let Some(rootfs_path) = rootfs_arg {
        if !rootfs_path.is_file() {
            anyhow::bail!(
                "--rootfs path {rootfs_path:?} is not a file (use `sandal pack <dir>` to create an ext2 image)"
            );
        }
        info!("Loading ext2 rootfs from {rootfs_path:?}...");
        std::fs::read(rootfs_path)
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
        ext2::inject_runtime_files(&mut disk_image, &args.command, network_enabled, use_8250)
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

    // Always create a second virtio-blk device so the kernel probes /dev/vdb
    // during cold boot.  This ensures the same snapshot works regardless of
    // whether --disk-size is specified on subsequent warm restores.
    // With --disk-size: create a real-sized ext2 disk.
    // Without: create a minimal 1MB stub (enough for the kernel to register
    // the device; the init script will fall back to tmpfs overlay).
    {
        let data_blk_bytes = args.disk_size.unwrap_or(1) * 1024 * 1024;
        let disk_image = ext2::create_empty_ext2(data_blk_bytes)?;
        vm.data_blk = Some(VirtioBlkDevice::new(disk_image));
        if let Some(mb) = args.disk_size {
            info!("Created {}MB overlay disk (/dev/vdb)", mb);
        }
    }

    // Load kernel (this also builds the device tree, which needs initrd info)
    vm.load_kernel(&kernel_data)?;

    // Set mount setup + command to be injected via UART after BOOT_MARKER.
    // The init script reads two lines: mount setup, then the command.
    let mount_setup = initramfs::build_mount_setup_line(&shares);
    vm.pending_mount_setup = Some(mount_setup);
    let cmd_line = initramfs::build_command_line(&args.command);
    vm.pending_command = Some(cmd_line.clone());

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
        // Virtiofs is supported: the mount is deferred to after BOOT_MARKER,
        // so no FUSE session is active at snapshot time.  On restore, fresh
        // VirtioFsDevice instances are created from --share args.
        if let Ok(snap_path) = snapshot::snapshot_path(fingerprint) {
            if !snap_path.exists() {
                vm.snapshot_save_path = Some(snap_path);
            }
        }
    }

    // Run the VM
    let exit_code = vm.run_command(&args.command)?;

    debug!("VM exited with code: {exit_code}");

    std::process::exit(exit_code);
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

    // Set up UART type from snapshot, restoring interrupt enable state
    let uart_type = if snapshot_device_state.uart_is_8250 {
        UartType::Uart8250(Uart8250State {
            ier: snapshot_device_state.uart_8250_ier,
            ..Uart8250State::default()
        })
    } else {
        UartType::PL011(Pl011State {
            imsc: snapshot_device_state.pl011_imsc,
        })
    };

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
        let disk_image = std::fs::read(&disk_path).context("Failed to read snapshot disk image")?;
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

    // Build mount setup + command line to inject via UART
    let mount_setup = initramfs::build_mount_setup_line(&shares);
    let cmd_line = initramfs::build_command_line(&args.command);

    // Build the VmInstance struct with restored state
    let mut vm = VmInstance {
        vm: vm_handle,
        memory,
        memory_size,
        uart_type,
        kernel_entry: 0, // Not needed for restore
        initrd_info: None,
        exit_code: None,
        boot_complete: true, // Already booted
        boot_complete_iter: 0,
        command_injected: false,
        pending_mount_setup: Some(mount_setup),
        pending_command: Some(cmd_line),
        snapshot_save_path: None,
        snapshot_fingerprint: fingerprint,
        snapshot_pending: 0,
        restored_cpu_state: Some(snapshot_cpu_state),
        gic_state_to_restore: snapshot_device_state.gic_state,
        is_restored: true,
        uart_line_buf: String::new(),
        uart_suppress_line: false,
        uart_rx_buf: VecDeque::new(),
        network_enabled,
        virtio_net,
        virtio_rng: Some(virtio_rng),
        virtio_blk,
        data_blk: None, // Restored below with fresh disk
        data_blk_config_changed: false,
        use_virtio_blk,
        virtiofs: virtiofs_devices,
    };

    // Restore second virtio-blk device (overlay disk).  The disk data is
    // ephemeral (fresh ext2 on every run), but the MMIO state must match
    // what the kernel's driver saw during cold boot.
    // With --disk-size N: create an N MB disk.
    // Without: create a 1 MB stub (init script will fall back to tmpfs).
    {
        let data_blk_bytes = args.disk_size.unwrap_or(1) * 1024 * 1024;
        let disk_image = crate::ext2::create_empty_ext2(data_blk_bytes)?;
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
        if args.disk_size.is_some() {
            device.config_generation = device.config_generation.wrapping_add(1);
            // Bit 1 = config change notification (VIRTIO_MMIO_INT_CONFIG)
            device.interrupt_status |= 2;
            vm.data_blk_config_changed = true;
        }

        vm.data_blk = Some(device);
        if let Some(mb) = args.disk_size {
            info!("Created {}MB overlay disk (/dev/vdb)", mb);
        }
    }

    // Inject the command into the UART RX buffer.  The snapshot was
    // taken in userspace (EL0) at the BRK instruction — no kernel
    // locks are held and IRQs are enabled.  On resume the guest's
    // sandal-signal process exits, the shell continues to `read`,
    // and the UART driver finds the injected data via normal MMIO reads.
    vm.inject_command();

    debug!(
        "Snapshot restored in {:.2}ms",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // Run the VM from the restored state
    let exit_code = vm.run_command(&args.command)?;

    debug!("VM exited with code: {exit_code}");
    std::process::exit(exit_code);
}
