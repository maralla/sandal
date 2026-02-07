use crate::cli::Args;
use crate::devicetree::DeviceTree;
use crate::hypervisor::{
    self, HvReg, HvSysReg, Vcpu, Vm, HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE,
};
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;
use anyhow::{Context, Result};
use log::{debug, error, info, trace, warn};
use memmap2::MmapMut;
use std::collections::VecDeque;
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};

const RAM_BASE: u64 = 0x40000000; // Match QEMU virt machine
const KERNEL_OFFSET: u64 = 0x80000; // Kernel at RAM + 512KB (standard ARM64 load addr)
const DTB_OFFSET: u64 = 0x8000000; // DTB at RAM + 128MB (well after kernel)
const INITRD_OFFSET: u64 = 0x8100000; // Initrd at RAM + 129MB (after DTB)
const UART_BASE: u64 = 0x09000000; // UART base (PL011 or 8250, auto-detected)

// Virtio-net MMIO region (follows QEMU virt convention)
const VIRTIO_NET_BASE: u64 = 0x0A000000;
const VIRTIO_NET_SIZE: u64 = 0x200;
const VIRTIO_NET_SPI: u32 = 16; // GIC SPI 16 (GIC intid = 48)

// Virtio-blk MMIO region
const VIRTIO_BLK_BASE: u64 = 0x0A000200;
const VIRTIO_BLK_SIZE: u64 = 0x200;
const VIRTIO_BLK_SPI: u32 = 17; // GIC SPI 17

// Virtio-rng MMIO region
const VIRTIO_RNG_BASE: u64 = 0x0A000400;
const VIRTIO_RNG_SIZE: u64 = 0x200;
const VIRTIO_RNG_SPI: u32 = 18; // GIC SPI 18

// UART 8250 interrupt (SPI 1 in DTB → GIC SPI 1)
const UART_SPI: u32 = 1;

/// UART type detected from the kernel binary
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UartType {
    PL011,    // ARM PL011 (used by Debian/Ubuntu kernels, QEMU default)
    Uart8250, // 8250/16550 (used by Firecracker, minimal kernels)
}

pub struct VmInstance {
    vm: Vm,
    memory: MmapMut,
    memory_size: usize,
    uart_type: UartType,
    kernel_entry: u64,
    initrd_info: Option<(u64, u64)>, // (start_gpa, end_gpa)
    exit_code: Option<i32>,          // Set when guest signals exit via UART marker
    boot_complete: bool,             // Set once kernel finishes booting and init runs
    uart_line_buf: String,           // Buffer for current line being received
    network_enabled: bool,
    virtio_net: Option<VirtioNetDevice>,
    virtio_blk: Option<VirtioBlkDevice>,
    virtio_rng: Option<VirtioRngDevice>,
    use_virtio_blk: bool,
    uart_ier: u8,              // 8250 IER: bit 1 = THRE interrupt enable
    uart_thr_written: bool,    // 8250: THR was written, THRE will be raised after ISR exits
    uart_thre_pending: bool,   // 8250: THRE interrupt needs to be delivered (ready for IIR)
    uart_irq_asserted: bool,   // 8250: SPI has been asserted, waiting for ISR to read IIR
    uart_rx_buf: VecDeque<u8>, // Buffered stdin data for the guest to read
    uart_suppress_line: bool,  // True if rest of line is suppressed (kernel/marker)
}

// ============= Terminal raw mode =============

mod termios {
    use std::os::fd::RawFd;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Termios {
        pub c_iflag: u64,
        pub c_oflag: u64,
        pub c_cflag: u64,
        pub c_lflag: u64,
        pub c_cc: [u8; 20],
        pub c_ispeed: u64,
        pub c_ospeed: u64,
    }

    // macOS ioctl constants
    // TIOCGETA = _IOR('t', 19, struct termios) = 0x40487413
    // TIOCSETA = _IOW('t', 20, struct termios) = 0x80487414
    const TIOCGETA: u64 = 0x40487413;
    const TIOCSETA: u64 = 0x80487414;

    // c_lflag bits
    pub const ECHO: u64 = 0x00000008;
    pub const ICANON: u64 = 0x00000100;
    pub const ISIG: u64 = 0x00000080;
    pub const IEXTEN: u64 = 0x00000400;

    // c_iflag bits
    pub const ICRNL: u64 = 0x00000100;
    pub const IXON: u64 = 0x00000200;

    // c_cc indices
    pub const VMIN: usize = 16;
    pub const VTIME: usize = 17;

    extern "C" {
        fn ioctl(fd: RawFd, request: u64, ...) -> i32;
    }

    pub fn get_termios(fd: RawFd) -> Option<Termios> {
        unsafe {
            let mut t: Termios = std::mem::zeroed();
            if ioctl(fd, TIOCGETA, &mut t as *mut Termios) == 0 {
                Some(t)
            } else {
                None
            }
        }
    }

    pub fn set_termios(fd: RawFd, t: &Termios) -> bool {
        unsafe { ioctl(fd, TIOCSETA, t as *const Termios) == 0 }
    }

    /// Put the terminal in raw mode: disable echo, canonical mode, signals.
    /// Returns the original termios for restoring later.
    pub fn enable_raw_mode(fd: RawFd) -> Option<Termios> {
        let orig = get_termios(fd)?;
        let mut raw = orig;
        raw.c_lflag &= !(ECHO | ICANON | ISIG | IEXTEN);
        raw.c_iflag &= !(ICRNL | IXON);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        set_termios(fd, &raw);
        Some(orig)
    }

    pub fn restore_mode(fd: RawFd, orig: &Termios) {
        set_termios(fd, orig);
    }
}

extern "C" {
    fn fcntl(fd: RawFd, cmd: i32, ...) -> i32;
    fn isatty(fd: RawFd) -> i32;
    fn read(fd: RawFd, buf: *mut u8, count: usize) -> isize;
    fn poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32;
}

#[repr(C)]
struct PollFd {
    fd: RawFd,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 0x0001;

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0x0004;

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

fn set_blocking(fd: RawFd) {
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
    }
}

/// Block until stdin has data available (or error/hangup).
/// Returns > 0 if data ready, 0 on timeout (shouldn't happen), < 0 on error.
fn poll_stdin_once(fd: RawFd) -> i32 {
    let mut pfd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    // Block up to 1 second then re-check (allows thread to notice shutdown)
    unsafe { poll(&mut pfd, 1, 1000) }
}

impl VmInstance {
    /// Helper to write to guest register by number (0-31)
    fn write_guest_register(vcpu: &Vcpu, rt: u8, value: u64) -> Result<()> {
        match rt {
            0 => vcpu.write_register(HvReg::X0, value),
            1 => vcpu.write_register(HvReg::X1, value),
            2 => vcpu.write_register(HvReg::X2, value),
            3 => vcpu.write_register(HvReg::X3, value),
            4 => vcpu.write_register(HvReg::X4, value),
            5 => vcpu.write_register(HvReg::X5, value),
            6 => vcpu.write_register(HvReg::X6, value),
            7 => vcpu.write_register(HvReg::X7, value),
            8 => vcpu.write_register(HvReg::X8, value),
            9 => vcpu.write_register(HvReg::X9, value),
            10 => vcpu.write_register(HvReg::X10, value),
            11 => vcpu.write_register(HvReg::X11, value),
            12 => vcpu.write_register(HvReg::X12, value),
            13 => vcpu.write_register(HvReg::X13, value),
            14 => vcpu.write_register(HvReg::X14, value),
            15 => vcpu.write_register(HvReg::X15, value),
            16 => vcpu.write_register(HvReg::X16, value),
            17 => vcpu.write_register(HvReg::X17, value),
            18 => vcpu.write_register(HvReg::X18, value),
            19 => vcpu.write_register(HvReg::X19, value),
            20 => vcpu.write_register(HvReg::X20, value),
            21 => vcpu.write_register(HvReg::X21, value),
            22 => vcpu.write_register(HvReg::X22, value),
            23 => vcpu.write_register(HvReg::X23, value),
            24 => vcpu.write_register(HvReg::X24, value),
            25 => vcpu.write_register(HvReg::X25, value),
            26 => vcpu.write_register(HvReg::X26, value),
            27 => vcpu.write_register(HvReg::X27, value),
            28 => vcpu.write_register(HvReg::X28, value),
            29 => vcpu.write_register(HvReg::Fp, value),
            30 => vcpu.write_register(HvReg::Lr, value),
            31 => Ok(()), // XZR (zero register) - writes are discarded
            _ => Ok(()),
        }
    }

    /// Helper to read from guest register by number (0-31)
    fn read_guest_register(vcpu: &Vcpu, rt: u8) -> Result<u64> {
        match rt {
            0 => vcpu.read_register(HvReg::X0),
            1 => vcpu.read_register(HvReg::X1),
            2 => vcpu.read_register(HvReg::X2),
            3 => vcpu.read_register(HvReg::X3),
            4 => vcpu.read_register(HvReg::X4),
            5 => vcpu.read_register(HvReg::X5),
            6 => vcpu.read_register(HvReg::X6),
            7 => vcpu.read_register(HvReg::X7),
            8 => vcpu.read_register(HvReg::X8),
            9 => vcpu.read_register(HvReg::X9),
            10 => vcpu.read_register(HvReg::X10),
            11 => vcpu.read_register(HvReg::X11),
            12 => vcpu.read_register(HvReg::X12),
            13 => vcpu.read_register(HvReg::X13),
            14 => vcpu.read_register(HvReg::X14),
            15 => vcpu.read_register(HvReg::X15),
            16 => vcpu.read_register(HvReg::X16),
            17 => vcpu.read_register(HvReg::X17),
            18 => vcpu.read_register(HvReg::X18),
            19 => vcpu.read_register(HvReg::X19),
            20 => vcpu.read_register(HvReg::X20),
            21 => vcpu.read_register(HvReg::X21),
            22 => vcpu.read_register(HvReg::X22),
            23 => vcpu.read_register(HvReg::X23),
            24 => vcpu.read_register(HvReg::X24),
            25 => vcpu.read_register(HvReg::X25),
            26 => vcpu.read_register(HvReg::X26),
            27 => vcpu.read_register(HvReg::X27),
            28 => vcpu.read_register(HvReg::X28),
            29 => vcpu.read_register(HvReg::Fp),
            30 => vcpu.read_register(HvReg::Lr),
            31 => Ok(0), // XZR (zero register) - always reads 0
            _ => Ok(0),
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
            uart_type: UartType::PL011, // Default, auto-detected in load_kernel
            kernel_entry: 0,
            initrd_info: None,
            exit_code: None,
            boot_complete: false,
            uart_line_buf: String::new(),
            network_enabled: false,
            virtio_net: None,
            virtio_blk: None,
            virtio_rng: None,
            use_virtio_blk: false,
            uart_ier: 0,
            uart_thr_written: false,
            uart_thre_pending: false,
            uart_irq_asserted: false,
            uart_rx_buf: VecDeque::new(),
            uart_suppress_line: false,
        })
    }

    /// Detect the UART type from the kernel binary.
    /// Must be called before building the initramfs if using rootfs.
    pub fn detect_uart_type(&mut self, kernel_path: &std::path::Path) -> Result<()> {
        let kernel_data = std::fs::read(kernel_path)?;
        let has_pl011 = kernel_data.windows(5).any(|w| w == b"pl011");
        let has_8250 = kernel_data.windows(4).any(|w| w == b"8250")
            || kernel_data.windows(10).any(|w| w == b"serial8250");

        if has_8250 && !has_pl011 {
            self.uart_type = UartType::Uart8250;
        } else {
            self.uart_type = UartType::PL011;
        }

        debug!(
            "UART type: {:?} (pl011={}, 8250={})",
            self.uart_type, has_pl011, has_8250
        );
        Ok(())
    }

    pub fn setup(&mut self) -> Result<()> {
        let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;

        // Map main memory at 0x40000000 (QEMU virt machine layout)
        self.vm
            .map_memory(
                self.memory.as_mut_ptr() as *mut std::ffi::c_void,
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

    pub fn load_kernel(&mut self, kernel_path: &std::path::Path) -> Result<()> {
        // === QEMU-style boot sequence ===
        // 1. Write bootloader stub at RAM_BASE (offset 0)
        // 2. Load kernel at RAM_BASE + 0x80000
        // 3. Load DTB at RAM_BASE + DTB_OFFSET
        // 4. Fix up bootloader with absolute addresses

        // Step 1: Write QEMU's bootloader at offset 0
        // This bootloader sets up X0 (DTB), clears X1-X3, jumps to kernel
        // From QEMU hw/arm/boot.c bootloader_aarch64[]
        let bootloader: [u32; 10] = [
            0x580000c0, // ldr x0, [pc, #0x18]  → load DTB address
            0xaa1f03e1, // mov x1, xzr
            0xaa1f03e2, // mov x2, xzr
            0xaa1f03e3, // mov x3, xzr
            0x58000084, // ldr x4, [pc, #0x10]  → load kernel entry
            0xd61f0080, // br x4                 → jump to kernel
            // Data section (filled in step 4):
            0x00000000, // [6] DTB address low 32 bits
            0x00000000, // [7] DTB address high 32 bits
            0x00000000, // [8] Kernel entry low 32 bits
            0x00000000, // [9] Kernel entry high 32 bits
        ];

        unsafe {
            let ptr = self.memory.as_mut_ptr() as *mut u32;
            for (i, &instr) in bootloader.iter().enumerate() {
                *ptr.add(i) = instr;
            }
        }

        // Step 2: Load kernel at offset 0x80000
        let kernel_data = std::fs::read(kernel_path)?;
        let kernel_offset = KERNEL_OFFSET as usize;

        if kernel_offset + kernel_data.len() > self.memory_size {
            anyhow::bail!(
                "Kernel too large for VM memory ({} bytes, memory {} bytes)",
                kernel_data.len(),
                self.memory_size
            );
        }

        self.memory[kernel_offset..kernel_offset + kernel_data.len()].copy_from_slice(&kernel_data);

        debug!(
            "Kernel loaded at offset 0x{:x} ({} bytes = {} MB)",
            kernel_offset,
            kernel_data.len(),
            kernel_data.len() / (1024 * 1024)
        );

        // Step 3: Load device tree
        self.load_device_tree()?;

        // Step 4: Fix up bootloader with absolute guest physical addresses
        let dtb_gpa = RAM_BASE + DTB_OFFSET;
        let kernel_entry_gpa = RAM_BASE + KERNEL_OFFSET;
        self.kernel_entry = kernel_entry_gpa;

        unsafe {
            let ptr = self.memory.as_mut_ptr() as *mut u32;
            *ptr.add(6) = (dtb_gpa & 0xFFFFFFFF) as u32;
            *ptr.add(7) = ((dtb_gpa >> 32) & 0xFFFFFFFF) as u32;
            *ptr.add(8) = (kernel_entry_gpa & 0xFFFFFFFF) as u32;
            *ptr.add(9) = ((kernel_entry_gpa >> 32) & 0xFFFFFFFF) as u32;
        }

        debug!("Bootloader configured:");
        debug!("   Kernel at GPA: 0x{kernel_entry_gpa:x}");
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
            crate::hypervisor::vm::Vm::query_gic_params();
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
        let use_8250 = self.uart_type == UartType::Uart8250;
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
            virtio_rng_dt,
            use_8250,
            log::log_enabled!(log::Level::Debug),
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
        debug!("=== Starting Linux kernel execution ===");

        // Create VCPU
        let vcpu = Vcpu::new().context("Failed to create vCPU")?;
        debug!("vCPU created (ID: {})", vcpu.id());

        // === Configure VCPU state (matching QEMU's boot sequence) ===

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

        if log::log_enabled!(log::Level::Debug) {
            let verify_pc = vcpu.read_register(HvReg::Pc)?;
            let verify_cpsr = vcpu.read_register(HvReg::Cpsr)?;
            debug!("VCPU configured:");
            debug!(
                "   PC:   0x{:x} (expected: 0x{:x}) {}",
                verify_pc,
                bootloader_gpa,
                if verify_pc == bootloader_gpa {
                    "OK"
                } else {
                    "MISMATCH!"
                }
            );
            debug!("   CPSR: 0x{:x} (EL{}h)", verify_cpsr, verify_cpsr & 0xF);
            debug!("   SP:   0x{sp_addr:x}");
            debug!("   Kernel entry: 0x{:x}", self.kernel_entry);

            if verify_pc != bootloader_gpa {
                warn!("PC mismatch! HvReg values may still be wrong.");
            }

            debug!("--- Entering VCPU run loop ---");
        }

        let mut iteration: u64 = 0;
        let mut stdin_eof = false;
        let max_iterations: u64 = 100_000_000; // 100M iterations for kernel boot

        // Put the terminal in raw mode so we can forward stdin to the guest
        // character-by-character (needed for interactive programs like Python REPL).
        let stdin_fd = std::io::stdin().as_raw_fd();
        let stdin_is_tty = unsafe { isatty(stdin_fd) } != 0;
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
        // (NO_HZ) may idle the vtimer for seconds, stalling network I/O and
        // interactive input.
        //
        // When networking is enabled we use the NetPoller (which already has
        // kqueue set up for network sockets).  Otherwise we create a minimal
        // stdin-only poller.
        let net_poller_thread = if let Some(ref mut net) = self.virtio_net {
            let poller = net.create_poller(vcpu.id());
            // Register stdin so keypresses kick the vcpu (TTY only —
            // /dev/null and closed pipes report as always-readable which
            // would spin the poller and starve the vcpu).
            if stdin_is_tty {
                let fd_tx = poller.fd_sender();
                fd_tx.send(stdin_fd).ok();
            }
            Some(std::thread::spawn(move || poller.run()))
        } else if stdin_is_tty {
            // No networking — create a minimal stdin poller that kicks the
            // vcpu when the user types (TTY only).
            let vcpu_id = vcpu.id();
            Some(std::thread::spawn(move || {
                Self::stdin_poller(vcpu_id, stdin_fd);
            }))
        } else {
            None
        };

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

            let exit_reason = match vcpu.run() {
                Ok(r) => r,
                Err(e) => {
                    let pc = vcpu.read_register(HvReg::Pc).unwrap_or(0);
                    error!("hv_vcpu_run error at PC=0x{pc:x}: {e}");
                    return Err(e);
                }
            };

            match exit_reason {
                0 => {
                    // HV_EXIT_REASON_CANCELED — hv_vcpus_exit() was called
                    // (from the network poller thread or externally).
                    // Just continue to poll the network and re-enter the vcpu.
                }
                1 => {
                    // HV_EXIT_REASON_EXCEPTION
                    let pc = vcpu.read_register(HvReg::Pc)?;
                    let syndrome = vcpu.read_exception_syndrome()?;
                    let ec = (syndrome >> 26) & 0x3F;
                    let iss = syndrome & 0x1FFFFFF;

                    // Detailed logging for first 30 iterations
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
                            // WFI/WFE - just advance PC
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

                            if log::log_enabled!(log::Level::Debug) {
                                let cpsr = vcpu.read_register(HvReg::Cpsr)?;
                                let sp_el0 =
                                    vcpu.read_sys_register(HvSysReg::SpEl0).unwrap_or(0xDEAD);
                                let x4 = vcpu.read_register(HvReg::X4)?;
                                let x7 = vcpu.read_register(HvReg::X7)?;
                                let x8 = vcpu.read_register(HvReg::X8)?;
                                let elr =
                                    vcpu.read_sys_register(HvSysReg::ElrEl1).unwrap_or(0xDEAD);

                                debug!(
                                    "[HVC] PC=0x{:x} func=0x{:x} CPSR=0x{:x} (EL{})",
                                    pc,
                                    x0,
                                    cpsr,
                                    cpsr & 0xF
                                );
                                debug!("[HVC]   SP_EL0=0x{sp_el0:x} SP_EL1=0x{sp_el1:x}");
                                debug!("[HVC]   X4=0x{x4:x} X7=0x{x7:x} X8=0x{x8:x} LR=0x{lr:x}");
                                debug!("[HVC]   ELR_EL1=0x{elr:x}");
                                debug!(
                                    "[HVC]   TTBR1_EL1=0x{ttbr1:x} TCR_EL1=0x{tcr:x} T1SZ={t1sz}"
                                );

                                if let Some(phys) = self.translate_va_to_pa(sp, ttbr1, t1sz) {
                                    debug!("[HVC]   SP VA 0x{sp:x} -> PA 0x{phys:x}");
                                    if phys >= RAM_BASE
                                        && phys + 16 < RAM_BASE + self.memory_size as u64
                                    {
                                        let offset = (phys - RAM_BASE) as usize;
                                        let val0 = u64::from_le_bytes(
                                            self.memory[offset..offset + 8].try_into().unwrap(),
                                        );
                                        let val1 = u64::from_le_bytes(
                                            self.memory[offset + 8..offset + 16]
                                                .try_into()
                                                .unwrap(),
                                        );
                                        debug!("[HVC]   [SP+0]=0x{val0:x} [SP+8]=0x{val1:x}");
                                    }
                                }
                            }

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

                                                    debug!("[HVC]   Emulated SMCCC: res@VA=0x{res_ptr_va:x} PA=0x{res_pa:x}, wrote a0=0x{result:x}");
                                                    debug!("[HVC]   PC -> LR 0x{lr:x} (skipped __arm_smccc_hvc body)");
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if !emulated_smccc {
                                // Fallback: just advance past HVC
                                vcpu.write_register(HvReg::Pc, pc + 4)?;
                                debug!(
                                    "[HVC]   PC advanced to 0x{:x} (no SMCCC emulation)",
                                    pc + 4
                                );
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
                            // BRK - breakpoint/semihosting
                            let imm = iss & 0xFFFF;
                            if imm == 0xF000 {
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
                            } else {
                                debug!("BRK #{imm} at PC=0x{pc:x}");
                            }
                            vcpu.write_register(HvReg::Pc, pc + 4)?;
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
                    // Virtual timer fired - inject the timer IRQ and unmask
                    // The GIC will deliver the interrupt to the guest
                    vcpu.set_vtimer_mask(true)?;
                    // Inject IRQ (type 0 = IRQ) to signal the timer interrupt
                    vcpu.set_pending_interrupt(0, true)?;
                }

                _ => {
                    warn!("Unknown exit reason: {exit_reason}");
                    break;
                }
            }

            // Poll stdin for input and buffer it for the guest UART
            self.poll_stdin(stdin_fd, &mut stdin_eof);

            // Fire UART interrupt if any source is pending
            if self.uart_type == UartType::Uart8250 {
                let rx_pending = !self.uart_rx_buf.is_empty() && (self.uart_ier & 0x01) != 0;
                let tx_pending = self.uart_thre_pending
                    && (self.uart_ier & 0x02) != 0
                    && !self.uart_irq_asserted;
                if rx_pending || tx_pending {
                    if tx_pending {
                        self.uart_irq_asserted = true;
                    }
                    Vm::set_gic_spi(UART_SPI, true);
                }
            }

            // Poll network backend and deliver incoming packets to guest RX queue
            if let Some(ref mut net) = self.virtio_net {
                net.poll_backend();
                if net.process_rx(&mut self.memory, RAM_BASE) {
                    Vm::set_gic_spi(VIRTIO_NET_SPI, true);
                }
            }

            // Exit immediately once the exit marker has been received
            // (no need to wait for the guest to poweroff)
            if self.exit_code.is_some() {
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
    /// Exits when stdin reaches EOF or an error occurs.
    fn stdin_poller(vcpu_id: u32, stdin_fd: RawFd) {
        use crate::hypervisor::Vcpu;
        loop {
            let n = poll_stdin_once(stdin_fd);
            if n < 0 {
                break; // error
            }
            if n > 0 {
                Vcpu::force_exit(&[vcpu_id]).ok();
            }
            // n == 0 → timeout, loop again
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
        let n = unsafe { read(stdin_fd, buf.as_mut_ptr(), buf.len()) };
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
        if let Some(marker_pos) = trimmed.find(crate::initramfs::EXIT_MARKER) {
            let after = &trimmed[marker_pos + crate::initramfs::EXIT_MARKER.len()..];
            if let Ok(code) = after.trim().parse::<i32>() {
                self.exit_code = Some(code);
            }
            return;
        }

        // Detect boot completion — the init script prints this marker
        // right before running the user command.
        if trimmed.contains(crate::initramfs::BOOT_MARKER) {
            self.boot_complete = true;
            debug!("{trimmed}");
            return;
        }

        // Before boot is complete: only show in debug mode
        if !self.boot_complete {
            debug!("{trimmed}");
        }

        // After boot: characters were already written directly to stdout
        // by the UART write handler, so nothing more to print here.
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
                // PSCI_CPU_OFF
                Ok(0)
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
        let crm = (iss >> 1) & 0xF;
        let crn = (iss >> 10) & 0xF;
        let op0 = (iss >> 20) & 0x3;
        let op1 = (iss >> 14) & 0x7;
        let op2 = (iss >> 17) & 0x7;

        let _sys_reg_id = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;

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
                            let marker = crate::initramfs::EXIT_MARKER.as_bytes();
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
                    // Mark that THR was written; THRE will fire after the ISR exits
                    if self.uart_type == UartType::Uart8250 {
                        self.uart_thr_written = true;
                    }
                } else if reg_offset == 0x04 && self.uart_type == UartType::Uart8250 {
                    // IER write — track interrupt enable state
                    let old_ier = self.uart_ier;
                    self.uart_ier = value as u8;
                    // If THRE interrupt just enabled, set pending immediately
                    // (TX holding register is always empty in our emulation)
                    if (old_ier & 0x02) == 0 && (self.uart_ier & 0x02) != 0 {
                        self.uart_thre_pending = true;
                    }
                }
                // Other UART registers (control, baud rate, etc.) - ignored
            } else {
                // UART read — handle both PL011 and 8250 register layouts
                let has_rx_data = !self.uart_rx_buf.is_empty();
                let value = if self.uart_type == UartType::Uart8250 {
                    // 8250/16550 registers (reg-shift=2, so 4-byte aligned)
                    match reg_offset {
                        0x00 => {
                            // RBR: read the next byte from the input buffer.
                            // The RX interrupt clears naturally when the buffer
                            // is drained (checked via is_empty() in the IIR path).
                            self.uart_rx_buf.pop_front().unwrap_or(0) as u64
                        }
                        0x04 => self.uart_ier as u64, // IER: return current state
                        0x08 => {
                            // IIR (Interrupt Identification Register)
                            // Priority: RX data ready > THRE
                            if !self.uart_rx_buf.is_empty() && (self.uart_ier & 0x01) != 0 {
                                // RX data available (ID bits = 10, highest priority).
                                // Reading IIR does NOT clear this — reading RBR does.
                                0xC4u64 // FIFO enabled + RX data available
                            } else if self.uart_thre_pending && (self.uart_ier & 0x02) != 0 {
                                // THRE interrupt pending → report it, clear, and deassert SPI
                                self.uart_thre_pending = false;
                                self.uart_irq_asserted = false;
                                Vm::set_gic_spi(UART_SPI, false);
                                0xC2u64 // FIFO enabled + THRE (ID bits = 01)
                            } else {
                                // No interrupt pending — deassert the SPI line so
                                // the GIC doesn't re-trigger after EOI.
                                Vm::set_gic_spi(UART_SPI, false);
                                self.uart_irq_asserted = false;
                                // If a THR was written, promote it to THRE pending
                                // for the NEXT interrupt cycle.
                                if self.uart_thr_written {
                                    self.uart_thr_written = false;
                                    self.uart_thre_pending = true;
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
                } else {
                    // PL011 registers
                    match reg_offset {
                        0x00 => {
                            // DR: read the next byte from the input buffer
                            self.uart_rx_buf.pop_front().unwrap_or(0) as u64
                        }
                        // FR (Flags Register):
                        //   Bit 4: RXFE (RX FIFO Empty)
                        //   Bit 7: TXFE (TX FIFO Empty) — always set
                        0x18 => {
                            let mut fr = 0x80u64; // TXFE
                            if !has_rx_data {
                                fr |= 0x10;
                            } // RXFE
                            fr
                        }
                        0x2C => 0x00,   // LCR_H: line control
                        0x30 => 0x0301, // CR: UART enabled, TX enabled, RX enabled
                        0x38 => 0x00,   // IMSC: interrupt mask
                        0x40 => 0x00,   // RIS: raw interrupt status
                        0x44 => 0x00,   // MIS: masked interrupt status
                        0x48 => 0x00,   // ICR: interrupt clear
                        0xFE0 => 0x11,  // PeriphID0: PL011 identification
                        0xFE4 => 0x10,  // PeriphID1
                        0xFE8 => 0x34,  // PeriphID2: revision 3, PL011
                        0xFEC => 0x00,  // PeriphID3
                        0xFF0 => 0x0D,  // CellID0 (PrimeCell component ID)
                        0xFF4 => 0xF0,  // CellID1
                        0xFF8 => 0x05,  // CellID2
                        0xFFC => 0xB1,  // CellID3
                        _ => 0x00,
                    }
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
                        // QueueNotify — process the request queue
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
        // Extract table base from TTBR1 (mask off ASID and other bits)
        let table_base = ttbr1 & !0xFFF;

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
fn resolve_data_path(relative: &str) -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe
            .canonicalize()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
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
    let path = std::path::PathBuf::from(relative);
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
        use crate::net::NetworkFilter;
        use crate::unet::UserNet;

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

        let device = VirtioNetDevice::new(backend, filter, VIRTIO_NET_SPI);
        vm.virtio_net = Some(device);
    }

    // Resolve kernel path (default: kernels/vmlinux)
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => resolve_data_path("kernels/vmlinux").ok_or_else(|| {
            anyhow::anyhow!("No kernel found. Use --kernel or run: scripts/setup-image.sh")
        })?,
    };

    // Detect UART type from kernel (needed for initramfs device nodes)
    vm.detect_uart_type(&kernel_path)?;

    // Check kernel capabilities to decide rootfs strategy
    let kernel_path = &kernel_path;
    let kernel_data = std::fs::read(kernel_path)?;
    let has_virtio_blk = kernel_data.windows(10).any(|w| w == b"virtio_blk");
    // Check if the kernel explicitly lacks initramfs support
    // (only the Firecracker kernel is known to lack it — detected by having virtio_blk but no initrd strings)
    let has_initrd_strings = kernel_data
        .windows(18)
        .any(|w| w == b"BLK_DEV_INITRD=y\r\n" || w == b"BLK_DEV_INITRD=y\n\x00")
        || kernel_data.windows(17).any(|w| w == b"BLK_DEV_INITRD=y\n")
        || kernel_data.windows(14).any(|w| w == b"initramfs_data")
        || kernel_data.windows(9).any(|w| w == b"cpio_data");
    // Default to initramfs support (most kernels have it); only use virtio-blk if we can
    // confirm virtio-blk support AND cannot confirm initramfs support
    let prefer_virtio_blk = has_virtio_blk && !has_initrd_strings;

    // Load initrd/rootfs (must be done before load_kernel, because load_kernel builds DTB)
    // Resolve rootfs path (default: rootfs)
    let default_rootfs = if args.rootfs.is_none() {
        resolve_data_path("rootfs")
    } else {
        None
    };
    let rootfs_arg = args.rootfs.as_ref().or(default_rootfs.as_ref());

    let use_8250 = vm.uart_type == UartType::Uart8250;
    if let Some(rootfs_path) = rootfs_arg {
        if !rootfs_path.is_dir() {
            anyhow::bail!("--rootfs path {rootfs_path:?} is not a directory");
        }

        if prefer_virtio_blk {
            // Kernel supports virtio-blk but NOT initramfs — use ext2 image on virtio-blk
            info!("Packing host directory {rootfs_path:?} as ext2 on virtio-blk...");
            let disk_image = crate::ext2::build_ext2_from_directory(
                rootfs_path,
                &args.command,
                network_enabled,
                use_8250,
            )
            .context("Failed to build ext2 filesystem image")?;
            debug!(
                "ext2 image: {} bytes ({} KB)",
                disk_image.len(),
                disk_image.len() / 1024
            );
            vm.virtio_blk = Some(VirtioBlkDevice::new(disk_image, VIRTIO_BLK_SPI));
            vm.use_virtio_blk = true;
        } else {
            // Default: use initramfs (cpio archive) — works with most kernels
            info!("Packing host directory {rootfs_path:?} as initramfs...");
            let initrd_data = crate::initramfs::build_from_directory(
                rootfs_path,
                &args.command,
                network_enabled,
                use_8250,
            )
            .context("Failed to build initramfs from directory")?;
            vm.load_initrd(&initrd_data)?;
        }
    } else if let Some(initrd_path) = &args.initrd {
        info!("Loading initrd from {initrd_path:?}...");
        let initrd_data =
            crate::initramfs::load_initrd(initrd_path).context("Failed to load initrd")?;
        vm.load_initrd(&initrd_data)?;
    }

    // Always provide a virtio-rng device for guest entropy
    vm.virtio_rng = Some(VirtioRngDevice::new());

    // Load kernel (this also builds the device tree, which needs initrd info)
    vm.load_kernel(kernel_path)?;

    // Run the VM
    let exit_code = vm.run_command(&args.command)?;

    debug!("VM exited with code: {exit_code}");

    std::process::exit(exit_code);
}
