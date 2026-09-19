//! sandal VMM core.
//!
//! The design source of truth is `docs/vmm-spec.md` (Apple
//! Hypervisor.framework contract, ARM ARM, and Linux arm64 requirements).
//! Key decisions:
//!
//! 1. The GIC is emulated in software (see [`crate::gic`]), NOT via
//!    `hv_gic_create`. This is required so the VMM can observe the guest's ICC
//!    EOI and unmask the vtimer (spec §1.1/§1.3).
//! 2. The guest arch timer is delivered through `HV_EXIT_REASON_VTIMER_ACTIVATED`
//!    (reason 2): on it, pend INTID 27 in the software GIC; unmask via
//!    `hv_vcpu_set_vtimer_mask(false)` when the guest EOIs/DIRs INTID 27.
//! 3. Device IRQs are level-triggered SPIs in the software GIC, injected via
//!    `hv_vcpu_set_pending_interrupt(HV_INTERRUPT_TYPE_IRQ=0, true)`.
//!
//! Exit reasons (verified from the local SDK header): CANCELED=0, EXCEPTION=1,
//! VTIMER_ACTIVATED=2.

use crate::cli::Args;
use crate::devicetree::DeviceTree;
use crate::gic::{
    Gic, IRQ_VTIMER, SPI_BLK, SPI_CONSOLE, SPI_DATA_BLK, SPI_FS_START, SPI_NET, SPI_RNG,
};
use crate::hypervisor::{HvReg, HvSysReg, Vcpu, Vm};
use crate::initramfs;
use crate::net::NetworkFilter;
use crate::unet::UserNet;
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::console::VirtioConsoleDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;
use anyhow::{anyhow, bail, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::thread::JoinHandle;

// ─────────────────────────────────────────────────────────────────────────────
// Guest physical memory map (must match src/devicetree.rs)
// ─────────────────────────────────────────────────────────────────────────────
const RAM_BASE: u64 = 0x4000_0000;
const KERNEL_LOAD_ADDR: u64 = 0x4020_0000; // 2 MB aligned
const DTB_ADDR: u64 = 0x4800_0000; // 128 MB offset, well past the kernel image

const GICD_BASE: u64 = 0x0800_0000;
const GICD_SIZE: u64 = 0x1_0000;
const GICR_BASE: u64 = 0x080A_0000;
const GICR_SIZE: u64 = 0x2_0000; // 2 × 64 KB frames (RD + SGI/PPI) for 1 CPU

const UART_BASE: u64 = 0x0900_0000;
const VIRTIO_NET_BASE: u64 = 0x0a00_0000;
const VIRTIO_CONSOLE_BASE: u64 = 0x0a00_0200;
const VIRTIO_BLK_BASE: u64 = 0x0a00_0400;
const DATA_BLK_BASE: u64 = 0x0a00_0600;
const VIRTIO_RNG_BASE: u64 = 0x0a00_0800;
const VIRTIOFS_BASE_START: u64 = 0x0a00_1000;
const VIRTIOFS_SIZE: u64 = 0x200;
const MAX_FS_DEVICES: usize = 8;

const CNTFRQ: u64 = 24_000_000; // Apple Silicon host timer frequency (Hz)

// HVF exit reasons (local SDK hv_vcpu_types.h)
const EXIT_CANCELED: u32 = 0;
const EXIT_EXCEPTION: u32 = 1;
const EXIT_VTIMER_ACTIVATED: u32 = 2;

// Exception classes (EC field, bits 31..26 of the syndrome)
const EC_WFX_TRAP: u32 = 0x01;
const EC_AA64_HVC: u32 = 0x16;
const EC_AA64_SMC: u32 = 0x17;
const EC_SYSTEMREGISTERTRAP: u32 = 0x18;
const EC_DATA_ABORT: u32 = 0x24;
const EC_DATA_ABORT_LOWER: u32 = 0x25;
const EC_BRK: u32 = 0x3c;

extern "C" {
    fn mach_absolute_time() -> u64;
}

/// Put the host terminal in raw mode: disable echo, canonical mode and signal
/// generation so every keystroke (including Tab and readline's CSI queries) is
/// forwarded to the guest verbatim instead of being line-buffered/echoed by
/// the host tty. Returns the original settings for restore.
fn enable_raw_mode(fd: RawFd) -> Option<libc::termios> {
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

fn restore_terminal(fd: RawFd, orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, orig);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VMM core
// ─────────────────────────────────────────────────────────────────────────────
struct Vmm {
    // Field drop order matters: HVF requires the vCPU to be destroyed before
    // the VM, and Rust drops fields in declaration order.
    vcpu: Vcpu,
    #[allow(dead_code)] // keeps the VM (and its hv_vm_destroy Drop) alive
    vm: Vm,
    memory: Vec<u8>,
    gic: Gic,
    console: VirtioConsoleDevice,
    blk: Option<VirtioBlkDevice>,
    data_blk: Option<VirtioBlkDevice>,
    net: Option<VirtioNetDevice>,
    rng: Option<VirtioRngDevice>,
    virtiofs: Vec<VirtioFsDevice>,
    /// kqueue poller thread that kicks the vCPU when host sockets are readable.
    net_poller: Option<JoinHandle<()>>,
    vtimer_masked: bool,
    config_blob: Vec<u8>,
    tty_saved: Option<libc::termios>,
    guest_shutdown: bool,
    verbose_uart: bool,
    vt_off: u64,
    /// Save path from the guest's `SANDAL_EXPORT_PATH:` console marker.
    export_save_path: Option<String>,
    /// Console TX line buffer used to intercept VMM protocol markers.
    tx_line: Vec<u8>,
    /// True while the current TX line is a suppressed protocol marker line.
    tx_suppress_line: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points used by main.rs
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve a data file (kernel, rootfs) relative to the working directory or
/// the executable.
pub fn resolve_data_path(name: &str) -> Option<PathBuf> {
    let candidates = [
        std::env::current_dir().ok()?.join(name),
        std::env::current_exe().ok()?.parent()?.join(name),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Parse `--share host_path:guest_path` arguments into
/// `(mount_tag, host_path, guest_path)` tuples.  Validates the host path and
/// the maximum number of devices.
fn parse_shares(args: &Args) -> Result<Vec<(String, PathBuf, String)>> {
    let mut shares = Vec::new();
    for (i, spec) in args.shared_dirs.iter().enumerate() {
        if i >= MAX_FS_DEVICES {
            bail!("too many shared directories (max {MAX_FS_DEVICES})");
        }
        let (host, guest) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid --share {spec:?} (expected host_path:guest_path)"))?;
        let host_path = PathBuf::from(host);
        if !host_path.is_dir() {
            bail!("shared path is not a directory: {host}");
        }
        shares.push((format!("share{i}"), host_path, guest.to_string()));
    }
    Ok(shares)
}

/// Map a guest physical address to a virtiofs device index, if in range.
fn virtiofs_index(addr: u64) -> Option<usize> {
    let end = VIRTIOFS_BASE_START + MAX_FS_DEVICES as u64 * VIRTIOFS_SIZE;
    if (VIRTIOFS_BASE_START..end).contains(&addr) {
        Some(((addr - VIRTIOFS_BASE_START) / VIRTIOFS_SIZE) as usize)
    } else {
        None
    }
}

/// Run a VM to execute the requested command, returning when the guest exits.
pub fn run(args: Args) -> Result<()> {
    let mut vmm = Vmm::new(&args)?;
    vmm.boot(&args)?;
    vmm.run_loop(&args)
}

/// Build the writable overlay data disk (vdb).
///
/// Layer tar entries are injected under `upper/` (see
/// `ext2::inject_tar_entries`), which the guest init mounts as the overlayfs
/// upperdir. The image is sized to fit the layer's uncompressed data with
/// headroom (2× + 16 MB), at least `--disk-size`.
fn build_data_disk(args: &Args) -> Result<Vec<u8>> {
    if args.layers.is_empty() {
        let mb = args.disk_size.unwrap_or(1);
        return crate::ext2::create_empty_ext2(mb * 1024 * 1024);
    }
    let mut all_entries = Vec::new();
    for layer in &args.layers {
        let gz = fs::read(layer)
            .map_err(|e| anyhow!("failed to read layer {}: {e}", layer.display()))?;
        let entries = crate::tar::read_tar_gz(&gz)?;
        all_entries.extend(entries);
    }
    let layer_data = crate::tar::total_data_size(&all_entries);
    let layer_need = (layer_data * 2) + 16 * 1024 * 1024;
    let disk_bytes = args.disk_size.unwrap_or(1) * 1024 * 1024;
    let final_size = disk_bytes.max(layer_need);
    let mut img = crate::ext2::create_empty_ext2(final_size)?;
    crate::ext2::inject_tar_entries(&mut img, &all_entries)?;
    Ok(img)
}

// ─────────────────────────────────────────────────────────────────────────────
// VM construction & boot
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    fn new(args: &Args) -> Result<Self> {
        let vm = Vm::new()?;
        let vcpu = Vcpu::new()?;

        // Trap BRK/debug exceptions to EL2 so the guest init's `BRK #imm`
        // protocol exits reach the VMM instead of being delivered to the
        // guest as SIGTRAP (which kills init).
        vcpu.set_trap_debug_exceptions(true)?;

        let mem_mb = args.memory.max(64);
        let mut memory = vec![0u8; mem_mb * 1024 * 1024];
        vm.map_memory(
            memory.as_mut_ptr() as *mut _,
            RAM_BASE,
            memory.len(),
            crate::hypervisor::HV_MEMORY_READ
                | crate::hypervisor::HV_MEMORY_WRITE
                | crate::hypervisor::HV_MEMORY_EXEC,
        )?;

        // CNTVOFF (`hv_vcpu_set_vtimer_offset`) is set once and never touched
        // again (spec §2.1): the guest's CNTVCT (= CNTPCT − CNTVOFF) starts
        // near 0 and advances at the host rate. Without it HVF reports a
        // frozen/0 counter and guest `__delay` loops spin.
        let vt_off = unsafe { mach_absolute_time() };
        vcpu.set_vtimer_offset(vt_off)?;
        vcpu.set_vtimer_mask(false)?;

        // Host stdin is the interactive pty.  Put it in raw mode (if it is a
        // tty) and read it non-blocking so the run loop can poll for input
        // without blocking; the original settings are restored on exit.
        let tty_saved = unsafe {
            let saved = if libc::isatty(0) != 0 {
                enable_raw_mode(0)
            } else {
                None
            };
            let fl = libc::fcntl(0, libc::F_GETFL);
            let _ = libc::fcntl(0, libc::F_SETFL, fl | libc::O_NONBLOCK);
            saved
        };

        // User-space networking (enabled unless --no-network).  A kqueue
        // poller thread watches the host sockets and kicks the vCPU when data
        // arrives, so an idle guest wakes to drain the RX queue.
        let net = if args.no_network {
            None
        } else {
            let backend =
                UserNet::new().map_err(|e| anyhow!("failed to create user-space network: {e}"))?;
            let mut filter = NetworkFilter::new();
            filter.set_protocols(NetworkFilter::parse_protocols(&args.protocols));
            if let Some(ref hosts) = args.allowed_hosts {
                filter.set_allowed_hosts(NetworkFilter::parse_hosts(hosts));
            }
            Some(VirtioNetDevice::new(backend, filter))
        };
        let mut net = net;
        let net_poller = net.as_mut().map(|n| {
            let poller = n.create_poller(vcpu.id() as u64);
            std::thread::spawn(move || poller.run())
        });

        // Virtiofs devices for --share host:guest pairs.
        let mut virtiofs = Vec::new();
        for (i, (tag, host_path, _guest)) in parse_shares(args)?.into_iter().enumerate() {
            let _ = i;
            virtiofs.push(VirtioFsDevice::new(host_path, tag));
        }

        Ok(Vmm {
            vm,
            vcpu,
            memory,
            gic: Gic::new(),
            console: VirtioConsoleDevice::new(40, 120),
            blk: None,
            data_blk: None,
            net,
            rng: Some(VirtioRngDevice::new()),
            virtiofs,
            net_poller,
            vtimer_masked: false,
            config_blob: Vec::new(),
            tty_saved,
            guest_shutdown: false,
            verbose_uart: args.verbose,
            vt_off,
            export_save_path: None,
            tx_line: Vec::new(),
            tx_suppress_line: false,
        })
    }

    fn boot(&mut self, args: &Args) -> Result<()> {
        // ── Load the kernel Image ──────────────────────────────────────
        let kernel_path = args
            .kernel
            .clone()
            .or_else(|| resolve_data_path("vmlinux-sandal"))
            .ok_or_else(|| anyhow!("kernel image not found"))?;
        let kernel = fs::read(&kernel_path)?;
        if kernel.len() < 64 {
            anyhow::bail!("kernel image too small");
        }
        // Linux arm64 Image header: text_offset at 0x08, image_size at 0x10.
        let text_offset = u64::from_le_bytes(kernel[0x08..0x10].try_into()?);
        let image_size = u64::from_le_bytes(kernel[0x10..0x18].try_into()?);
        let load = KERNEL_LOAD_ADDR + text_offset;
        let size = image_size as usize;
        if load + size as u64 > RAM_BASE + self.memory.len() as u64 {
            anyhow::bail!("kernel image does not fit in RAM");
        }
        self.memory[(load - RAM_BASE) as usize..(load - RAM_BASE) as usize + kernel.len()]
            .copy_from_slice(&kernel);

        // ── Root filesystem (vda): busybox ext2 + runtime files ───────
        let mut rootfs_img = match &args.rootfs {
            Some(path) => fs::read(path)
                .map_err(|e| anyhow!("failed to read rootfs {}: {e}", path.display()))?,
            None => crate::rootfs::load(),
        };
        crate::ext2::inject_runtime_files(&mut rootfs_img, !args.no_network)?;
        self.blk = Some(VirtioBlkDevice::new(rootfs_img));

        // ── Writable data disk (vdb): --disk-size / --layer ────────────
        // The layer tar entries are injected under `upper/`, which the guest
        // init mounts as the overlayfs upperdir, so the guest sees the layer's
        // files at their natural paths (usr/bin/uv, root/.local/bin/uv, ...).
        if args.disk_size.is_some() || !args.layers.is_empty() {
            self.data_blk = Some(VirtioBlkDevice::new(build_data_disk(args)?));
        }

        // ── Build the DTB ──────────────────────────────────────────────
        let virtiofs_dt: Vec<(u64, u32)> = (0..self.virtiofs.len())
            .map(|i| {
                (
                    VIRTIOFS_BASE_START + i as u64 * VIRTIOFS_SIZE,
                    SPI_FS_START + i as u32,
                )
            })
            .collect();
        let dtb = DeviceTree::build(
            self.memory.len() as u64,
            UART_BASE,
            GICD_BASE,
            GICD_SIZE as usize,
            GICR_BASE,
            GICR_SIZE as usize,
            self.net.as_ref().map(|_| (VIRTIO_NET_BASE, SPI_NET)),
            Some((VIRTIO_BLK_BASE, SPI_BLK)), // vda (root)
            self.data_blk
                .as_ref()
                .map(|_| (DATA_BLK_BASE, SPI_DATA_BLK)), // vdb (overlay upper)
            self.rng.as_ref().map(|_| (VIRTIO_RNG_BASE, SPI_RNG)),
            &virtiofs_dt,
            Some((VIRTIO_CONSOLE_BASE, SPI_CONSOLE)),
            args.verbose,
            None,             // overlay bootarg handled by the guest init from the config
            Some(&[0u8; 64]), // rng-seed so CRNG never blocks at boot
        )?;
        let dtb_start = DTB_ADDR - RAM_BASE;
        if dtb_start as usize + dtb.len() > self.memory.len() {
            anyhow::bail!("DTB does not fit in RAM");
        }
        self.memory[dtb_start as usize..dtb_start as usize + dtb.len()].copy_from_slice(&dtb);

        // ── Build the init config blob (delivered at the INIT_CONFIG BRK) ─
        let clock_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let disk_mode = if self.data_blk.is_some() {
            Some("disk")
        } else {
            None
        };
        let share_configs: Vec<(String, String)> = parse_shares(args)?
            .into_iter()
            .map(|(tag, _host, guest)| (tag, guest))
            .collect();
        self.config_blob = initramfs::build_init_config(
            disk_mode,
            &share_configs,
            &args.command,
            !args.no_network,
            clock_secs,
        );

        // ── Set the initial vCPU state (Linux arm64 boot protocol) ────
        // Enter at EL1h, all interrupts masked, MMU off (reset SCTLR).
        self.vcpu.write_register(HvReg::Pc, load)?;
        self.vcpu.write_register(HvReg::X0, DTB_ADDR)?;
        self.vcpu.write_register(HvReg::X1, 0)?;
        self.vcpu.write_register(HvReg::X2, 0)?;
        self.vcpu.write_register(HvReg::X3, 0)?;
        self.vcpu.write_register(HvReg::Cpsr, 0x3c5)?; // EL1h, DAIF=1111
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Run loop
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    /// INTIDs of the devices currently asserting an interrupt, used to re-pend
    /// level-triggered SPIs before each `hv_vcpu_run`.
    fn device_irq_intids(&self) -> ([u32; MAX_FS_DEVICES + 5], usize) {
        let mut irqs = [0u32; MAX_FS_DEVICES + 5];
        let mut n = 0;
        let mut push = |intid: u32| {
            irqs[n] = intid;
            n += 1;
        };
        if self.console.interrupt_status != 0 {
            push(32 + SPI_CONSOLE);
        }
        if self.blk.as_ref().is_some_and(|d| d.interrupt_status != 0) {
            push(32 + SPI_BLK);
        }
        if self
            .data_blk
            .as_ref()
            .is_some_and(|d| d.interrupt_status != 0)
        {
            push(32 + SPI_DATA_BLK);
        }
        if self.rng.as_ref().is_some_and(|d| d.interrupt_status != 0) {
            push(32 + SPI_RNG);
        }
        if self.net.as_ref().is_some_and(|d| d.interrupt_status != 0) {
            push(32 + SPI_NET);
        }
        for (i, dev) in self.virtiofs.iter().enumerate() {
            if dev.interrupt_status != 0 {
                push(32 + SPI_FS_START + i as u32);
            }
        }
        (irqs, n)
    }

    fn run_loop(&mut self, _args: &Args) -> Result<()> {
        loop {
            // Poll the user-space network backend and deliver any incoming
            // packets to the guest's RX queue.
            if let Some(net) = self.net.as_mut() {
                net.poll_backend();
                net.process_rx(&mut self.memory, RAM_BASE);
            }

            // Re-pend level-triggered device IRQs before each run.
            let (active, n) = self.device_irq_intids();
            self.gic.update_level_irqs(&active[..n]);
            let deliverable = self.gic.deliverable();
            // The IRQ line into the vCPU must mirror the software GIC's pending
            // state: assert when an enabled interrupt passes PMR, de-assert when
            // nothing is deliverable.  Leaving it asserted after the guest has
            // taken/completed the interrupt livelocks Linux in a spurious-IRQ
            // storm (IAR reads 1023 forever while the line stays high).
            let _ = self.vcpu.set_pending_interrupt(0, deliverable);

            match self.vcpu.run()? {
                EXIT_CANCELED => continue,
                EXIT_VTIMER_ACTIVATED => self.on_vtimer()?,
                EXIT_EXCEPTION => {
                    let syndrome = self.vcpu.read_exception_syndrome()?;
                    let ec = ((syndrome >> 26) & 0x3f) as u32;
                    match ec {
                        EC_DATA_ABORT | EC_DATA_ABORT_LOWER => {
                            self.handle_data_abort(syndrome)?;
                        }
                        EC_SYSTEMREGISTERTRAP => self.handle_sysreg(syndrome)?,
                        EC_WFX_TRAP => self.handle_wfi(syndrome)?,
                        EC_AA64_HVC => self.handle_hvc()?,
                        EC_AA64_SMC => {
                            // PSCI via SMC (not used; dtb method=hvc). Treat as HVC.
                            self.vcpu.write_register(
                                HvReg::Pc,
                                self.vcpu.read_register(HvReg::Pc)? + 4,
                            )?;
                            self.handle_hvc()?;
                        }
                        EC_BRK => self.handle_brk(syndrome)?,
                        _ => {
                            log::warn!(
                                "unhandled exception class 0x{ec:x} at PC=0x{:x}",
                                self.vcpu.read_register(HvReg::Pc)?
                            );
                        }
                    }
                }
                r => {
                    log::warn!("unexpected exit reason {r}");
                }
            }

            // Drain guest console TX → host stdout (intercepting protocol markers).
            let tx = self.console.process_tx(&mut self.memory, RAM_BASE);
            if !tx.is_empty() {
                self.process_console_tx(&tx);
            }

            // Host stdin → guest console RX.
            self.poll_stdin()?;

            // If the guest asked the VMM to shut down, exit the loop.
            if self.guest_shutdown {
                break;
            }
        }
        Ok(())
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if let Some(ref orig) = self.tty_saved {
            restore_terminal(0, orig);
        }
        // Dropping the net device signals the poller thread (UserNet::drop)
        // to exit; join it so no thread outlives the VM.
        self.net.take();
        if let Some(handle) = self.net_poller.take() {
            let _ = handle.join();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exit handlers
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    fn on_vtimer(&mut self) -> Result<()> {
        // HVF auto-masks the vtimer; pend PPI 27 so the guest's clockevent ISR
        // runs. The mask is cleared when the guest EOIs INTID 27.
        self.gic.set_pending(IRQ_VTIMER);
        self.vtimer_masked = true;
        Ok(())
    }

    fn handle_wfi(&mut self, _syndrome: u64) -> Result<()> {
        // Advance past the WFI/WFE.
        let pc = self.vcpu.read_register(HvReg::Pc)?;
        self.vcpu.write_register(HvReg::Pc, pc + 4)?;

        // If an interrupt is already pending, re-enter immediately.
        if self.gic.deliverable() {
            return Ok(());
        }

        // Otherwise wait until the guest's vtimer expires or host input
        // arrives. Compute the vtimer deadline from CNTV_CVAL/CNTV_CTL.
        let mut wait_ms: i32 = 1000; // safety cap (spurious WFI)
        let ctl = self
            .vcpu
            .read_sys_register(HvSysReg::CntvCtlEl0)
            .unwrap_or(0);
        let enabled = ctl & 1 != 0;
        let imask = ctl & 2 != 0;
        if enabled && !imask {
            if let Ok(cval) = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0) {
                // CNTVCT = CNTPCT - CNTVOFF, where CNTVOFF is the vtimer offset
                // set once at VM creation.  Compare against the *virtual*
                // counter, not the raw host counter (the two differ by a huge
                // constant, which would make every WFI look already-expired and
                // livelock the guest in a spurious-timer IRQ storm).
                let now_virt = unsafe { mach_absolute_time() }.wrapping_sub(self.vt_off);
                if cval <= now_virt {
                    // Already expired: pend the timer now.
                    self.gic.set_pending(IRQ_VTIMER);
                    self.vtimer_masked = true;
                    return Ok(());
                }
                let delta_ticks = cval - now_virt;
                let delta_ms = (delta_ticks * 1000 / CNTFRQ) as i32;
                wait_ms = delta_ms.clamp(1, 1000);
            }
        }

        // Wait for host stdin and/or the timer deadline.
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            self.drain_stdin()?;
        } else if n == 0 {
            // Timeout: the vtimer expired while the vCPU was idle-parked.
            self.gic.set_pending(IRQ_VTIMER);
            self.vtimer_masked = true;
        }
        Ok(())
    }

    fn handle_brk(&mut self, syndrome: u64) -> Result<()> {
        let imm = (syndrome & 0xffff) as u32;
        let pc = self.vcpu.read_register(HvReg::Pc)?;
        self.vcpu.write_register(HvReg::Pc, pc + 4)?;
        match imm {
            initramfs::INIT_CONFIG_IMM => {
                // Deliver the init config blob over the console RX and set x0.
                let size = self.config_blob.len() as u64;
                self.vcpu.write_register(HvReg::X0, size)?;
                let chunk = self.config_blob.clone();
                self.console
                    .push_rx_and_drain(&mut self.memory, RAM_BASE, &chunk);
            }
            initramfs::EXPORT_RESIZE_IMM => self.handle_export_resize(),
            initramfs::EXPORT_DONE_IMM => self.handle_export_done(),
            // Unknown BRKs are resumed; the init protocol has no other
            // immediate values.
            _ => {}
        }
        Ok(())
    }

    /// `BRK #EXPORT_RESIZE_IMM`: grow /dev/vdb so the guest can write a tar
    /// archive onto it (tmpfs-upper export path), then signal a virtio config
    /// change so the kernel re-reads the device capacity.
    fn handle_export_resize(&mut self) {
        const EXPORT_DISK_SIZE: usize = 128 * 1024 * 1024; // 128 MB

        let Some(dev) = self.data_blk.as_mut() else {
            log::warn!("export resize: no data disk");
            return;
        };
        if dev.disk_image.len() >= EXPORT_DISK_SIZE {
            return;
        }
        dev.disk_image.resize(EXPORT_DISK_SIZE, 0);
        dev.update_capacity();
        dev.config_generation = dev.config_generation.wrapping_add(1);
        dev.interrupt_status |= crate::virtio::VIRTIO_MMIO_INT_CONFIG;
    }

    /// `BRK #EXPORT_DONE_IMM`: turn the guest's overlay upper tree into a
    /// gzip-compressed `.layer` file on the host.
    ///
    /// Disk mode: the data disk is an ext2 image; its `upper/` subtree is
    /// extracted and serialized as a ustar archive.
    /// Tmpfs mode: the guest wrote an uncompressed tar to the raw device.
    fn handle_export_done(&mut self) {
        let Some(dev) = self.data_blk.as_ref() else {
            log::warn!("export done: no data disk");
            return;
        };

        let tar_data = match crate::ext2::read_upper_tar_entries(&dev.disk_image) {
            Ok(entries) if !entries.is_empty() => crate::tar::write_tar(&entries),
            _ => {
                // Fall back to a raw tar the guest wrote to the device.
                let end = crate::tar::find_tar_end(&dev.disk_image);
                if end == 0 {
                    log::warn!("export done: no exportable data found");
                    eprintln!("sandal: export failed: no exportable data found");
                    return;
                }
                dev.disk_image[..end].to_vec()
            }
        };

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        if let Err(e) = encoder.write_all(&tar_data) {
            eprintln!("sandal: export failed to gzip layer: {e}");
            return;
        }
        let gz_data = match encoder.finish() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("sandal: export failed to finish gzip: {e}");
                return;
            }
        };

        let save_path = match self.export_save_path.take() {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => {
                let mut hasher = DefaultHasher::new();
                gz_data.hash(&mut hasher);
                PathBuf::from(format!("layer-{:016x}.layer", hasher.finish()))
            }
        };

        match fs::write(&save_path, &gz_data) {
            Ok(()) => eprintln!("Layer saved to: {}", save_path.display()),
            Err(e) => eprintln!("sandal: failed to save layer: {e}"),
        }
    }

    /// Feed guest console TX bytes to stdout while intercepting the VMM
    /// protocol markers (`SANDAL_EXIT:`, `SANDAL_EXPORT_PATH:`), which are
    /// consumed here instead of being shown to the user.
    fn process_console_tx(&mut self, data: &[u8]) {
        let mut stdout = std::io::stdout();
        const MARKERS: [&[u8]; 2] = [
            initramfs::EXIT_MARKER.as_bytes(),
            initramfs::EXPORT_PATH_MARKER.as_bytes(),
        ];

        for &ch in data {
            self.tx_line.push(ch);

            if !self.tx_suppress_line {
                let buf = &self.tx_line;
                let is_full = MARKERS.iter().any(|m| buf == m);
                let is_prefix = buf.len() <= MARKERS.iter().map(|m| m.len()).max().unwrap_or(0)
                    && MARKERS
                        .iter()
                        .any(|m| buf.len() <= m.len() && buf[..] == m[..buf.len()]);
                let prev_was_prefix = buf.len() > 1
                    && MARKERS.iter().any(|m| {
                        m.len() >= buf.len() - 1 && buf[..buf.len() - 1] == m[..buf.len() - 1]
                    });

                if is_full {
                    self.tx_suppress_line = true;
                } else if is_prefix {
                    // Keep buffering: a marker may still complete.
                } else if prev_was_prefix {
                    // The marker was aborted mid-line: flush the buffered bytes.
                    let _ = stdout.write_all(buf);
                } else {
                    let _ = stdout.write_all(&[ch]);
                }
            }

            if ch == b'\n' {
                self.tx_suppress_line = false;
                let line = std::mem::take(&mut self.tx_line);
                self.process_console_line(&line);
            }
        }
        let _ = stdout.flush();
    }

    /// Handle one complete guest console line (marker side effects only —
    /// visible output has already been streamed to stdout).
    fn process_console_line(&mut self, line: &[u8]) {
        let Ok(line) = std::str::from_utf8(line) else {
            return;
        };
        let trimmed = line.trim_end_matches(['\n', '\r']);

        if let Some(pos) = trimmed.find(initramfs::EXPORT_PATH_MARKER) {
            let path = trimmed[pos + initramfs::EXPORT_PATH_MARKER.len()..].trim();
            if !path.is_empty() {
                self.export_save_path = Some(path.to_string());
            }
        }
    }

    fn handle_hvc(&mut self) -> Result<()> {
        // PSCI via HVC. HVF advances the PC past the HVC itself, so we only
        // set x0 to the PSCI return value.
        let fid = self.vcpu.read_register(HvReg::X0)?;
        let ret: u64 = match fid {
            0x8400_0000 => 0x0000_0001_0000_0002, // PSCI_VERSION → 1.1
            0x8400_0002 => 0,                     // CPU_OFF: success
            0xc400_0003 | 0x8400_0003 => 0,       // CPU_ON: single CPU, treat as success
            0x8400_0008 | 0x8400_0009 => {
                // SYSTEM_OFF / SYSTEM_RESET: stop the VM.
                self.guest_shutdown = true;
                0
            }
            0x8400_0005 => 0, // MIGRATE_INFO_TYPE → TOS migration not required
            0x8400_0004 | 0xc400_0004 => 0, // AFFINITY_INFO: on
            0x8400_0006 | 0xc400_0006 => 0xffff_ffff_ffff_fffe, // MIGRATE: not supported
            _ => 0xffff_ffff_ffff_ffff, // unknown → -1 (SMCCC)
        };
        self.vcpu.write_register(HvReg::X0, ret)?;
        Ok(())
    }

    /// Decode a data-abort and dispatch to the device at the fault address.
    fn handle_data_abort(&mut self, syndrome: u64) -> Result<()> {
        let isv = (syndrome >> 24) & 1 != 0;
        if !isv {
            // Non-synchronized abort (e.g. SIMD); just skip.
            let pc = self.vcpu.read_register(HvReg::Pc)?;
            self.vcpu.write_register(HvReg::Pc, pc + 4)?;
            return Ok(());
        }
        let iswrite = (syndrome >> 6) & 1 != 0;
        let sas = (syndrome >> 22) & 3;
        let len = 1usize << sas;
        let srt = (syndrome >> 16) & 0x1f;
        let sse = (syndrome >> 21) & 1 != 0;
        let addr = self.vcpu.read_fault_address()?;

        if iswrite {
            // Register 31 on a store is WZR/XZR: the value is zero, not X0.
            let val = match HvReg::from_gpr(srt as u8) {
                Some(r) => self.vcpu.read_register(r)?,
                None => 0,
            };
            self.mmio_write(addr, len, val);
        } else {
            let val = self.mmio_read(addr, len, sas as u8);
            let val = if sse && len < 8 {
                // sign-extend from the access width
                let shift = 64 - len * 8;
                ((val << shift) as i64 >> shift) as u64
            } else {
                val
            };
            if let Some(r) = HvReg::from_gpr(srt as u8) {
                self.vcpu.write_register(r, val)?;
            }
        }
        let pc = self.vcpu.read_register(HvReg::Pc)?;
        self.vcpu.write_register(HvReg::Pc, pc + 4)?;
        Ok(())
    }

    fn mmio_read(&mut self, addr: u64, len: usize, sas: u8) -> u64 {
        if (GICD_BASE..GICD_BASE + GICD_SIZE).contains(&addr) {
            return self.gic.gicd_read(addr - GICD_BASE) as u64;
        }
        if (GICR_BASE..GICR_BASE + GICR_SIZE).contains(&addr) {
            return self.gic.gicr_read(addr - GICR_BASE) as u64;
        }
        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x200).contains(&addr) {
            return self.console.mmio_read(addr - VIRTIO_CONSOLE_BASE, sas);
        }
        if let Some(net) = self.net.as_mut() {
            if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + 0x200).contains(&addr) {
                return net.mmio_read(addr - VIRTIO_NET_BASE) as u64;
            }
        }
        if let Some(b) = self.blk.as_mut() {
            if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + 0x200).contains(&addr) {
                return b.mmio_read(addr - VIRTIO_BLK_BASE) as u64;
            }
        }
        if let Some(b) = self.data_blk.as_mut() {
            if (DATA_BLK_BASE..DATA_BLK_BASE + 0x200).contains(&addr) {
                return b.mmio_read(addr - DATA_BLK_BASE) as u64;
            }
        }
        if let Some(rng) = self.rng.as_ref() {
            if (VIRTIO_RNG_BASE..VIRTIO_RNG_BASE + 0x200).contains(&addr) {
                return rng.mmio_read(addr - VIRTIO_RNG_BASE) as u64;
            }
        }
        if let Some(idx) = virtiofs_index(addr) {
            if let Some(dev) = self.virtiofs.get_mut(idx) {
                return dev.mmio_read(addr - VIRTIOFS_BASE_START - idx as u64 * VIRTIOFS_SIZE)
                    as u64;
            }
        }
        if (UART_BASE..UART_BASE + 0x1000).contains(&addr) {
            return self.uart_read(addr - UART_BASE);
        }
        log::warn!("mmio read 0x{addr:x} len {len}");
        0
    }

    fn mmio_write(&mut self, addr: u64, _len: usize, val: u64) {
        if (GICD_BASE..GICD_BASE + GICD_SIZE).contains(&addr) {
            self.gic.gicd_write(addr - GICD_BASE, val as u32);
            return;
        }
        if (GICR_BASE..GICR_BASE + GICR_SIZE).contains(&addr) {
            self.gic.gicr_write(addr - GICR_BASE, val as u32);
            return;
        }
        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x200).contains(&addr) {
            let notify = self
                .console
                .mmio_write(addr - VIRTIO_CONSOLE_BASE, val as u32);
            if let Some(qidx) = notify {
                if qidx == 0 {
                    // RX queue: the guest posted buffers; drain any pending
                    // host input into them.
                    self.console.drain_rx_backlog(&mut self.memory, RAM_BASE);
                }
            }
            return;
        }
        if let Some(b) = self.blk.as_mut() {
            if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - VIRTIO_BLK_BASE, val as u32);
                let _ = b.process_queue(&mut self.memory, RAM_BASE);
                return;
            }
        }
        if let Some(b) = self.data_blk.as_mut() {
            if (DATA_BLK_BASE..DATA_BLK_BASE + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - DATA_BLK_BASE, val as u32);
                let _ = b.process_queue(&mut self.memory, RAM_BASE);
                return;
            }
        }
        if let Some(net) = self.net.as_mut() {
            if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + 0x200).contains(&addr) {
                if let Some(qidx) = net.mmio_write(addr - VIRTIO_NET_BASE, val as u32) {
                    match qidx {
                        1 => {
                            net.process_tx(&mut self.memory, RAM_BASE);
                        }
                        0 => {
                            // Guest posted RX buffers: flush queued packets.
                            net.process_rx(&mut self.memory, RAM_BASE);
                        }
                        _ => {}
                    }
                }
                return;
            }
        }
        if let Some(rng) = self.rng.as_mut() {
            if (VIRTIO_RNG_BASE..VIRTIO_RNG_BASE + 0x200).contains(&addr) {
                if rng.mmio_write(addr - VIRTIO_RNG_BASE, val as u32).is_some() {
                    rng.process_queue(&mut self.memory, RAM_BASE);
                }
                return;
            }
        }
        if let Some(idx) = virtiofs_index(addr) {
            if let Some(dev) = self.virtiofs.get_mut(idx) {
                let off = addr - VIRTIOFS_BASE_START - idx as u64 * VIRTIOFS_SIZE;
                if let Some(qidx) = dev.mmio_write(off, val as u32) {
                    dev.process_queue(qidx, &mut self.memory, RAM_BASE);
                }
                return;
            }
        }
        if (UART_BASE..UART_BASE + 0x1000).contains(&addr) {
            self.uart_write(addr - UART_BASE, val);
            return;
        }
        log::warn!("mmio write 0x{addr:x} = 0x{val:x}");
    }

    /// Minimal PL011 for earlycon: absorb writes, report TX empty / RX empty.
    fn uart_read(&self, off: u64) -> u64 {
        match off {
            0x018 => 0x10, // FR: RXFE=1 (empty), TXFF=0 (ready)
            _ => 0,
        }
    }

    fn uart_write(&mut self, off: u64, val: u64) {
        if off == 0x000 && self.verbose_uart {
            eprint!("{}", (val & 0xff) as u8 as char);
        }
        let _ = val;
    }

    /// Handle an MRS/MSR system-register trap (EC 0x18).
    fn handle_sysreg(&mut self, syndrome: u64) -> Result<()> {
        let isread = syndrome & 1 != 0;
        let rt = ((syndrome >> 5) & 0x1f) as u8;
        let crm = (syndrome >> 1) & 0xf;
        let crn = (syndrome >> 10) & 0xf;
        let op1 = (syndrome >> 14) & 0x7;
        let op2 = (syndrome >> 17) & 0x7;
        let op0 = (syndrome >> 20) & 0x3;

        // Advance past the MRS/MSR instruction (4 bytes) for every trap.
        let pc = self.vcpu.read_register(HvReg::Pc)?;
        self.vcpu.write_register(HvReg::Pc, pc + 4)?;

        // ICC (GIC CPU interface) system registers.
        if op0 == 3 && op1 == 0 {
            match (crn, crm, op2) {
                (4, 6, 0) => {
                    // ICC_PMR_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_pmr as u64)?;
                    } else {
                        self.gic.icc_pmr = (self.read_gpr(rt)? & 0xff) as u8;
                    }
                    return Ok(());
                }
                (12, 12, 0) => {
                    // ICC_IAR1_EL1
                    let intid = self.gic.ack() as u64;
                    self.write_gpr(rt, intid)?;
                    return Ok(());
                }
                (12, 12, 1) => {
                    // ICC_EOIR1_EL1
                    let intid = (self.read_gpr(rt)? & 0x3ff) as u32;
                    self.gic.eoi(intid);
                    if intid == IRQ_VTIMER {
                        self.unmask_vtimer()?;
                    }
                    return Ok(());
                }
                (12, 11, 1) => {
                    // ICC_DIR_EL1 (deactivate)
                    let intid = (self.read_gpr(rt)? & 0x3ff) as u32;
                    self.gic.eoi(intid);
                    if intid == IRQ_VTIMER {
                        self.unmask_vtimer()?;
                    }
                    return Ok(());
                }
                (12, 12, 3) => {
                    // ICC_BPR1_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_bpr1 as u64)?;
                    } else {
                        self.gic.icc_bpr1 = (self.read_gpr(rt)? & 0x7) as u8;
                    }
                    return Ok(());
                }
                (12, 12, 4) => {
                    // ICC_CTLR_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_ctlr as u64)?;
                    }
                    return Ok(());
                }
                (12, 12, 5) => {
                    // ICC_SRE_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_sre as u64)?;
                    } else {
                        self.gic.icc_sre = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 12, 6) => {
                    // ICC_IGRPEN0_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_igrpen0 as u64)?;
                    } else {
                        self.gic.icc_igrpen0 = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 12, 7) => {
                    // ICC_IGRPEN1_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_igrpen1 as u64)?;
                    } else {
                        self.gic.icc_igrpen1 = (self.read_gpr(rt)? & 1) as u32;
                    }
                    return Ok(());
                }
                (12, 9, 0) => {
                    // ICC_AP1R0_EL1
                    if isread {
                        self.write_gpr(rt, self.gic.icc_ap1r0 as u64)?;
                    } else {
                        self.gic.icc_ap1r0 = (self.read_gpr(rt)? & 0xffff_ffff) as u32;
                    }
                    return Ok(());
                }
                (12, 8, 0) => {
                    // ICC_IAR0_EL1 — no group-0 interrupts; spurious.
                    if isread {
                        self.write_gpr(rt, 1023)?;
                    }
                    return Ok(());
                }
                _ => {}
            }
        }

        // Counter-timer registers. CRn=14, EL0. Encodings (per ARM ARM D11 and
        // Linux arch/arm64/include/asm/sysreg.h):
        //   CNTFRQ_EL0  (0,0)   CNTPCT_EL0   (0,1)   CNTVCT_EL0   (0,2)
        //   CNTPCTSS_EL0(0,5)   CNTVCTSS_EL0 (0,6)
        //   CNTP_TVAL   (2,0)   CNTP_CTL     (2,1)   CNTP_CVAL    (2,2)
        //   CNTV_TVAL   (3,0)   CNTV_CTL     (3,1)   CNTV_CVAL    (3,2)
        // The counter reads are synthesized from mach_absolute_time (the host
        // CNTPCT) minus CNTVOFF for the virtual counter; HVF rejects EL2 reads
        // of CNTVCT/CNTPCT, so a guest read that traps here would otherwise see
        // a frozen counter and spin in __delay.
        if op0 == 3 && op1 == 3 && crn == 14 {
            let now = unsafe { mach_absolute_time() };
            let now_virt = now.wrapping_sub(self.vt_off);
            match (crm, op2) {
                (0, 0) => {
                    // CNTFRQ_EL0
                    if isread {
                        self.write_gpr(rt, CNTFRQ)?;
                    }
                    return Ok(());
                }
                (0, 1) | (0, 5) => {
                    // CNTPCT_EL0 / CNTPCTSS_EL0: raw host counter.
                    if isread {
                        self.write_gpr(rt, now)?;
                    }
                    return Ok(());
                }
                (0, 2) | (0, 6) => {
                    // CNTVCT_EL0 / CNTVCTSS_EL0: CNTPCT minus CNTVOFF (the
                    // vtimer offset set once at VM creation).
                    if isread {
                        self.write_gpr(rt, now_virt)?;
                    }
                    return Ok(());
                }
                (2, 1) => {
                    // CNTP_CTL_EL0: this VM only uses the virtual timer, so
                    // tolerate HVF rejecting physical-timer accesses instead of
                    // failing the whole run loop.
                    if isread {
                        let v = self
                            .vcpu
                            .read_sys_register(HvSysReg::CntpCtlEl0)
                            .unwrap_or(0);
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        let _ = self.vcpu.write_sys_register(HvSysReg::CntpCtlEl0, v);
                    }
                    return Ok(());
                }
                (3, 0) => {
                    // CNTV_TVAL_EL0 — the arm64 clockevent writes this 32-bit
                    // relative value to arm the next tick.  Translate it into
                    // an absolute CVAL for the HVF virtual timer, otherwise the
                    // comparator never moves and the timer IRQ storms forever.
                    if isread {
                        let cval = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0)?;
                        let tval = cval.wrapping_sub(now_virt) as u32;
                        self.write_gpr(rt, tval as u64)?;
                    } else {
                        let tval = self.read_gpr(rt)? as u32 as i32 as i64;
                        let cval = (now_virt as i64).wrapping_add(tval) as u64;
                        self.vcpu.write_sys_register(HvSysReg::CntvCvalEl0, cval)?;
                    }
                    return Ok(());
                }
                (3, 1) => {
                    // CNTV_CTL_EL0: forward to HVF's virtual timer
                    if isread {
                        let v = self.vcpu.read_sys_register(HvSysReg::CntvCtlEl0)?;
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        self.vcpu.write_sys_register(HvSysReg::CntvCtlEl0, v)?;
                    }
                    return Ok(());
                }
                (3, 2) => {
                    // CNTV_CVAL_EL0: forward to HVF's virtual timer
                    if isread {
                        let v = self.vcpu.read_sys_register(HvSysReg::CntvCvalEl0)?;
                        self.write_gpr(rt, v)?;
                    } else {
                        let v = self.read_gpr(rt)?;
                        self.vcpu.write_sys_register(HvSysReg::CntvCvalEl0, v)?;
                    }
                    return Ok(());
                }
                _ => {
                    // Other timer regs (e.g. CNTP_TVAL/CNTP_CVAL): synthesize a
                    // consistent value, ignore writes.
                    if isread {
                        self.write_gpr(rt, 0)?;
                    }
                    return Ok(());
                }
            }
        }

        // Feature ID registers: return curated values.  These reads normally do
        // not trap (native EL1 reads); the values below only matter if HVF does
        // route them to the VMM.  The guest kernel is built for 48-bit VA, and
        // Apple Silicon HVF reports 48-bit VA, so VARange is reported as 0.
        if op0 == 3 && op1 == 0 && crn == 0 {
            let v = match (crm, op2) {
                (0, 0) => 0x411f_d070u64, // MIDR_EL1 (Cortex-A57)
                (4, 0) => 0x110_011u64,   // ID_AA64PFR0: EL0/EL1/FP/ASIMD
                (7, 0) => 0x5u64,         // ID_AA64MMFR0: 48-bit PARange
                (2, 1) => 0u64,           // ID_AA64MMFR2: VARange=0 (48-bit VA)
                _ => 0,
            };
            if isread {
                self.write_gpr(rt, v)?;
            }
            return Ok(());
        }

        // Unknown sysreg: permissive (read 0 / ignore write).
        if isread {
            self.write_gpr(rt, 0)?;
        }
        Ok(())
    }

    fn unmask_vtimer(&mut self) -> Result<()> {
        if self.vtimer_masked {
            self.vcpu.set_vtimer_mask(false)?;
            self.vtimer_masked = false;
        }
        Ok(())
    }

    fn write_gpr(&mut self, rt: u8, val: u64) -> Result<()> {
        if let Some(r) = HvReg::from_gpr(rt) {
            self.vcpu.write_register(r, val)?;
        }
        Ok(())
    }

    fn read_gpr(&mut self, rt: u8) -> Result<u64> {
        match HvReg::from_gpr(rt) {
            Some(r) => self.vcpu.read_register(r),
            None => Ok(0),
        }
    }

    /// Poll host stdin; forward any input to the guest console RX.
    fn poll_stdin(&mut self) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 0) };
        if n > 0 && pfd.revents & libc::POLLIN != 0 {
            self.drain_stdin()?;
        }
        Ok(())
    }

    fn drain_stdin(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if n == 0 {
                return Ok(());
            }
            self.console
                .push_rx_and_drain(&mut self.memory, RAM_BASE, &buf[..n as usize]);
        }
    }
}
