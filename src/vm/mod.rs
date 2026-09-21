//! The shared VM core: guest RAM, device dispatch, the console protocol
//! (markers, escape tracking, DSR replies), the export/exit handlers, and
//! the platform-specific setup that the per-OS run loops drive.
//!
//! Layout of this module:
//! - [`GuestRam`]: the page-aligned guest RAM mapping (KVM requires
//!   page-aligned user memory regions).
//! - [`Vmm`]: the virtual machine monitor state and its entry points.
//! - The per-platform pieces live in the sibling modules (`aarch64`,
//!   `x86_64`, `macos`, `linux`); this module owns everything both
//!   architectures share.

#[cfg(target_os = "macos")]
use crate::hypervisor::Gic;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::atomic::Ordering;

use crate::hypervisor::{Vcpu, Vm};
use crate::initramfs;
use crate::net::NetworkFilter;
use crate::unet::UserNet;
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::console::VirtioConsoleDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;
use anyhow::{anyhow, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub(crate) use crate::cli::Args;
pub(crate) use crate::irqs::{SPI_BLK, SPI_CONSOLE, SPI_DATA_BLK, SPI_FS_START, SPI_NET, SPI_RNG};
#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{MAX_FS_DEVICES, RAM_BASE};
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::x86_hypercall_page_off;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::{MAX_FS_DEVICES, RAM_BASE};

// ── Virtio-MMIO device addresses (both architectures) ──────────────────
#[cfg(target_arch = "x86_64")]
pub(crate) const MMIO_BASE: u64 = 0x0a00_0000;
pub(crate) const VIRTIO_NET_BASE: u64 = 0x0a00_0000;
pub(crate) const VIRTIO_CONSOLE_BASE: u64 = 0x0a00_0200;
pub(crate) const VIRTIO_BLK_BASE: u64 = 0x0a00_0400;
pub(crate) const DATA_BLK_BASE: u64 = 0x0a00_0600;
pub(crate) const VIRTIO_RNG_BASE: u64 = 0x0a00_0800;
pub(crate) const VIRTIOFS_BASE_START: u64 = 0x0a00_1000;
pub(crate) const VIRTIOFS_SIZE: u64 = 0x200;

// ── Host terminal helpers ────────────────────────────────────────────────

/// Put the host terminal in raw mode: disable echo, canonical mode and
/// signal generation so every keystroke (including Tab and the guest line
/// editor's CSI queries) is forwarded to the guest verbatim instead of
/// being line-buffered/echoed by the host tty. Returns the original
/// settings for restore.
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

/// Disable output post-processing (OPOST/ONLCR) on the console fd. The
/// guest console stream is already fully formed (the guest tty applies
/// ONLCR and its console driver inserts CRs); the host tty re-applying
/// ONLCR turned every guest newline into `\r\r\n` on the pane. Returns
/// the original settings for restore.
fn disable_output_processing(fd: RawFd) -> Option<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut orig) != 0 {
            return None;
        }
        let mut raw = orig;
        raw.c_oflag &= !(libc::OPOST | libc::ONLCR);
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
        Some(orig)
    }
}

// ── Guest RAM ────────────────────────────────────────────────────────────

/// Page-aligned guest RAM. KVM's `KVM_SET_USER_MEMORY_REGION` requires a
/// page-aligned userspace mapping, which `Vec<u8>` does not guarantee.
pub(crate) struct GuestRam {
    ptr: *mut u8,
    len: usize,
}

impl GuestRam {
    fn new(len: usize) -> Self {
        assert_eq!(len % 4096, 0, "guest RAM size must be page-aligned");
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            panic!("failed to mmap {len} bytes of guest RAM");
        }
        let ptr = ptr as *mut u8;
        unsafe { std::ptr::write_bytes(ptr, 0, len) };
        GuestRam { ptr, len }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The guest RAM as a byte slice. The VMM and the guest CPU both access
    /// this memory concurrently — it is the guest's physical address space,
    /// not ordinary Rust state — hence the raw-pointer escape hatch (and the
    /// deliberate `&self -> &mut [u8]` signature: every device call site
    /// holds the RAM through an shared `Arc`).
    #[allow(clippy::mut_from_ref)]
    pub(crate) fn as_shared_slice(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

// The guest CPU thread reads/writes this memory while the VMM drives
// devices through it; that sharing is the entire point of the mapping.
unsafe impl Send for GuestRam {}
unsafe impl Sync for GuestRam {}

impl Drop for GuestRam {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

// ── The virtual machine monitor ──────────────────────────────────────────

struct Vmm {
    // Field drop order matters: the hypervisor requires the vCPU to be
    // destroyed before the VM, and Rust drops fields in declaration order.
    vcpu: Vcpu,
    #[allow(dead_code)] // keeps the VM (and its Drop) alive
    vm: Vm,
    memory: Arc<GuestRam>,
    #[cfg(target_os = "macos")]
    gic: Gic,
    /// Console device (shared with the stdin poller thread on Linux, which
    /// injects keystrokes directly into the RX virtqueue).
    console: Arc<Mutex<VirtioConsoleDevice>>,
    blk: Option<VirtioBlkDevice>,
    data_blk: Option<VirtioBlkDevice>,
    /// Net device behind a mutex: the Linux net-kick thread pumps the
    /// backend and raises the net IRQ independently of the run loop (an
    /// idle guest would otherwise wait for its own delayed-ACK exit before
    /// more host data is delivered).
    net: Arc<Mutex<Option<VirtioNetDevice>>>,
    rng: Option<VirtioRngDevice>,
    virtiofs: Vec<VirtioFsDevice>,
    config_blob: Vec<u8>,
    #[cfg(target_os = "linux")]
    host: linux::KvmHost,
    /// Set on drop so the net-kick thread exits.
    #[cfg(target_os = "linux")]
    net_kick_stop: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(target_os = "macos")]
    vt_off: u64,
    #[cfg(target_os = "macos")]
    vtimer_masked: bool,
    #[cfg(target_os = "macos")]
    /// Last value written to the vtimer pending-interrupt state; the
    /// pending state is one-shot (cleared after `hv_vcpu_run`), so an
    /// asserted line is re-written every iteration and a redundant `false`
    /// write is skipped.
    irq_line_asserted: bool,
    tty_saved: Option<libc::termios>,
    /// Original stdout termios (OPOST restored on exit).
    tty_out_saved: Option<libc::termios>,
    guest_shutdown: bool,
    verbose_uart: bool,
    /// Per-boot exit-protocol token (x86_64): the init script echoes
    /// `<token><status>`; the VMM only treats that as the protocol, so
    /// user output containing the old fixed `SANDAL_EXIT:0` string is
    /// just output. The arm64 crafted init binary keeps the fixed marker.
    exit_marker: String,
    /// Save path from the guest's `SANDAL_EXPORT_PATH:` console marker.
    export_save_path: Option<String>,
    /// Console TX line buffer used to intercept VMM protocol markers.
    tx_line: Vec<u8>,
    /// Bytes held back because they may start a protocol marker (suffix scan).
    tx_hold: Vec<u8>,
    /// True while the current TX line is a suppressed protocol marker line.
    tx_suppress_line: bool,
    /// Guest command exit status from the exit marker.
    guest_exit_code: Option<i32>,
    /// Virtual-terminal escape tracking: the guest's line editor (busybox
    /// ash) probes the terminal with `ESC [ 6 n` (device status report:
    /// cursor position) and reads the reply from its input. The VMM is the
    /// virtual terminal: it intercepts that one query and answers it from a
    /// conservatively tracked cursor position, so the editor's line-wrap
    /// and redraw logic stay correct on long input lines. Every OTHER
    /// escape sequence (erase, colors, cursor movement) is forwarded to
    /// the user's terminal untouched — swallowing those breaks guest-side
    /// erases like the backspace path's `ESC [ J`.
    vt_esc: bool,
    vt_csi: u8,
    /// Bytes of the escape sequence currently being parsed.
    vt_seq: Vec<u8>,
    /// Numeric parameter accumulated from the current CSI sequence.
    vt_param: u32,
    /// True when the accumulated CSI parameter is 6 (a DSR query).
    vt_dsr: bool,
    /// Tracked terminal cursor (1-based) for DSR cursor-position replies.
    vt_row: u32,
    vt_col: u32,
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
            bail_shares()?;
        }
        let (host, guest) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid --share {spec:?} (expected host_path:guest_path)"))?;
        let host_path = PathBuf::from(host);
        if !host_path.is_dir() {
            bail_shares_dir(host)?;
        }
        shares.push((format!("share{i}"), host_path, guest.to_string()));
    }
    Ok(shares)
}

fn bail_shares() -> Result<()> {
    anyhow::bail!("too many shared directories (max {MAX_FS_DEVICES})");
}

fn bail_shares_dir(host: &str) -> Result<()> {
    anyhow::bail!("shared path is not a directory: {host}");
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

/// Run a VM to execute the requested command, returning the guest's exit
/// status when it exits.
pub fn run(args: Args) -> Result<i32> {
    let mut vmm = Vmm::new(&args)?;
    vmm.boot(&args)?;
    #[cfg(target_os = "linux")]
    {
        vmm.run_loop_kvm(&args)
    }
    #[cfg(target_os = "macos")]
    {
        vmm.run_loop_hvf(&args)
    }
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
// VM construction
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    fn new(args: &Args) -> Result<Self> {
        let vm = Vm::new()?;

        // In-kernel interrupt controllers must exist before the first vCPU:
        // x86_64 gets the PIC+PIT (the guest timer), arm64 the GICv3.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        vm.create_irqchip()?;
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        vm.create_vgic(
            aarch64::GICD_BASE,
            aarch64::GICD_SIZE,
            aarch64::GICR_BASE,
            aarch64::GICR_SIZE,
        )?;

        #[cfg(target_os = "linux")]
        let vcpu = Vcpu::new(&vm)?;
        #[cfg(target_os = "macos")]
        let vcpu = Vcpu::new()?;

        // Guest RAM. On x86_64 the virtio-mmio device window sits at
        // MMIO_BASE (160 MB) inside the flat physical address space, so the
        // RAM is capped below it — the kernel's request_mem_region for each
        // device would otherwise collide with "System RAM" (-EBUSY) and no
        // device would ever probe.
        #[cfg(target_arch = "x86_64")]
        let ram_bytes = (args.memory.max(64) * 1024 * 1024).min(MMIO_BASE as usize);
        #[cfg(target_arch = "aarch64")]
        let ram_bytes = args.memory.max(64) * 1024 * 1024;
        let memory = Arc::new(GuestRam::new(ram_bytes));
        vm.map_memory(
            memory.as_shared_slice().as_ptr() as *mut _,
            RAM_BASE,
            memory.len(),
            crate::hypervisor::HV_MEMORY_READ
                | crate::hypervisor::HV_MEMORY_WRITE
                | crate::hypervisor::HV_MEMORY_EXEC,
        )?;

        // Per-platform vCPU bring-up: the arm64 BRK #imm init protocol must
        // trap to the VMM (KVM_EXIT_DEBUG) instead of SIGTRAP; the macos
        // vtimer offset is set once (the guest counter starts near 0).
        #[cfg(target_os = "macos")]
        let vt_off = macos::hvf_setup(&vcpu)?;

        // Host stdin is the interactive pty: raw mode so every keystroke
        // reaches the guest verbatim; the original settings are restored on
        // exit. stdout is the guest console stream: OPOST/ONLCR disabled so
        // the already-formed guest output is not re-processed.
        let (tty_saved, tty_out_saved) = unsafe {
            let saved = if libc::isatty(0) != 0 {
                enable_raw_mode(0)
            } else {
                None
            };
            let out_saved = if libc::isatty(1) != 0 {
                disable_output_processing(1)
            } else {
                None
            };
            #[cfg(target_os = "macos")]
            {
                let fl = libc::fcntl(0, libc::F_GETFL);
                let _ = libc::fcntl(0, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            (saved, out_saved)
        };

        let console = Arc::new(Mutex::new(VirtioConsoleDevice::new(120, 40)));

        // User-space networking (enabled unless --no-network). The run loops
        // poll the backend after every guest exit and the Linux net-kick
        // thread pumps it independently, so an idle guest never waits for
        // its own delayed-ACK timer before more host data is delivered.
        let net = if args.no_network {
            Arc::new(Mutex::new(None))
        } else {
            let backend =
                UserNet::new().map_err(|e| anyhow!("failed to create user-space network: {e}"))?;

            let mut filter = NetworkFilter::new();

            filter.set_protocols(NetworkFilter::parse_protocols(&args.protocols));
            if let Some(ref hosts) = args.allowed_hosts {
                filter.set_allowed_hosts(NetworkFilter::parse_hosts(hosts));
            }

            Arc::new(Mutex::new(Some(VirtioNetDevice::new(backend, filter))))
        };

        // Per-boot exit-protocol token (x86_64): the init script echoes
        // `<token><status>`; the VMM only treats that as the protocol, so
        // user output containing the old fixed `SANDAL_EXIT:0` string is
        // just output.
        let exit_marker = {
            #[cfg(target_arch = "x86_64")]
            {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);

                let mut h = std::collections::hash_map::DefaultHasher::new();
                (nanos, std::process::id(), args.command.first()).hash(&mut h);
                format!("{:08x}", h.finish() as u32)
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                initramfs::EXIT_MARKER.trim_end_matches(':').to_string()
            }
        };

        #[cfg(target_os = "linux")]
        let host = {
            let irq_lock = Arc::new(Mutex::new(()));
            let (stdin_thread, stdin_stop_w) = linux::spawn_stdin_poller(
                vm.clone(),
                console.clone(),
                memory.clone(),
                irq_lock.clone(),
            )?;
            linux::KvmHost {
                irq_lock,
                stdin_stop_w,
                stdin_thread: Some(stdin_thread),
                irq_levels: [false; linux::NUM_TRACKED_SPIS],
            }
        };

        #[cfg(target_os = "linux")]
        let net_kick_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        #[cfg(target_os = "linux")]
        linux::spawn_net_kicker(
            vm.clone(),
            net.clone(),
            memory.clone(),
            host.irq_lock.clone(),
            net_kick_stop.clone(),
        );

        let mut virtiofs = Vec::new();
        for (tag, host_path, _guest) in parse_shares(args)? {
            virtiofs.push(VirtioFsDevice::new(host_path, tag));
        }

        Ok(Vmm {
            vcpu,
            vm,
            memory,
            #[cfg(target_os = "macos")]
            gic: Gic::new(),
            console,
            blk: None,
            data_blk: None,
            net,
            rng: Some(VirtioRngDevice::new()),
            virtiofs,
            config_blob: Vec::new(),
            #[cfg(target_os = "linux")]
            host,
            #[cfg(target_os = "linux")]
            net_kick_stop,
            #[cfg(target_os = "macos")]
            vt_off,
            #[cfg(target_os = "macos")]
            vtimer_masked: false,
            #[cfg(target_os = "macos")]
            irq_line_asserted: false,
            tty_saved,
            tty_out_saved,
            guest_shutdown: false,
            verbose_uart: args.verbose,
            exit_marker,
            export_save_path: None,
            tx_line: Vec::new(),
            tx_hold: Vec::new(),
            tx_suppress_line: false,
            guest_exit_code: None,
            vt_esc: false,
            vt_csi: 0,
            vt_seq: Vec::new(),
            vt_param: 0,
            vt_dsr: false,
            vt_row: 1,
            vt_col: 1,
        })
    }

    fn boot(&mut self, args: &Args) -> Result<()> {
        // ── Writable data disk (vdb): --disk-size / --layer ────────────
        // Created first: DISK_MODE in the init config selects the overlay
        // upperdir (disk vs tmpfs), so `data_blk` must be known by then.
        if args.disk_size.is_some() || !args.layers.is_empty() {
            self.data_blk = Some(VirtioBlkDevice::new(build_data_disk(args)?));
        }

        // ── Init config blob ───────────────────────────────────────────
        // arm64: delivered at the INIT_CONFIG BRK hypercall. x86_64: injected
        // into the rootfs as /etc/sandal.conf (a plain file read needs no
        // I/O-port privileges, which nested KVM denies to userspace).
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

        #[cfg(target_arch = "x86_64")]
        {
            let (cols, rows) = self.console.lock().unwrap().terminal_size();
            self.config_blob = initramfs::build_init_config_text(
                disk_mode,
                &share_configs,
                &args.command,
                !args.no_network,
                clock_secs,
                cols,
                rows,
                &self.exit_marker,
            );
        }

        #[cfg(target_arch = "aarch64")]
        {
            self.config_blob = initramfs::build_init_config(
                disk_mode,
                &share_configs,
                &args.command,
                !args.no_network,
                clock_secs,
            );
        }

        // ── Root filesystem (vda): busybox ext2 + runtime files ───────
        let mut rootfs_img = match &args.rootfs {
            Some(path) => fs::read(path)
                .map_err(|e| anyhow!("failed to read rootfs {}: {e}", path.display()))?,
            None => crate::rootfs::load(),
        };

        crate::ext2::inject_runtime_files(&mut rootfs_img, !args.no_network)?;

        #[cfg(target_arch = "x86_64")]
        {
            // The init script reads the run configuration from this file.
            let sb = crate::ext2::Ext2Superblock::parse(&rootfs_img)?;
            let bgdt = crate::ext2::Ext2BgdTable::parse(&rootfs_img, &sb)?;
            crate::ext2::inject_file(
                &mut rootfs_img,
                &sb,
                &bgdt,
                crate::vm::x86_64::CONFIG_PATH,
                &self.config_blob,
                0o644,
            )?;
        }

        self.blk = Some(VirtioBlkDevice::new(rootfs_img));

        // ── Load the kernel ─────────────────────────────────────────────
        #[cfg(target_arch = "x86_64")]
        self.boot_kernel_x86(args)?;

        #[cfg(target_arch = "aarch64")]
        self.boot_kernel_arm64(args)?;

        Ok(())
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.net_kick_stop.store(true, Ordering::Relaxed);

        if let Some(ref orig) = self.tty_out_saved {
            restore_terminal(1, orig);
        }

        if let Some(ref orig) = self.tty_saved {
            restore_terminal(0, orig);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device dispatch (MMIO) — both architectures share the virtio-MMIO layout;
// the GIC (arm64) and the hypercall page (x86_64) are arch-specific.
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    fn mmio_read(&mut self, addr: u64, len: usize, sas: u8) -> u64 {
        #[cfg(target_os = "macos")]
        {
            if (aarch64::GICD_BASE..aarch64::GICD_BASE + aarch64::GICD_SIZE).contains(&addr) {
                return self.gic.gicd_read(addr - aarch64::GICD_BASE) as u64;
            }

            if (aarch64::GICR_BASE..aarch64::GICR_BASE + aarch64::GICR_SIZE).contains(&addr) {
                return self.gic.gicr_read(addr - aarch64::GICR_BASE) as u64;
            }
        }

        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x200).contains(&addr) {
            return self
                .console
                .lock()
                .unwrap()
                .mmio_read(addr - VIRTIO_CONSOLE_BASE, sas);
        }

        if let Some(net) = self.net.lock().unwrap().as_mut() {
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

        #[cfg(target_arch = "aarch64")]
        if (aarch64::UART_BASE..aarch64::UART_BASE + 0x1000).contains(&addr) {
            return self.uart_read(addr - aarch64::UART_BASE);
        }

        log::debug!("mmio read 0x{addr:x} len {len}");

        0
    }

    fn mmio_write(&mut self, addr: u64, _len: usize, val: u64) {
        #[cfg(target_os = "macos")]
        {
            if (aarch64::GICD_BASE..aarch64::GICD_BASE + aarch64::GICD_SIZE).contains(&addr) {
                self.gic.gicd_write(addr - aarch64::GICD_BASE, val as u32);
                return;
            }
            if (aarch64::GICR_BASE..aarch64::GICR_BASE + aarch64::GICR_SIZE).contains(&addr) {
                self.gic.gicr_write(addr - aarch64::GICR_BASE, val as u32);
                return;
            }
        }

        if (VIRTIO_CONSOLE_BASE..VIRTIO_CONSOLE_BASE + 0x200).contains(&addr) {
            let mut console = self.console.lock().unwrap();
            let notify = console.mmio_write(addr - VIRTIO_CONSOLE_BASE, val as u32);
            if let Some(qidx) = notify {
                if qidx == 0 {
                    // RX queue: the guest posted buffers; drain any pending
                    // host input into them.
                    console.drain_rx_backlog(self.memory.as_shared_slice(), RAM_BASE);
                }
            }

            return;
        }

        if let Some(b) = self.blk.as_mut() {
            if (VIRTIO_BLK_BASE..VIRTIO_BLK_BASE + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - VIRTIO_BLK_BASE, val as u32);
                let _ = b.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                return;
            }
        }

        if let Some(b) = self.data_blk.as_mut() {
            if (DATA_BLK_BASE..DATA_BLK_BASE + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - DATA_BLK_BASE, val as u32);
                let _ = b.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                return;
            }
        }

        if let Some(net) = self.net.lock().unwrap().as_mut() {
            if (VIRTIO_NET_BASE..VIRTIO_NET_BASE + 0x200).contains(&addr) {
                if let Some(qidx) = net.mmio_write(addr - VIRTIO_NET_BASE, val as u32) {
                    match qidx {
                        1 => {
                            net.process_tx(self.memory.as_shared_slice(), RAM_BASE);
                        }
                        0 => {
                            // Guest posted RX buffers: flush queued packets.
                            net.process_rx(self.memory.as_shared_slice(), RAM_BASE);
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
                    rng.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                }
                return;
            }
        }

        if let Some(idx) = virtiofs_index(addr) {
            if let Some(dev) = self.virtiofs.get_mut(idx) {
                let off = addr - VIRTIOFS_BASE_START - idx as u64 * VIRTIOFS_SIZE;
                if let Some(qidx) = dev.mmio_write(off, val as u32) {
                    dev.process_queue(qidx, self.memory.as_shared_slice(), RAM_BASE);
                }
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        if (aarch64::UART_BASE..aarch64::UART_BASE + 0x1000).contains(&addr) {
            self.uart_write(addr - aarch64::UART_BASE, val);
            return;
        }

        #[cfg(target_arch = "x86_64")]
        if (x86_64::HYPERCALL_PAGE..x86_64::HYPERCALL_PAGE + 0x200).contains(&addr) {
            // Hypercall page: a u32 write of the port number signals the VMM
            // (the x86 analog of the ARM64 BRK immediates).
            match val as u16 {
                crate::elf::x86_64_linux::EXPORT_RESIZE_PORT => self.handle_export_resize(),
                crate::elf::x86_64_linux::EXPORT_DONE_PORT => self.handle_export_done(),
                other => log::warn!("unknown hypercall {other:#x}"),
            }
            return;
        }

        log::debug!("mmio write 0x{addr:x} = 0x{val:x}");
    }

    /// `export resize`: grow /dev/vdb so the guest can write a tar archive
    /// onto it (tmpfs-upper export path), then signal a virtio config change
    /// so the kernel re-reads the device capacity.
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

    /// `export done`: turn the guest's overlay upper tree into a
    /// gzip-compressed `.layer` file on the host.
    ///
    /// Disk mode: the data disk is an ext2 image; its `upper/` subtree is
    /// extracted and serialized as a ustar archive.
    /// Tmpfs mode: the guest wrote an uncompressed tar to the raw device.
    fn handle_export_done(&mut self) {
        log::info!(
            "export: DONE hypercall, save_path={:?}",
            self.export_save_path
        );
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
    /// protocol markers (the per-boot exit token and
    /// `SANDAL_EXPORT_PATH:`), which are consumed here instead of being
    /// shown to the user.
    fn process_console_tx(&mut self, data: &[u8]) {
        let mut dsr_reply: Option<(u32, u32)> = None;
        let exit_marker = self.exit_marker.clone();
        let markers: [&[u8]; 2] = [
            exit_marker.as_bytes(),
            initramfs::EXPORT_PATH_MARKER.as_bytes(),
        ];
        let mut stdout = std::io::stdout();

        for &ch in data {
            if self.guest_shutdown {
                // The guest is shutting down; drop any trailing kernel output
                // (e.g. the poweroff path's `reboot: Power down`).
                break;
            }

            // ── Virtual-terminal escape handling ──────────────────────
            // The guest's line editor (busybox ash) probes the terminal
            // with `ESC [ 6 n` (device status report: cursor position) and
            // reads the reply from its input. The VMM is the virtual
            // terminal: it intercepts that one query and answers it from a
            // conservatively tracked cursor position, so the editor's
            // line-wrap and redraw logic stay correct on long input lines.
            // Every OTHER escape sequence (erase, colors, cursor movement)
            // is forwarded to the user's terminal untouched — swallowing
            // those breaks guest-side erases like the backspace path's
            // `ESC [ J`.
            if self.vt_esc {
                self.vt_seq.push(ch);
                if self.vt_csi == 0 {
                    if ch == b'[' {
                        self.vt_csi = b'[';
                    } else {
                        // Two-byte non-CSI escape (e.g. ESC 7): forward.
                        self.end_vt_sequence(&mut dsr_reply);
                    }
                    continue;
                }

                if ch.is_ascii_digit() {
                    self.vt_param = self.vt_param * 10 + (ch - b'0') as u32;
                }

                if (0x40..=0x7e).contains(&ch) {
                    // Final byte: the sequence is complete.
                    self.end_vt_sequence(&mut dsr_reply);
                }

                continue;
            }

            if ch == 0x1b {
                self.vt_esc = true;
                self.vt_csi = 0;
                self.vt_seq.clear();
                self.vt_seq.push(0x1b);
                self.vt_param = 0;
                self.vt_dsr = false;
                continue;
            }

            // Advance the tracked cursor: printable characters move it
            // right; a backspace moves it left (the guest erases with
            // `BS ESC[J`, so this keeps the position honest); newlines
            // restart the line.
            if (0x20..0x7f).contains(&ch) {
                self.vt_col += 1;
            } else if ch == b'\x08' {
                self.vt_col = self.vt_col.saturating_sub(1);
            } else if ch == b'\n' || ch == b'\r' {
                self.vt_col = 0;
                self.vt_row += 1;
            }

            self.emit_tx_byte(ch, &mut stdout, &markers);

            if ch == b'\n' {
                self.tx_suppress_line = false;
                self.tx_hold.clear();
                let line = std::mem::take(&mut self.tx_line);
                self.process_console_line(&line);
            }
        }

        let _ = stdout.flush();

        // Answer cursor-position queries (DSR): the reply goes into the
        // console RX — the guest's line editor reads it as terminal input.
        if let Some((row, col)) = dsr_reply {
            let reply = format!("\x1b[{row};{col}R");
            self.console.lock().unwrap().push_rx_and_drain(
                self.memory.as_shared_slice(),
                RAM_BASE,
                reply.as_bytes(),
            );

            #[cfg(target_os = "linux")]
            {
                let line = self.irq_line_for_spi(crate::irqs::SPI_CONSOLE);
                let _ = self.vm.irq_line(line, true);

                #[cfg(target_arch = "x86_64")]
                {
                    let _ = self.vm.irq_line(line, false);
                    let _ = self.vm.irq_line(line, true);
                }
            }
        }
    }

    /// Finish the escape sequence accumulated in `vt_seq`: answer DSR
    /// cursor-position queries, forward everything else to the user's
    /// terminal, and apply cursor-movement sequences to the tracker.
    fn end_vt_sequence(&mut self, dsr_reply: &mut Option<(u32, u32)>) {
        let seq = std::mem::take(&mut self.vt_seq);
        if std::env::var_os("SANDAL_DEBUG_KVM").is_some() {
            eprintln!("DBG-SEQ param={} seq={seq:02x?}", self.vt_param);
        }

        self.vt_esc = false;
        self.vt_csi = 0;

        // DSR cursor-position query: `ESC [ 6 n` (some senders use an
        // empty parameter, which means the same thing).
        let is_dsr_query = seq.len() >= 3
            && seq[1] == b'['
            && seq[seq.len() - 1] == b'n'
            && (self.vt_param == 6 || self.vt_param == 0);

        self.vt_dsr = false;
        self.vt_param = 0;

        if is_dsr_query {
            // Cursor position is 1-based: after N printable columns the
            // cursor sits at column N+1.
            *dsr_reply = Some((self.vt_row, self.vt_col + 1));
            return;
        }

        // Apply cursor movement so the tracker stays usable across
        // redraws: `C` (forward), `D` (back), `G` (column absolute).
        let final_byte = seq[seq.len() - 1];
        match final_byte {
            b'C' => self.vt_col += self.vt_param.max(1),
            b'D' => self.vt_col = self.vt_col.saturating_sub(self.vt_param.max(1)),
            b'G' => self.vt_col = self.vt_param.saturating_sub(1),
            _ => {}
        }

        // Forward the sequence to the user's terminal verbatim.
        let exit_marker = self.exit_marker.clone();
        let markers: [&[u8]; 2] = [
            exit_marker.as_bytes(),
            initramfs::EXPORT_PATH_MARKER.as_bytes(),
        ];
        let mut stdout = std::io::stdout();
        for b in seq {
            self.emit_tx_byte(b, &mut stdout, &markers);
        }
    }

    /// Emit one visible TX byte: track the current line for marker
    /// detection, hold back bytes that could start a protocol marker, and
    /// stream everything else to the user's terminal.
    fn emit_tx_byte(&mut self, ch: u8, stdout: &mut std::io::Stdout, markers: &[&[u8]]) {
        self.tx_line.push(ch);

        if self.tx_suppress_line {
            // Swallow the rest of the marker line.
            return;
        }

        self.tx_hold.push(ch);

        if markers.iter().any(|m| self.tx_hold.ends_with(m)) {
            // Full marker: discard it and swallow the rest of the line.
            self.tx_hold.clear();
            self.tx_suppress_line = true;
        } else {
            // Hold back only the longest suffix that could still become
            // a marker; everything before it is safe to print.
            let hold = &self.tx_hold;
            let keep = if markers.iter().any(|m| m.starts_with(hold)) {
                hold.len()
            } else {
                (1..hold.len())
                    .rev()
                    .find(|&k| {
                        markers
                            .iter()
                            .any(|m| m.starts_with(&hold[hold.len() - k..]))
                    })
                    .unwrap_or(0)
            };

            let flush_len = self.tx_hold.len() - keep;

            if flush_len > 0 {
                let _ = stdout.write_all(&self.tx_hold[..flush_len]);
                self.tx_hold.drain(..flush_len);
            }
        }
    }

    /// Handle one complete guest console line (marker side effects only —
    /// visible output has already been streamed to stdout).
    fn process_console_line(&mut self, line: &[u8]) {
        let Ok(line) = std::str::from_utf8(line) else {
            return;
        };

        let trimmed = line.trim_end_matches(['\n', '\r']);

        if let Some(pos) = trimmed.find(&self.exit_marker) {
            let code = trimmed[pos + self.exit_marker.len()..].trim();
            // Only a real integer is the exit protocol. Commands like
            // `cat /init` surface the script's *unexpanded* placeholder —
            // that must not shut the VM down.
            if let Ok(code) = code.parse::<i32>() {
                self.guest_exit_code = Some(code);
                self.guest_shutdown = true;
                return;
            }
            // Not the protocol — fall through to the export marker.
        }

        if let Some(pos) = trimmed.find(initramfs::EXPORT_PATH_MARKER) {
            let path = trimmed[pos + initramfs::EXPORT_PATH_MARKER.len()..].trim();
            // The protocol always carries an absolute host path; ignore
            // garbage from e.g. dumping a helper binary.
            if path.starts_with('/') {
                self.export_save_path = Some(path.to_string());
            }
        }
    }
}
