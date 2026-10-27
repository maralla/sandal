//! The shared VM core: guest RAM, device dispatch, the run configuration
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

pub(crate) use crate::cli::Args;
#[cfg(not(target_os = "windows"))]
pub(crate) use crate::irqs::*;

use crate::hypervisor::{Vcpu, Vm};

/// The tracked SPI lines (the KVM line mirror's width): NET .. VSOCK.
pub(crate) const NUM_TRACKED_SPIS: usize = 32;
use crate::initramfs;
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::rng::VirtioRngDevice;
use anyhow::{anyhow, Result};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crate::hypervisor::Gic;

#[cfg(not(target_os = "windows"))]
use crate::net::NetworkFilter;

#[cfg(not(target_os = "windows"))]
use crate::unet::UserNet;

#[cfg(not(target_os = "windows"))]
use crate::virtio::fs::VirtioFsDevice;
use vsock_host::VsockHost;

#[cfg(not(target_os = "windows"))]
use crate::virtio::net::VirtioNetDevice;

#[cfg(not(target_os = "windows"))]
use std::os::unix::io::RawFd;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_os = "linux")]
mod linux;
pub(super) mod session;
mod vsock_host;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_os = "windows")]
pub(crate) mod windows;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{MAX_FS_DEVICES, RAM_BASE};

#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::x86_hypercall_page_off;

#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::{MAX_FS_DEVICES, RAM_BASE};

// ── Virtio-MMIO device addresses (both architectures) ──────────────────
// The x86_64 device window sits at 1 GB, ABOVE the guest RAM: the flat
// aarch64: a fixed device window at 160 MB (guest RAM starts at 1 GB,
// above it — the devices never overlap "System RAM").
#[cfg(target_arch = "aarch64")]
pub(crate) const MMIO_BASE: u64 = 0x0a00_0000;

#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_NET_BASE: u64 = MMIO_BASE + MMIO_OFF_NET;

#[cfg(target_arch = "aarch64")]
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_BLK_BASE: u64 = MMIO_BASE + MMIO_OFF_BLK;

#[cfg(target_arch = "aarch64")]
pub(crate) const DATA_BLK_BASE: u64 = MMIO_BASE + MMIO_OFF_DATA_BLK;

#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_RNG_BASE: u64 = MMIO_BASE + MMIO_OFF_RNG;

#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_VSOCK_BASE: u64 = MMIO_BASE + MMIO_OFF_VSOCK;

#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIOFS_BASE_START: u64 = MMIO_BASE + MMIO_OFF_FS;

// Per-device offsets inside the MMIO window (shared by both architectures).
// x86_64 places the window ABOVE the guest RAM (see `x86_64::mmio_base`) so
// the guest gets the full requested memory: capping RAM below a fixed device
// region silently shrank `-m` to 1 GB and OOM-killed large builds.
pub(crate) const MMIO_OFF_NET: u64 = 0x000;
pub(crate) const MMIO_OFF_BLK: u64 = 0x400;
pub(crate) const MMIO_OFF_DATA_BLK: u64 = 0x600;
pub(crate) const MMIO_OFF_RNG: u64 = 0x800;
/// The userspace virtio-vsock device (the one session transport on every
/// platform).
pub(crate) const MMIO_OFF_VSOCK: u64 = 0xa00;
#[cfg(target_arch = "x86_64")]
pub(crate) const MMIO_OFF_HYPERCALL: u64 = 0xe00;
pub(crate) const MMIO_OFF_FS: u64 = 0x1000;
pub(crate) const VIRTIOFS_SIZE: u64 = 0x200;

// ── Host terminal helpers ────────────────────────────────────────────────

/// Put the host terminal in raw mode: disable echo, canonical mode and
/// signal generation so every keystroke (including Tab and the guest line
/// editor's CSI queries) is forwarded to the guest verbatim instead of
/// being line-buffered/echoed by the host tty.
///
/// Mangles from the CURRENT state: the manglings must COMPOSE (the
/// output-side mangle below runs after this one, on the same tty), so
/// each mangle starts from whatever the previous one left — never from
/// a pre-mangling original (MEASURED: an output-side mangle from the
/// original turned ECHO back on mid-session). The RESTORE's original
/// is captured separately, before any mangling (see [`capture_tty`]).
#[cfg(not(target_os = "windows"))]
fn enable_raw_mode(fd: RawFd) {
    unsafe {
        let mut raw: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut raw) != 0 {
            return;
        }
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::ICRNL | libc::IXON);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
    }
}

/// Capture a tty's ORIGINAL termios — the pre-mangling state, for both
/// the Drop's restore and the exit-path restore (see
/// [`register_host_terminal_restore`]). None when the fd is not a tty.
#[cfg(not(target_os = "windows"))]
fn capture_tty(fd: RawFd) -> Option<libc::termios> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::isatty(fd) != 0 && libc::tcgetattr(fd, &mut orig) == 0 {
            Some(orig)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn restore_terminal(fd: RawFd, orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSANOW, orig);
    }
}

/// Disable output post-processing (OPOST/ONLCR) on the session's stdout. The
/// guest pty output is already fully formed (the guest tty applies
/// ONLCR and its console driver inserts CRs); the host tty re-applying
/// ONLCR turned every guest newline into `\r\r\n` on the pane.
/// Mangles from the CURRENT state (see [`enable_raw_mode`]: the
/// manglings compose); the RESTORE's original is captured separately,
/// before any mangling (see [`capture_tty`]).
#[cfg(not(target_os = "windows"))]
fn disable_output_processing(fd: RawFd) {
    unsafe {
        let mut raw: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut raw) != 0 {
            return;
        }
        raw.c_oflag &= !(libc::OPOST | libc::ONLCR);
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
    }
}

// ── The exit-path host-terminal restore ────────────────────────────────
//
// `process::exit` runs atexit handlers but never Drops, and the
// session's own exit path (the status trailer's match in
// `vm/session.rs`) must not leave the host terminal mangled: the
// session disables the host tty's OPOST (the guest pty already formed
// the output) and the raw input mode (every keystroke must reach the
// guest verbatim), and the ORIGINALS outlived the process — the
// user's own shell inherited a bare-`\n` terminal (MEASURED: fish's
// own `time` report printed as a staircase, each line shifted right by
// the previous one, ending in a bare CR) and an echo-less input side.
// The Drop's restore never runs on that path; this one does.
#[cfg(not(target_os = "windows"))]
static HOST_TERMINAL_ORIGINALS: std::sync::OnceLock<[libc::termios; 2]> =
    std::sync::OnceLock::new();

#[cfg(not(target_os = "windows"))]
extern "C" fn restore_host_terminal() {
    if let Some([fd0, fd1]) = HOST_TERMINAL_ORIGINALS.get() {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, fd0);
            libc::tcsetattr(1, libc::TCSANOW, fd1);
        }
    }
    if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
        eprintln!(
            "BOOT_TIMING atexit_terminal_restore: {:?}",
            BOOT_T0.get().map(|t| t.elapsed())
        );
    }
}

/// Register the exit-path restore for the host terminal's originals
/// (both descriptors). Idempotent: the first caller wins, and the
/// handler restores the SAME originals no matter which path mangled
/// the terminal afterwards (the raw input side, the OPOST-off output
/// side — every mangling of this process started from these).
#[cfg(not(target_os = "windows"))]
fn register_host_terminal_restore(fd0: libc::termios, fd1: libc::termios) {
    if HOST_TERMINAL_ORIGINALS.set([fd0, fd1]).is_ok() {
        unsafe {
            libc::atexit(restore_host_terminal as extern "C" fn());
        };
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
    /// Debug (SANDAL_DEBUG_RESIDENCY): dump which guest-physical 16MB
    /// buckets of the RAM mapping have host-resident pages (mincore over
    /// the whole slot). The total is the real overhead number; the
    /// per-bucket histogram pins it to guest physical ranges (compare
    /// /proc/iomem: kernel image, device MMIO, the hotplug sections).
    #[cfg(target_os = "linux")]
    pub(crate) fn dump_residency(&self) {
        const BUCKET: usize = 16 << 20;
        let mut vec = vec![0u8; self.len / 4096];
        let rc = unsafe { libc::mincore(self.ptr.cast(), self.len, vec.as_mut_ptr()) };
        if rc != 0 {
            eprintln!("RESIDENCY: mincore failed: {rc}");
            return;
        }
        let mut counts = vec![0u32; self.len.div_ceil(BUCKET)];
        let mut total = 0usize;
        for (i, r) in vec.iter().enumerate() {
            if *r & 1 != 0 {
                total += 1;
                counts[i * 4096 / BUCKET] += 1;
            }
        }
        eprintln!(
            "RESIDENCY: guest RAM: {} pages resident ({}MB) of {}MB mapped",
            total,
            (total * 4096) >> 20,
            self.len >> 20
        );
        for (b, c) in counts.iter().enumerate() {
            if *c != 0 {
                eprintln!(
                    "RESIDENCY: guest [{:#010x}..{:#010x}) {}MB resident",
                    b * BUCKET,
                    (b + 1) * BUCKET,
                    ((*c as usize) * 4096) >> 20
                );
            }
        }
        // The VMM's own mappings: the rest of the overhead. Walk
        // /proc/self/maps and mincore each mapping of this process — the
        // per-mapping resident totals pin the VMM's own cost to the heap,
        // the binary, the stacks, and whatever anonymous buffers the boot
        // path left behind (the guest RAM mapping above is excluded by
        // its exact range).
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
        for line in maps.lines() {
            let Some((range, rest)) = line.split_once(' ') else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let Ok(start) = usize::from_str_radix(start, 16) else {
                continue;
            };
            let Ok(end) = usize::from_str_radix(end, 16) else {
                continue;
            };
            if start == self.ptr as usize && end == start + self.len {
                continue; // the guest RAM mapping, dumped above
            }
            let len = end - start;
            if len == 0 || len % 4096 != 0 {
                continue;
            }
            let mut vec = vec![0u8; len / 4096];
            let rc = unsafe { libc::mincore(start as *mut libc::c_void, len, vec.as_mut_ptr()) };
            if rc != 0 {
                continue;
            }
            let resident = vec.iter().filter(|r| **r & 1 != 0).count();
            if resident > 0 {
                eprintln!(
                    "RESIDENCY: vmm  {start:#x}-{end:#x} {}MB of {}MB: {}",
                    (resident * 4096) >> 20,
                    len >> 20,
                    rest.split_whitespace().next().unwrap_or("")
                );
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn new(len: usize) -> Self {
        assert_eq!(len % 4096, 0, "guest RAM size must be page-aligned");
        // MEM_COMMIT: zero-filled by the OS (lazy — pages back from the
        // pagefile on first touch). Declared locally: the libc crate does
        // not wrap VirtualAlloc on Windows.
        unsafe extern "system" {
            fn VirtualAlloc(
                address: *mut u8,
                size: usize,
                allocation_type: u32,
                protect: u32,
            ) -> *mut u8;
        }

        const MEM_RESERVE: u32 = 0x2000;
        const MEM_COMMIT: u32 = 0x1000;
        const PAGE_READWRITE: u32 = 0x04;

        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                len,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        if ptr.is_null() {
            panic!("failed to VirtualAlloc {len} bytes of guest RAM");
        }

        GuestRam { ptr, len }
    }

    #[cfg(not(target_os = "windows"))]
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

        // Opt the guest RAM into transparent huge pages. MEASURED (the
        // host's THP policy is `madvise`, so this is what opts in): the
        // whole KVM mmu — the EPT behind the guest — works at 4 KB
        // granularity without it, and that granularity is what made
        // BOTH ends slow: kvm_destroy_vm walked 65K pages to free 256 MB
        // (close(vmfd): ~87 ms, the single largest term of the teardown),
        // and every guest page fault built page tables one page at a time.
        // With 2 MB huge pages behind it, the mmu works 512x coarser.
        // On `never` hosts this is a no-op. MADV_HUGEPAGE
        // is a Linux-only constant (macOS has no transparent hugepage advice).
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(ptr.cast(), len, libc::MADV_HUGEPAGE);
        }

        // MAP_ANONYMOUS memory is already zero-filled by the kernel (lazy
        // zero pages until first write) — no explicit memset needed.
        //
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

    /// Tear the mapping down NOW, before the process exit path would.
    ///
    /// MEASURED: the Drop's munmap never runs — an Arc clone leaks in a
    /// guest-thread handle, the refcount never reaches zero, and the
    /// 256 MB mapping falls to the kernel's exit_mm teardown — which
    /// cost 50-100 ms of wall time AFTER the last userspace byte
    /// (exit_group). An explicit munmap here is fast (MEASURED:
    /// munmap of a 67 MB image region: <1 ms), the Drop's own munmap
    /// of the then-empty range is a no-op, and the exit path has
    /// nothing left to tear down.
    pub(crate) fn force_teardown(&self) {
        #[cfg(not(target_os = "windows"))]
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
        #[cfg(target_os = "windows")]
        {
            // Windows: VirtualFree in the Drop; nothing to force here.
        }
    }
}

// The guest CPU thread reads/writes this memory while the VMM drives
// devices through it; that sharing is the entire point of the mapping.
unsafe impl Send for GuestRam {}
unsafe impl Sync for GuestRam {}

impl Drop for GuestRam {
    #[cfg(target_os = "windows")]
    fn drop(&mut self) {
        unsafe extern "system" {
            fn VirtualFree(address: *mut u8, size: usize, free_type: u32) -> i32;
        }

        const MEM_RELEASE: u32 = 0x8000;

        unsafe {
            VirtualFree(self.ptr, 0, MEM_RELEASE);
        }
    }

    #[cfg(not(target_os = "windows"))]
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
    /// x86_64: base of the MMIO device window (above the guest RAM).
    #[cfg(target_arch = "x86_64")]
    mmio_base: u64,
    /// x86_64: the emulated 8250's register file (the printk console's
    /// port — see Vmm::uart_pio).
    #[cfg(target_arch = "x86_64")]
    uart_regs: [u8; 8],

    /// Windows: the HLT park for the run loop + the device-thread wake.
    #[cfg(target_os = "windows")]
    halt: Arc<crate::hypervisor::whp::HaltWaker>,
    /// Windows: the PIT tick thread (stopped on drop).
    #[cfg(target_os = "windows")]
    device_threads: Option<crate::vm::windows::DeviceThreads>,
    blk: Option<VirtioBlkDevice>,
    data_blk: Option<VirtioBlkDevice>,
    /// The specified layer archives' paths (the --full export's
    /// consolidation inputs; re-read at export time).
    layer_paths: Vec<PathBuf>,
    /// Net device behind a mutex: the Linux net-kick thread pumps the
    /// backend and raises the net IRQ independently of the run loop (an
    /// idle guest would otherwise wait for its own delayed-ACK exit before
    /// more host data is delivered).
    #[cfg(not(target_os = "windows"))]
    net: Arc<Mutex<Option<VirtioNetDevice>>>,
    rng: Option<VirtioRngDevice>,
    #[cfg(not(target_os = "windows"))]
    virtiofs: Vec<VirtioFsDevice>,
    config_blob: Vec<u8>,
    #[cfg(target_os = "linux")]
    host: linux::KvmHost,
    /// Set on drop so the net-kick thread exits.
    #[cfg(target_os = "linux")]
    net_kick_stop: Arc<std::sync::atomic::AtomicBool>,
    /// The userspace virtio-vsock device and its host machinery (every
    /// platform: the one session transport). The device, its stop flag,
    /// and its threads. None while the VM runs without a session line.
    vsock: Option<VsockHost>,
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
    /// Unix: the saved termios. Windows: the saved console input mode.
    #[cfg(not(target_os = "windows"))]
    tty_saved: Option<libc::termios>,
    #[cfg(target_os = "windows")]
    tty_saved: Option<u32>,
    #[cfg(not(target_os = "windows"))]
    tty_out_saved: Option<libc::termios>,
    #[cfg(target_os = "windows")]
    tty_out_saved: Option<u32>,
    guest_shutdown: bool,
    verbose_uart: bool,
    /// Guest command exit status: set by the exit hypercall (x86_64:
    /// `sandal-exit`'s MMIO store) or the exit BRK (aarch64: the crafted
    /// init, the code in x15).
    guest_exit_code: Option<i32>,
}

pub fn resolve_data_path(name: &str) -> Option<PathBuf> {
    let candidates = [
        std::env::current_dir().ok()?.join(name),
        std::env::current_exe().ok()?.parent()?.join(name),
    ];

    candidates.into_iter().find(|p| p.exists())
}

/// Print a diagnostic line to the host console (stderr). The host tty runs
/// with OPOST disabled (the guest's raw output requires it, and termios is
/// per-tty, so stderr shares the setting): a bare `\n` moves the cursor
/// down WITHOUT returning to column 0, so the guest's next output would
/// appear indented by this line's width. Emit CRLF explicitly — harmless
/// on a normal tty (an extra CR renders as nothing).
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

impl Vmm {
    /// Base of this platform's MMIO device window: on x86_64 it sits just
    /// above the guest RAM (the window position depends on `-m`); on
    /// aarch64 it is a fixed low region below RAM.
    #[cfg(target_arch = "x86_64")]
    fn mmio_window(&self) -> u64 {
        self.mmio_base
    }

    #[cfg(target_arch = "aarch64")]
    fn mmio_window(&self) -> u64 {
        MMIO_BASE
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn halt_waker(&self) -> Arc<crate::hypervisor::whp::HaltWaker> {
        self.halt.clone()
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn pic_handle(&self) -> Arc<Mutex<crate::hypervisor::whp::Pic>> {
        self.vm.pic_handle()
    }

    /// Map a guest physical address to a virtiofs device index, if in range.
    #[cfg(not(target_os = "windows"))]
    fn virtiofs_index(&self, addr: u64) -> Option<usize> {
        let start = self.mmio_window() + MMIO_OFF_FS;
        let end = start + MAX_FS_DEVICES as u64 * VIRTIOFS_SIZE;
        if (start..end).contains(&addr) {
            Some(((addr - start) / VIRTIOFS_SIZE) as usize)
        } else {
            None
        }
    }
}

/// Run a VM to execute the requested command, returning the guest's exit
/// status when it exits.
/// Print a diagnostic line to the host console (stderr). The host tty runs
/// with OPOST disabled (the guest's raw output requires it, and termios is
/// per-tty, so stderr shares the setting): a bare `\n` moves the cursor
/// down WITHOUT returning to column 0, so the guest's next output would
/// appear indented by this line's width. Emit CRLF explicitly — harmless
/// on a normal tty (an extra CR renders as nothing).
pub(crate) fn console_eprintln(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{msg}\r");
}

/// Process-start timestamp for BOOT_TIMING diagnostics.
pub static BOOT_T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// The --script client's own copy of the guest's trailer magic (the
/// guest's protocol constant; the two must never diverge).
const SCRIPT_TRAILER_MAGIC: &[u8; 16] = b"VSOCKD:EXIT:01\n\0";

/// Deliver the script through the command line and stream the run back
/// to the host's stdout: mode 4 (the script), payload = the whole file.
/// Everything but the trailing 17-byte trailer is the script's output;
/// the trailer's last byte is its exit status. The last 17 bytes are
/// withheld from the stream until EOF, so the trailer is verified whole
/// and never displayed.
///
/// The guest's output is LF-only (its stdout is a socket — no tty line
/// discipline), and the VMM runs the host terminal raw (the session
/// console needs OPOST off): left alone, every line staircases. On a
/// terminal the stream is translated LF→CRLF statefully (an existing
/// CRLF never doubles) — exactly the kernel's ONLCR, which the raw
/// mode disabled. Piped output stays byte-exact.
fn run_script_client(port: &str, script: &[u8]) -> Result<i32> {
    let port_num: u16 = port
        .rsplit_once(':')
        .map(|(_, p)| p)
        .unwrap_or(port)
        .parse()
        .map_err(|e| anyhow!("--script: bad port {port:?}: {e}"))?;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port_num))?;

    let mut hdr = [0u8; 9];
    hdr[0] = 4; // the script mode
    hdr[5..9].copy_from_slice(&(script.len() as u32).to_le_bytes());
    stream.write_all(&hdr)?;
    stream.write_all(script)?;

    // The host stdout's own line discipline was disabled by the VMM's
    // raw-mode setup; a terminal needs the translation back.
    let to_tty = std::io::stdout().is_terminal();
    let mut last_was_cr = false;
    let emit = |out: &mut std::io::Stdout, chunk: &[u8], last_was_cr: &mut bool| {
        if !to_tty {
            let _ = out.write_all(chunk);
            return;
        }
        let mut translated = Vec::with_capacity(chunk.len() + 8);
        for &b in chunk {
            if b == b'\n' && !*last_was_cr {
                translated.push(b'\r');
            }
            *last_was_cr = b == b'\r';
            translated.push(b);
        }
        let _ = out.write_all(&translated);
    };

    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut out = std::io::stdout();
    loop {
        let n = std::io::Read::read(&mut stream, &mut chunk)?;
        if n == 0 {
            break;
        }
        tail.extend_from_slice(&chunk[..n]);
        if tail.len() > SCRIPT_TRAILER_MAGIC.len() + 1 {
            let cut = tail.len() - SCRIPT_TRAILER_MAGIC.len() - 1;
            emit(&mut out, &tail[..cut], &mut last_was_cr);
            tail.drain(..cut);
        }
        // The trailer IS the run's end: the guest writes it, closes the
        // connection and powers the VM off. Waiting for the stream's EOF
        // here would deadlock the teardown (the socket closes only when
        // the process does), so the run returns the moment the trailer
        // lands.
        if tail.len() == SCRIPT_TRAILER_MAGIC.len() + 1
            && tail[..SCRIPT_TRAILER_MAGIC.len()] == *SCRIPT_TRAILER_MAGIC
        {
            break;
        }
    }
    out.flush()?;

    if tail.len() != SCRIPT_TRAILER_MAGIC.len() + 1
        || &tail[..SCRIPT_TRAILER_MAGIC.len()] != SCRIPT_TRAILER_MAGIC
    {
        anyhow::bail!(
            "the script's output ended without a status trailer ({} bytes)",
            tail.len()
        );
    }
    Ok(tail[SCRIPT_TRAILER_MAGIC.len()] as i32)
}

/// Joins the --script sender on the way out: the run loop ends when the
/// guest powers off (the script's exit_vm), and the sender's output
/// drain must finish before the process does.
struct ScriptJoin(Option<std::thread::JoinHandle<()>>);

impl Drop for ScriptJoin {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

pub fn run(args: Args) -> Result<i32> {
    let timing = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
    let t0 = BOOT_T0.get_or_init(std::time::Instant::now);

    // The script payload reads early: a missing/unreadable file fails
    // before any VM exists.
    let script_payload = match &args.script {
        Some(path) => {
            Some(fs::read(path).map_err(|e| anyhow!("--script: read {}: {e}", path.display()))?)
        }
        None => None,
    };

    let mut vmm = Vmm::new(&args)?;
    if timing {
        eprintln!("BOOT_TIMING vmm_new: {:?}", t0.elapsed());
    }

    vmm.boot(&args)?;

    if timing {
        eprintln!("BOOT_TIMING boot (disks+rootfs+kernel): {:?}", t0.elapsed());
    }

    // The --script delivery: the whole file goes through the command
    // line once the listener is up (connections park until the guest's
    // vsockd signals ready, so an immediate connect is safe). The
    // guest's script sandbox powers the VM off with the script's own
    // exit status, so the run loop below ends with it; the join guard
    // only makes sure the output drain finishes before the process.
    let _script_join = ScriptJoin(script_payload.map(|script| {
        let port = args.port.clone().expect("--script forces the port");
        std::thread::spawn(move || {
            if let Err(error) = run_script_client(&port, &script) {
                eprintln!("sandal: --script: {error}");
                std::process::exit(124);
            }
        })
    }));

    #[cfg(target_os = "linux")]
    {
        let code = vmm.run_loop_kvm(&args);
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING pre_teardown: {:?}",
                BOOT_T0.get().map(|t| t.elapsed()).unwrap_or_default()
            );
        }
        // The guest RAM's explicit teardown (see force_teardown): the Arc
        // refcount never reaches zero (a leaked thread clone), so the
        // Drop's munmap never runs and the kernel's exit path pays.
        vmm.memory.force_teardown();
        code
    }

    #[cfg(target_os = "macos")]
    {
        vmm.run_loop_hvf(&args)
    }

    #[cfg(target_os = "windows")]
    {
        vmm.run_loop_whp(&args)
    }
    // The Vmm drops here (scope end): guest RAM munmap, device teardown.
}

/// Diagnose the session-failure protocol codes before they are returned.
///
/// The guest produced NO output in these cases — the session never
/// started — so a silent exit is indistinguishable from a hang: the
/// operator sees nothing at all (MEASURED by reproduction: a typo in
/// the workload command — `uanme` for `uname` — exited 125 with not
/// one byte of output). The VMM names the failure itself: it built the
/// command line, and the codes are its own protocol (the portagent:
/// 125 = the session exec failed; the guest init: 126 = no session
/// transport). The code is forwarded UNCHANGED (see
/// test_exit_codes.py); only the diagnostic is added.
pub(crate) fn diagnose_session_exit(code: i32, command: &[String]) {
    match code {
        125 => eprintln!(
            "sandal: failed to execute the workload command `{}`: not found \
             or not executable (the session helper's exec failed)",
            command.join(" ")
        ),
        126 => eprintln!(
            "sandal: no session: the session transport never opened (the host \
             device port did not come up, or the session helper rejected its \
             arguments)"
        ),
        // 127 is the guest shell's own not-found code (the command
        // line reached it and nothing it resolved existed) — the same
        // silence-measuring defect as 125: the operator sees nothing at
        // all. Name the failure; forward the code unchanged.
        127 => eprintln!(
            "sandal: the workload command `{}` was not found inside the VM \
             (the guest shell's own exit code, forwarded unchanged)",
            command.join(" ")
        ),
        _ => {}
    }
}

/// Build the writable overlay data disk (vdb).
///
/// Layer tar entries are injected under `upper/` (see
/// `ext2::inject_tar_entries`), which the guest init mounts as the overlayfs
/// upperdir. The image is sized to fit the layer's uncompressed data with
/// headroom (2× + 16 MB), at least `--disk-size`.
fn build_data_disk(args: &Args) -> Result<(Vec<u8>, Vec<crate::virtio::blk::SparseRegion>)> {
    if args.layers.is_empty() {
        let mb = args.disk_size.unwrap_or(1);
        let img = crate::ext2::create_empty_ext2(mb * 1024 * 1024)?;
        return Ok((img, Vec::new()));
    }

    let timing = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
    let t = std::time::Instant::now();

    // The zero-copy pipeline: each layer's decompressed archive stays
    // one buffer, and the entries span it (crate::tar::TarEntryRef).
    // The data blocks are RECORDED as sparse regions — served from the
    // archive by the block device, COW on the first guest write — and
    // never copied into the image: the copy pass was the load path's
    // dominant cost (measured ~90 ms for a 148 MB layer, fault-bound:
    // neither run-coalescing nor a parallel copy moved it, and the
    // parallel copy thrashed 9x worse — see inject_file_sparse).
    let mut all_tars: Vec<std::sync::Arc<Vec<u8>>> = Vec::new();
    let mut all_entries = Vec::new();
    for layer in &args.layers {
        // The file-based load path: no serial read of the compressed
        // file (see read_tar_zst_ref_file) — the chunked container's
        // workers pread their own chunks.
        let (tar, mut entries) = crate::tar::read_tar_zst_ref_file(layer)?;
        for e in &mut entries {
            e.tar = all_tars.len();
        }
        all_tars.push(std::sync::Arc::new(tar));
        all_entries.extend(entries);
    }

    if timing {
        eprintln!("BOOT_TIMING   layer_parse: {:?}", t.elapsed());
    }

    let layer_data = crate::tar::total_data_size(&all_entries);
    let layer_need = (layer_data * 2) + 16 * 1024 * 1024;
    let disk_bytes = args.disk_size.unwrap_or(1) * 1024 * 1024;
    let final_size = disk_bytes.max(layer_need);
    let t = std::time::Instant::now();
    let mut img = crate::ext2::create_empty_ext2(final_size)?;
    if timing {
        eprintln!(
            "BOOT_TIMING   ext2_create: {:?} ({} MB)",
            t.elapsed(),
            final_size / (1024 * 1024)
        );
    }

    let t = std::time::Instant::now();
    let mut regions = Vec::new();
    crate::ext2::inject_tar_entries_ref(&mut img, &all_tars, &all_entries, &mut regions)?;
    drop(all_tars); // the regions own their sources now

    if timing {
        eprintln!(
            "BOOT_TIMING   ext2_inject: {:?} ({} sparse regions, {} MB recorded)",
            t.elapsed(),
            regions.len(),
            regions.iter().map(|r| r.len).sum::<usize>() / (1024 * 1024)
        );
    }

    // The image and its sparse overlays travel together: the caller wires
    // the regions into the device (the image alone serves zeros where
    // the regions map).
    Ok((img, regions))
}

// ─────────────────────────────────────────────────────────────────────────────
// VM construction
// ─────────────────────────────────────────────────────────────────────────────
impl Vmm {
    fn new(args: &Args) -> Result<Self> {
        #[cfg(target_os = "windows")]
        let _args_no_network = true; // the user-space netstack is unix-only for now
                                     //
        #[cfg(not(target_os = "windows"))]
        let args_no_network = args.no_network;

        #[cfg(target_os = "windows")]
        let args = &Args {
            no_network: true,
            ..args.clone()
        };

        let tt = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
        let mut tp = std::time::Instant::now();
        let vm = Vm::new()?;

        if tt {
            eprintln!("BOOT_TIMING   vm_create: {:?}", tp.elapsed());
            tp = std::time::Instant::now();
        }

        // In-kernel interrupt controllers must exist before the first vCPU:
        // x86_64 gets the PIC+PIT (the guest timer), arm64 the GICv3.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let t = std::time::Instant::now();
            vm.create_irqchip()?;
            if tt {
                eprintln!("BOOT_TIMING   irqchip: {:?}", t.elapsed());
                tp = std::time::Instant::now();
            }
        }

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        vm.create_irqchip()?; // the userspace PIC pair
                              //
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

        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let vcpu = Vcpu::new(&vm)?;

        // Guest RAM. On x86_64 the virtio-mmio device window sits at
        // MMIO_BASE (160 MB) inside the flat physical address space, so the
        // RAM is capped below it — the kernel's request_mem_region for each
        // device would otherwise collide with "System RAM" (-EBUSY) and no
        // device would ever probe.
        #[cfg(target_arch = "x86_64")]
        // No RAM cap: the MMIO device window is placed above the guest RAM
        // (see `x86_64::mmio_base`), so `-m` is honored in full. The 1 TB
        // ceiling only guards against absurd values; the mmap is lazy.
        let ram_bytes = (args.memory.max(64) * 1024 * 1024).min(1 << 40);

        #[cfg(target_arch = "aarch64")]
        let ram_bytes = args.memory.max(64) * 1024 * 1024;

        let memory = Arc::new(GuestRam::new(ram_bytes));

        #[cfg(target_arch = "x86_64")]
        let mmio_base = x86_64::mmio_base(ram_bytes as u64);

        if tt {
            eprintln!("BOOT_TIMING   guest_ram: {:?}", tp.elapsed());
            tp = std::time::Instant::now();
        }

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
        #[cfg(target_os = "windows")]
        let (tty_saved, tty_out_saved) = {
            // stdin: VT input, no line/echo/processed — every keystroke
            // reaches the guest verbatim. stdout: VT output, processed
            // output OFF (the guest's CRLF is authoritative; the host-side
            // console_eprintln carries its own CR).
            unsafe extern "system" {
                fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
                fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
                fn SetConsoleMode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
            }

            const STD_INPUT_HANDLE: u32 = 0xFFFF_FFD6;
            const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFD5;

            let in_h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let out_h = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
            let (saved_in, saved_out) = unsafe {
                let (mut m_in, mut m_out) = (0u32, 0u32);
                let _ = GetConsoleMode(in_h, &mut m_in);
                let _ = GetConsoleMode(out_h, &mut m_out);
                (m_in, m_out)
            };

            // ENABLE_VIRTUAL_TERMINAL_INPUT = 0x200; clear line/echo/
            // processed (0x2|0x4|0x1).
            unsafe { SetConsoleMode(in_h, 0x0200) };
            // ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4; clear
            // ENABLE_PROCESSED_OUTPUT (0x1) so the guest's CRLF is not
            // re-translated.
            unsafe { SetConsoleMode(out_h, 0x4) };
            (Some(saved_in), Some(saved_out))
        };

        #[cfg(not(target_os = "windows"))]
        let (tty_saved, tty_out_saved) = {
            // BOTH originals BEFORE any mangling (the exit-path
            // restore's source), then the SEQUENTIAL mangling — each
            // mangle from the current state, so they compose: a mangle
            // from the pre-mangling original would UNDO the other side's
            // mangle on the same tty (MEASURED: the output-side mangle
            // from the original turned ECHO back on mid-session).
            let saved = capture_tty(0);
            let out_saved = capture_tty(1);

            enable_raw_mode(0);
            disable_output_processing(1);

            #[cfg(target_os = "macos")]
            {
                // The session's stdin: nonblocking (the run loop's poll
                // owns the pacing; a blocking read would stall it).
                unsafe {
                    let fl = libc::fcntl(0, libc::F_GETFL);
                    let _ = libc::fcntl(0, libc::F_SETFL, fl | libc::O_NONBLOCK);
                }
            }

            // The exit-path restore: `process::exit` never runs the
            // Drop that restores these, and the session's own exit path
            // (the status trailer's match) exits straight through it.
            // On the same tty both restores write the SAME pre-mangling
            // original; on different ttys each side gets its own.
            match (saved, out_saved) {
                (Some(fd0), Some(fd1)) => {
                    register_host_terminal_restore(fd0, fd1);
                    (Some(fd0), Some(fd1))
                }
                pair => pair,
            }
        };

        // User-space networking (enabled unless --no-network). The run loops
        // poll the backend after every guest exit and the Linux net-kick
        // thread pumps it independently, so an idle guest never waits for
        // its own delayed-ACK timer before more host data is delivered.
        #[cfg(not(target_os = "windows"))]
        let net = if args_no_network {
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

        if tt {
            eprintln!("BOOT_TIMING   net: {:?}", tp.elapsed());
        }

        #[cfg(target_os = "linux")]
        // The host is mutated later on x86_64 only (the aarch64 build
        // never reassigns it); the allow keeps -D warnings green there.
        #[cfg_attr(target_arch = "aarch64", allow(unused_mut))]
        let mut host = {
            let irq_lock = Arc::new(Mutex::new(()));
            let irq_levels = linux::new_irq_levels();
            linux::KvmHost {
                irq_lock,
                stop_fd: -1,
                net_thread: None,
                irq_levels,
            }
        };

        #[cfg(target_os = "linux")]
        let net_kick_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // The command execution line's bridge core: the device + the
        // exchange loop, ALWAYS (front end 1 — the session handler —
        // registers its stream with it when there's a command); the TCP
        // proxy (front end 2) only when the operator named --port. One
        // core, two front ends — the exchange loop is stream-agnostic.
        // Every platform: the vsock IS the session transport.
        let vsock = {
            // Front end 2: the TCP proxy — only with --port. The
            // listener binds synchronously (fail fast on a bad target).
            let listener = match args.port.as_ref() {
                Some(target) => {
                    let (addr, port) = match target.rsplit_once(':') {
                        Some((addr, port)) => (addr, port),
                        None => ("127.0.0.1", target.as_str()),
                    };
                    let port: u16 = port
                        .parse()
                        .map_err(|error| anyhow!("--port: bad port {port:?}: {error}"))?;
                    if port == 0 {
                        return Err(anyhow!("--port: port 0 is random; name one"));
                    }
                    let addr = if addr.is_empty() { "127.0.0.1" } else { addr };
                    Some(
                        std::net::TcpListener::bind((addr, port))
                            .map_err(|error| anyhow!("--port: bind {addr}:{port}: {error}"))?,
                    )
                }
                None => None,
            };
            // Front end 1: the session handler — the command execution
            // line's own host side (the host stdio as a stream). Only
            // when there's a command; the empty command is the pool's
            // own long-lived VM (no session of its own).
            let session = if args.command.is_empty() {
                None
            } else {
                Some(session::SessionStream::new(&args.command)?)
            };
            #[cfg(target_os = "linux")]
            let host_spawner = (host.irq_lock.clone(), host.irq_levels.clone());
            Some(vsock_host::VsockHost::spawn(
                memory.clone(),
                #[cfg(target_os = "linux")]
                vm.clone(),
                #[cfg(target_os = "linux")]
                host_spawner.0,
                #[cfg(target_os = "linux")]
                host_spawner.1,
                listener,
                session,
            )?)
        };

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // The net kicker's shutdown wake (see spawn_net_kicker): an
            // eventfd in its epoll set, written once at shutdown.
            let stop_fd = unsafe { libc::eventfd(0, 0) };
            let net_thread = linux::spawn_net_kicker(
                vm.clone(),
                net.clone(),
                memory.clone(),
                host.irq_lock.clone(),
                host.irq_levels.clone(),
                net_kick_stop.clone(),
                stop_fd,
            );
            host.stop_fd = stop_fd;
            host.net_thread = Some(net_thread);
        }

        #[cfg(not(target_os = "windows"))]
        let mut virtiofs = Vec::new();

        #[cfg(not(target_os = "windows"))]
        for (tag, host_path, _guest) in parse_shares(args)? {
            virtiofs.push(VirtioFsDevice::new(host_path, tag));
        }

        Ok(Vmm {
            vcpu,
            vm,
            memory,
            #[cfg(target_os = "macos")]
            gic: Gic::new(),
            #[cfg(target_arch = "x86_64")]
            mmio_base,
            #[cfg(target_arch = "x86_64")]
            uart_regs: [0u8; 8],
            #[cfg(target_os = "windows")]
            halt: Arc::new(crate::hypervisor::whp::HaltWaker::default()),
            #[cfg(target_os = "windows")]
            device_threads: None,
            blk: None,
            data_blk: None,
            layer_paths: args.layers.clone(),
            #[cfg(not(target_os = "windows"))]
            net,
            rng: Some(VirtioRngDevice::new()),
            #[cfg(not(target_os = "windows"))]
            virtiofs,
            config_blob: Vec::new(),
            #[cfg(target_os = "linux")]
            host,
            #[cfg(target_os = "linux")]
            net_kick_stop,
            vsock,
            #[cfg(target_os = "macos")]
            vt_off,
            #[cfg(target_os = "macos")]
            vtimer_masked: false,
            #[cfg(target_os = "macos")]
            irq_line_asserted: false,
            tty_saved,
            tty_out_saved,
            guest_shutdown: false,
            // -v or SANDAL_VERBOSE_UART=1: mirror guest serial-port (0x3f8)
            // THR writes to stderr — a diagnostics channel that bypasses
            // the guest tty stack entirely (see tests/test_tmux_attached.py).
            verbose_uart: args.verbose || std::env::var_os("SANDAL_VERBOSE_UART").is_some(),
            guest_exit_code: None,
        })
    }

    fn boot(&mut self, args: &Args) -> Result<()> {
        let timing = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
        let t0 = std::time::Instant::now();

        // The device is always present. With `--disk-size`/`--layer` it backs
        // the overlay upperdir; without them the overlay upper stays on tmpfs
        // but the device is still needed as the scratch target `sandal-export`
        // writes its tar onto (the VMM reads it back). Without it, a default
        // tmpfs-mode guest could never export a layer.
        let disk_backed_upper = args.disk_size.is_some() || !args.layers.is_empty();
        let (img, regions) = build_data_disk(args)?;
        let mut blk = VirtioBlkDevice::new(img);
        blk.add_sparse(regions);
        self.data_blk = Some(blk);

        if timing {
            eprintln!("BOOT_TIMING data_disk: {:?}", t0.elapsed());
        }

        // ── Init config (the text injected as /etc/sandal.conf) ────────
        // The one run-configuration channel on every platform: a plain
        // file read needs no privileges, and both inits (the script and
        // the aarch64 Rust binary) parse the same format.
        let clock_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let disk_mode = if disk_backed_upper {
            Some("disk")
        } else {
            None
        };

        let share_configs: Vec<(String, String)> = parse_shares(args)?
            .into_iter()
            .map(|(tag, _host, guest)| (tag, guest))
            .collect();

        // The effective network flag: the Windows host runs network-less
        // (the user-space netstack's socket plumbing is unix-only for now).
        #[cfg(target_os = "windows")]
        let network = false;

        #[cfg(not(target_os = "windows"))]
        let network = !args.no_network;

        // The guest terminal type: the host's own TERM, sanitized to a
        // single path-free token (the config line and the terminfo
        // subdirectory are built from it). The pty session runs REAL
        // terminal software — readline, vim, tmux — and without the
        // matching terminfo entry every one of them falls back to dumb
        // settings (MEASURED: the python REPL lost its line editor).
        // Empty (no TERM, or a hostile value): the guest keeps its own
        // linux fallback entry.
        let host_term = std::env::var("TERM")
            .ok()
            .filter(|t| {
                !t.is_empty()
                    && t.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
                    && t.chars()
                        .skip(1)
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
            })
            .unwrap_or_default();

        // The whole slot is the hotplug cap: the boot memory map declares
        // only the RAM floor (see RAM_FLOOR), and the guest init grows
        // toward this cap on demand. x86_64 only — the aarch64 kernel
        // carries no memory hotplug, and its slot is fully declared RAM.
        #[cfg(target_arch = "x86_64")]
        let mem_cap = self.memory.len() as u64;
        #[cfg(not(target_arch = "x86_64"))]
        let mem_cap = 0u64;
        // The session line's ports, verbatim from the device's own
        // constant (they must never diverge): every platform runs the
        // vsock session line, so the port is always present.
        let vsockd_port = Some(crate::virtio::vsock::VSOCKD_PORT);
        // The hypercall page's address rides the config on x86_64 (the
        // guest helpers' /dev/mem MMIO store); the aarch64 signals are
        // BRK immediates and need no address.
        #[cfg(target_arch = "x86_64")]
        let hypercall_addr = Some({
            let (page, off) = crate::vm::x86_hypercall_page_off(self.mmio_base);
            page + off
        });
        #[cfg(not(target_arch = "x86_64"))]
        let hypercall_addr = None;
        self.config_blob = initramfs::build_init_config_text(
            disk_mode,
            &share_configs,
            network,
            clock_secs,
            &host_term,
            mem_cap,
            vsockd_port,
            hypercall_addr,
            args.script.is_some(),
        );

        // ── Root filesystem (vda): busybox ext2 + runtime files ───────
        let mut rootfs_img = match &args.rootfs {
            Some(path) => fs::read(path)
                .map_err(|e| anyhow!("failed to read rootfs {}: {e}", path.display()))?,
            None => {
                let t = std::time::Instant::now();
                let img = crate::rootfs::load();
                if timing {
                    eprintln!("BOOT_TIMING rootfs_gunzip: {:?}", t.elapsed());
                }
                img
            }
        };

        crate::ext2::inject_runtime_files(&mut rootfs_img, network, &host_term)?;

        // The init reads the run configuration from this file (the shell
        // script sources it line-by-line; the aarch64 init parses it).
        {
            let sb = crate::ext2::Ext2Superblock::parse(&rootfs_img)?;
            let bgdt = crate::ext2::Ext2BgdTable::parse(&rootfs_img, &sb)?;
            let mut alloc = crate::ext2::Ext2Alloc::default();
            crate::ext2::inject_file(
                &mut rootfs_img,
                &sb,
                &bgdt,
                &mut alloc,
                initramfs::CONFIG_PATH,
                &self.config_blob,
                0o644,
            )?;
        }

        self.blk = Some(VirtioBlkDevice::new(rootfs_img));

        // ── Load the kernel ─────────────────────────────────────────────
        #[cfg(target_arch = "x86_64")]
        self.boot_kernel_x86(args)?;
        if timing {
            eprintln!("BOOT_TIMING kernel_load: {:?}", t0.elapsed());
        }

        // ── Host device threads (Windows): the PIT tick + console input ─
        #[cfg(target_os = "windows")]
        {
            self.device_threads = Some(windows::spawn_device_threads(self));
        }

        #[cfg(target_arch = "aarch64")]
        self.boot_kernel_arm64(args)?;

        Ok(())
    }
}

impl Drop for Vmm {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.net_kick_stop.store(true, Ordering::Relaxed);

        // Windows: restore the saved console modes (input re-enables
        // line/echo/processed; output re-enables processed output).
        #[cfg(target_os = "windows")]
        unsafe extern "system" {
            fn GetStdHandle(which: u32) -> *mut std::ffi::c_void;
            fn SetConsoleMode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
        }

        #[cfg(target_os = "windows")]
        unsafe {
            if let Some(mode) = self.tty_out_saved {
                let out_h = GetStdHandle(0xFFFF_FFD5);
                SetConsoleMode(out_h, mode);
            }

            if let Some(mode) = self.tty_saved {
                let in_h = GetStdHandle(0xFFFF_FFD6);
                SetConsoleMode(in_h, mode);
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if let Some(ref orig) = self.tty_out_saved {
                restore_terminal(1, orig);
            }

            if let Some(ref orig) = self.tty_saved {
                restore_terminal(0, orig);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device dispatch (MMIO) — both architectures share the virtio-MMIO layout;
// the GIC (arm64) and the hypercall page (x86_64) are arch-specific.
// ─────────────────────────────────────────────────────────────────────────────
/// The overlay-upper marker file that carries the guest's requested
/// layer name: consumed by the export, filtered from the layer
/// content.
const LAYER_NAME_MARKER: &str = ".sandal-layer-name";

/// Pull the requested layer name out of the export entries: the marker
/// file's content IS the name; the marker itself never reaches the
/// layer.
fn take_requested_layer_name(
    entries: Vec<crate::tar::TarEntry>,
) -> (Option<String>, Vec<crate::tar::TarEntry>) {
    let mut name = None;
    let mut kept = Vec::with_capacity(entries.len());
    for e in entries {
        if name.is_none() && e.path.trim_start_matches("./") == LAYER_NAME_MARKER {
            name = Some(String::from_utf8_lossy(&e.data).trim().to_string());
        } else {
            kept.push(e);
        }
    }
    (name, kept)
}

/// The --full consolidation: the specified layers (in command-line
/// order, the later shadowing the earlier) under the current upper —
/// the upper's files replace the layers', its whiteouts delete layer
/// paths, its dirs merge over them. The BASE ROOTFS IS IGNORED: the
/// layer = the specified layers + the runtime state, consolidated, the
/// ignore rules applied by the caller's filter.
fn merge_full_entries(
    layers: Vec<Vec<crate::tar::TarEntry>>,
    upper: Vec<crate::tar::TarEntry>,
) -> Vec<crate::tar::TarEntry> {
    use std::collections::BTreeMap;

    fn apply(map: &mut BTreeMap<String, crate::tar::TarEntry>, e: crate::tar::TarEntry) {
        let path = e.path.trim_start_matches("./").to_string();
        match e.entry_type {
            // The deletion: the path and its whole subtree drop.
            crate::tar::TarEntryType::Whiteout => {
                let prefix = format!("{path}/");
                map.retain(|k, _| k != &path && !k.starts_with(&prefix));
            }
            // A file replaces the path and any directory subtree under
            // it (the overlay's own shadowing rule).
            crate::tar::TarEntryType::File => {
                let prefix = format!("{path}/");
                map.retain(|k, _| !k.starts_with(&prefix));
                map.insert(path, e);
            }
            // A dir/symlink shadows the same path; the base's children
            // of a dir merge through (the overlay's own dir semantics).
            _ => {
                map.insert(path, e);
            }
        }
    }

    let mut map: BTreeMap<String, crate::tar::TarEntry> = BTreeMap::new();
    for layer in layers {
        for e in layer {
            apply(&mut map, e);
        }
    }
    for e in upper {
        apply(&mut map, e);
    }
    map.into_values().collect()
}

/// Sanitize a guest-requested layer name: a single path component, a
/// strict charset, at most 64 bytes, `.layer` appended when missing.
/// Anything else is unusable — the guest never names a host path
/// directly, so no separator, no dot-prefix, no traversal ever lands.
fn sanitize_layer_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    if name.starts_with('-') || name.starts_with('.') {
        return None;
    }
    Some(if name.ends_with(".layer") {
        name.to_string()
    } else {
        format!("{name}.layer")
    })
}

/// The export's ignore rules: the layer carries WORKSPACE data, never
/// session state — the shell history and the /tmp scratch are filtered
/// out of every export. /tmp rides the overlay root (it shares the
/// data disk), so without this filter every export would carry the
/// guest's scratch — the invariant: sandal-export NEVER delivers /tmp
/// content.
fn filter_export_entries(entries: Vec<crate::tar::TarEntry>) -> Vec<crate::tar::TarEntry> {
    let mut entries = entries;
    entries.retain(|e| {
        let p = e.path.trim_start_matches("./");
        !p.ends_with("/.ash_history")
            && p != "tmp"
            && !p.starts_with("tmp/")
            && p != LAYER_NAME_MARKER
    });
    entries
}

impl Vmm {
    fn mmio_read(&mut self, addr: u64, len: usize, sas: u8) -> u64 {
        let mw = self.mmio_window();
        #[cfg(target_os = "macos")]
        {
            if (aarch64::GICD_BASE..aarch64::GICD_BASE + aarch64::GICD_SIZE).contains(&addr) {
                return self.gic.gicd_read(addr - aarch64::GICD_BASE) as u64;
            }

            if (aarch64::GICR_BASE..aarch64::GICR_BASE + aarch64::GICR_SIZE).contains(&addr) {
                return self.gic.gicr_read(addr - aarch64::GICR_BASE) as u64;
            }
        }

        #[cfg(not(target_os = "windows"))]
        if let Some(net) = self.net.lock().unwrap().as_mut() {
            if (mw + MMIO_OFF_NET..mw + MMIO_OFF_NET + 0x200).contains(&addr) {
                return net.mmio_read(addr - mw - MMIO_OFF_NET) as u64;
            }
        }

        if let Some(b) = self.blk.as_mut() {
            if (mw + MMIO_OFF_BLK..mw + MMIO_OFF_BLK + 0x200).contains(&addr) {
                return b.mmio_read(addr - mw - MMIO_OFF_BLK) as u64;
            }
        }

        if let Some(b) = self.data_blk.as_mut() {
            if (mw + MMIO_OFF_DATA_BLK..mw + MMIO_OFF_DATA_BLK + 0x200).contains(&addr) {
                return b.mmio_read(addr - mw - MMIO_OFF_DATA_BLK) as u64;
            }
        }

        if let Some(rng) = self.rng.as_ref() {
            if (mw + MMIO_OFF_RNG..mw + MMIO_OFF_RNG + 0x200).contains(&addr) {
                return rng.mmio_read(addr - mw - MMIO_OFF_RNG) as u64;
            }
        }

        if let Some(vsock) = self.vsock.as_ref() {
            if (mw + MMIO_OFF_VSOCK..mw + MMIO_OFF_VSOCK + 0x200).contains(&addr) {
                // The config space (the guest CID) needs the sas.
                return vsock
                    .device
                    .lock()
                    .unwrap()
                    .mmio_read(addr - mw - MMIO_OFF_VSOCK, sas);
            }
        }

        #[cfg(not(target_os = "windows"))]
        if let Some(idx) = self.virtiofs_index(addr) {
            if let Some(dev) = self.virtiofs.get_mut(idx) {
                return dev.mmio_read(addr - mw - MMIO_OFF_FS - idx as u64 * VIRTIOFS_SIZE) as u64;
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
        let mw = self.mmio_window();
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

        if let Some(b) = self.blk.as_mut() {
            if (mw + MMIO_OFF_BLK..mw + MMIO_OFF_BLK + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - mw - MMIO_OFF_BLK, val as u32);
                let _ = b.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                return;
            }
        }

        if let Some(b) = self.data_blk.as_mut() {
            if (mw + MMIO_OFF_DATA_BLK..mw + MMIO_OFF_DATA_BLK + 0x200).contains(&addr) {
                let _ = b.mmio_write(addr - mw - MMIO_OFF_DATA_BLK, val as u32);
                let _ = b.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                return;
            }
        }

        #[cfg(not(target_os = "windows"))]
        if let Some(net) = self.net.lock().unwrap().as_mut() {
            if (mw + MMIO_OFF_NET..mw + MMIO_OFF_NET + 0x200).contains(&addr) {
                if let Some(qidx) = net.mmio_write(addr - mw - MMIO_OFF_NET, val as u32) {
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
            if (mw + MMIO_OFF_RNG..mw + MMIO_OFF_RNG + 0x200).contains(&addr) {
                if rng
                    .mmio_write(addr - mw - MMIO_OFF_RNG, val as u32)
                    .is_some()
                {
                    rng.process_queue(self.memory.as_shared_slice(), RAM_BASE);
                }
                return;
            }
        }

        if let Some(vsock) = self.vsock.as_ref() {
            if (mw + MMIO_OFF_VSOCK..mw + MMIO_OFF_VSOCK + 0x200).contains(&addr) {
                // QueueNotify returns Some(queue); the driving is the run
                // loop's per-iteration process() — the same iteration
                // this exit is handled in, never inside the dispatch.
                let _ = vsock
                    .device
                    .lock()
                    .unwrap()
                    .mmio_write(addr - mw - MMIO_OFF_VSOCK, val as u32);
                return;
            }
        }

        #[cfg(not(target_os = "windows"))]
        if let Some(idx) = self.virtiofs_index(addr) {
            if let Some(dev) = self.virtiofs.get_mut(idx) {
                let off = addr - mw - MMIO_OFF_FS - idx as u64 * VIRTIOFS_SIZE;
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
        {
            let hyper = mw + MMIO_OFF_HYPERCALL;
            if (hyper..hyper + 0x200).contains(&addr) {
                if self.verbose_uart {
                    eprintln!("HYPERCALL write 0x{addr:x} = 0x{val:x}");
                }
                // Hypercall page: a u32 write of the port number signals the VMM
                // (the x86 analog of the ARM64 BRK immediates). The port
                // numbers are the shared "SanDal N" signals (initramfs.rs).
                const RESIZE: u16 = initramfs::EXPORT_RESIZE_IMM as u16;
                const DONE: u16 = initramfs::EXPORT_DONE_IMM as u16;
                const DONE_FULL: u16 = initramfs::EXPORT_DONE_FULL_IMM as u16;
                const EXIT: u16 = initramfs::EXIT_IMM as u16;
                const READY: u16 = initramfs::VSOCKD_READY_IMM as u16;
                match val as u16 {
                    RESIZE => self.handle_export_resize(),
                    DONE => self.handle_export_done(false),
                    DONE_FULL => self.handle_export_done(true),
                    // The exit protocol: the low half selects the signal,
                    // the high half carries the session's exit code (the
                    // init's `sandal-exit <status>` helper).
                    EXIT => {
                        self.guest_exit_code = Some((val >> 16) as i32);
                        self.guest_shutdown = true;
                    }
                    // The command execution line's readiness event: the
                    // guest's vsockd bound its listener — connect every
                    // parked front end now. The REQUEST goes out exactly
                    // once, at the moment the guest can accept it.
                    READY => {
                        log::info!("vsockd: the READY hypercall landed");
                        if let Some(vsock) = self.vsock.as_ref() {
                            vsock.device.lock().unwrap().set_guest_listening();
                        }
                    }
                    other => log::warn!("unknown hypercall {other:#x}"),
                }
                return;
            }
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

    /// `export done`: turn the export into a zstd-compressed `.layer`
    /// file on the host.
    ///
    /// The upper side (the export's payload):
    /// Disk mode: the data disk is an ext2 image; its `upper/` subtree is
    /// extracted and serialized as a ustar archive.
    /// Tmpfs mode: the guest wrote an uncompressed tar to the raw device.
    ///
    /// `full`: merge the SPECIFIED layers (the command line's --layer
    /// archives) with the upper into one consolidated layer — the upper
    /// shadows the layers, its whiteouts delete layer paths. `false`:
    /// the upper alone (the diff, whiteouts included). The base rootfs
    /// is ignored either way.
    ///
    /// The saved name: the guest's requested one (the `.sandal-layer-name`
    /// marker in the upper, sanitized hard, never overwriting) or the
    /// content-addressed default.
    fn handle_export_done(&mut self, full: bool) {
        log::info!("export: DONE hypercall (full={full})");
        let Some(dev) = self.data_blk.as_mut() else {
            log::warn!("export done: no data disk");
            return;
        };
        // Flatten the sparse overlays first: the export reads the image
        // directly, and the layer's data blocks live in the overlays
        // (see virtio::blk::SparseRegion). The export is an explicit,
        // already-expensive operation — the one-time copy is fine here
        // (it is exactly the copy the boot path skipped).
        dev.flatten_sparse();

        // The upper side, both export modes: the ext2 upper (disk mode)
        // or the guest's raw tar (tmpfs mode). The name marker rides the
        // entries in either.
        let mut requested_name: Option<String> = None;
        let mut upper_entries: Option<Vec<crate::tar::TarEntry>> = None;
        let mut raw_tar: Option<Vec<u8>> = None;
        match crate::ext2::read_upper_tar_entries(&dev.disk_image) {
            Ok(entries) if !entries.is_empty() => {
                let (name, entries) = take_requested_layer_name(entries);
                if requested_name.is_none() {
                    requested_name = name;
                }
                upper_entries = Some(entries);
            }
            _ => {
                // Fall back to a raw tar the guest wrote to the device
                // (tmpfs-mode export). Parsed and re-serialized below so
                // the shell history filter applies to this path too.
                let end = crate::tar::find_tar_end(&dev.disk_image);
                if end == 0 {
                    log::warn!("export done: no exportable data found");
                    console_eprintln("sandal: export failed: no exportable data found");
                    return;
                }
                raw_tar = Some(dev.disk_image[..end].to_vec());
            }
        }

        let mut entries = match (upper_entries, raw_tar) {
            (Some(entries), _) => entries,
            (None, Some(raw)) => match crate::tar::read_tar(&raw) {
                Ok(entries) => {
                    let (name, entries) = take_requested_layer_name(entries);
                    if requested_name.is_none() {
                        requested_name = name;
                    }
                    entries
                }
                // Not parseable: forward it verbatim — nothing
                // user-output can ever act as the protocol.
                Err(_) => {
                    return self.save_export_layer(raw.to_vec(), None);
                }
            },
            (None, None) => unreachable!(),
        };

        if full {
            // The consolidation: the SPECIFIED layers (in command-line
            // order, the later shadowing the earlier) under the current
            // upper — the upper's files replace the layers', its
            // whiteouts delete layer paths, its dirs merge. The base
            // rootfs is ignored: the layer = the layers + the runtime
            // state, consolidated, the ignore rules applied below.
            let mut layers = Vec::new();
            for path in &self.layer_paths {
                match std::fs::read(path)
                    .map_err(|e| anyhow!("read: {e}"))
                    .and_then(|zst| crate::tar::read_tar_zst_ref(&zst))
                {
                    Ok((tar_data, refs)) => layers.push(
                        refs.into_iter()
                            .map(|r| crate::tar::TarEntry {
                                path: r.path,
                                mode: r.mode,
                                entry_type: r.entry_type,
                                link_target: r.link_target,
                                data: tar_data[r.data].to_vec(),
                            })
                            .collect::<Vec<_>>(),
                    ),
                    Err(e) => console_eprintln(&format!(
                        "sandal: export full: layer {} unreadable: {e}",
                        path.display()
                    )),
                }
            }
            entries = merge_full_entries(layers, entries);
        }

        let tar_data = crate::tar::write_tar(&filter_export_entries(entries));
        self.save_export_layer(tar_data, requested_name.as_deref());
    }

    /// Compress + save the layer payload under the requested (sanitized)
    /// or the content-addressed name.
    fn save_export_layer(&self, tar_data: Vec<u8>, requested_name: Option<&str>) {
        // The chunked container: compression parallelizes across cores
        // too (see crate::zchunk) — the export's slow direction.
        let layer_data = match crate::zchunk::compress_chunked(&tar_data, 3) {
            Ok(data) => data,
            Err(e) => {
                console_eprintln(&format!("sandal: export failed to compress layer: {e}"));
                return;
            }
        };
        let content_addressed = |layer_data: &[u8]| {
            let mut hasher = DefaultHasher::new();
            layer_data.hash(&mut hasher);
            PathBuf::from(format!("layer-{:016x}.layer", hasher.finish()))
        };
        let save_path = match requested_name {
            Some(raw) => match sanitize_layer_name(raw) {
                Some(name) => {
                    let path = PathBuf::from(&name);
                    if path.exists() {
                        console_eprintln(&format!(
                            "sandal: export: {} exists; using the content-addressed name",
                            name
                        ));
                        content_addressed(&layer_data)
                    } else {
                        path
                    }
                }
                None => {
                    console_eprintln(&format!(
                        "sandal: export: the requested layer name {raw:?} is not usable; \
                         using the content-addressed name",
                    ));
                    content_addressed(&layer_data)
                }
            },
            None => content_addressed(&layer_data),
        };

        match fs::write(&save_path, &layer_data) {
            Ok(()) => console_eprintln(&format!("Layer saved to: {}", save_path.display())),
            Err(e) => console_eprintln(&format!("sandal: failed to save layer: {e}")),
        }
    }
}
