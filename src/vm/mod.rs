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
// The x86_64 device window sits at 1 GB, ABOVE the guest RAM: the flat
// aarch64: a fixed device window at 160 MB (guest RAM starts at 1 GB,
// above it — the devices never overlap "System RAM").
#[cfg(target_arch = "aarch64")]
pub(crate) const MMIO_BASE: u64 = 0x0a00_0000;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_NET_BASE: u64 = MMIO_BASE + MMIO_OFF_NET;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_CONSOLE_BASE: u64 = MMIO_BASE + MMIO_OFF_CONSOLE;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_BLK_BASE: u64 = MMIO_BASE + MMIO_OFF_BLK;
#[cfg(target_arch = "aarch64")]
pub(crate) const DATA_BLK_BASE: u64 = MMIO_BASE + MMIO_OFF_DATA_BLK;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_RNG_BASE: u64 = MMIO_BASE + MMIO_OFF_RNG;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIOFS_BASE_START: u64 = MMIO_BASE + MMIO_OFF_FS;

// Per-device offsets inside the MMIO window (shared by both architectures).
// x86_64 places the window ABOVE the guest RAM (see `x86_64::mmio_base`) so
// the guest gets the full requested memory: capping RAM below a fixed device
// region silently shrank `-m` to 1 GB and OOM-killed large builds.
pub(crate) const MMIO_OFF_NET: u64 = 0x000;
pub(crate) const MMIO_OFF_CONSOLE: u64 = 0x200;
pub(crate) const MMIO_OFF_BLK: u64 = 0x400;
pub(crate) const MMIO_OFF_DATA_BLK: u64 = 0x600;
pub(crate) const MMIO_OFF_RNG: u64 = 0x800;
#[cfg(target_arch = "x86_64")]
pub(crate) const MMIO_OFF_HYPERCALL: u64 = 0xe00;
pub(crate) const MMIO_OFF_FS: u64 = 0x1000;
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
        // MAP_ANONYMOUS memory is already zero-filled by the kernel (lazy
        // zero pages until first write) — no explicit memset needed.
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

/// The console TX pipeline: escape-sequence tracking (DSR/DA query replies),
/// protocol-marker filtering, and the line/cursor state. Owned by the
/// net-kick thread that drains the console TX virtqueue (Linux).
#[cfg(target_os = "linux")]
pub(crate) struct ConsoleTxFilter {
    /// The per-boot exit-protocol token.
    pub exit_marker: String,
    /// Console TX line buffer used to intercept protocol markers.
    tx_line: Vec<u8>,
    /// Bytes held back because they may start a protocol marker.
    tx_hold: Vec<u8>,
    /// True while the current TX line is a suppressed marker line.
    tx_suppress_line: bool,
    /// Escape-sequence tracking state (see the module docs).
    vt_esc: bool,
    vt_csi: u8,
    vt_seq: Vec<u8>,
    vt_param: u32,
    vt_priv: u8,
    vt_dsr: bool,
    vt_row: u32,
    vt_col: u32,
    /// Set by feed(): the guest's exit code from the exit marker.
    pub exit_code: Option<i32>,
    /// Set by feed(): the export save path from the export marker.
    pub export_path: Option<String>,
    /// Set by feed(): true when a query reply was injected into the console
    /// RX (the caller must pulse the console IRQ so the guest reads it).
    pub replied: bool,
    /// DA1 (`ESC[c`) answered once: tmux re-sends DA1 around redraws while
    /// its own reply is still in flight; its parser consumes the FIRST
    /// response and treats every later one as plain keys (TTY_HAVEDA is
    /// already set), which would leak into the focused pane as typed text.
    /// A real terminal answers every query, but tmux only needs the first —
    /// later queries are swallowed silently.
    da1_answered: bool,
    /// DA2 (`ESC[>c`) — same once-only treatment as DA1.
    da2_answered: bool,
    /// True while a fullscreen app owns the terminal (alternate screen:
    /// tmux attaches with `ESC[?1049h`, leaves with `ESC[?1049l`). Under
    /// alt-screen the outer console shell is parked, so console-level DSR
    /// replies have no consumer — the attached client forwards them as
    /// unknown keys into the focused pane, where they leak as typed text
    /// (a probe reply racing the attach is what skewed ash's cursor state).
    /// Pane-level probes are answered by the guest's own tmux and are
    /// unaffected.
    alt_screen: bool,
}

#[cfg(target_os = "linux")]
impl ConsoleTxFilter {
    pub(crate) fn new(exit_marker: String) -> Self {
        ConsoleTxFilter {
            exit_marker,
            tx_line: Vec::new(),
            tx_hold: Vec::new(),
            tx_suppress_line: false,
            vt_esc: false,
            vt_csi: 0,
            vt_seq: Vec::new(),
            vt_param: 0,
            vt_priv: 0,
            vt_dsr: false,
            vt_row: 1,
            vt_col: 1,
            exit_code: None,
            export_path: None,
            replied: false,
            da1_answered: false,
            da2_answered: false,
            alt_screen: false,
        }
    }

    /// Feed guest console TX bytes: track the escape state, answer terminal
    /// queries (into the console RX), filter protocol markers, and append
    /// the visible bytes to `out`.
    pub(crate) fn feed(
        &mut self,
        data: &[u8],
        console: &Arc<Mutex<VirtioConsoleDevice>>,
        memory: &Arc<GuestRam>,
        ram_base: u64,
        out: &mut Vec<u8>,
    ) {
        let mut replies: Vec<Vec<u8>> = Vec::new();

        for &ch in data {
            if self.exit_code.is_some() {
                // The guest is shutting down; drop trailing output.
                break;
            }

            // ── Virtual-terminal escape handling ──────────────────────
            // The guest's line editor probes the terminal with `ESC [ 6 n`
            // and reads the reply from its input; tmux also probes with
            // DA1/DA2 before its first draw. The VMM is the virtual
            // terminal: those queries are answered here from a tracked
            // cursor position. Every OTHER escape sequence (erase, colors,
            // cursor movement) is forwarded verbatim — swallowing those
            // breaks guest-side erases like the backspace path's `ESC[J`.
            if self.vt_esc {
                self.vt_seq.push(ch);
                if self.vt_csi == 0 {
                    if ch == b'[' {
                        self.vt_csi = b'[';
                    } else {
                        self.end_vt_sequence(&mut replies, out);
                    }
                    continue;
                }
                if ch == b'>' && self.vt_param == 0 {
                    self.vt_priv = 2;
                } else if ch == b'?' {
                    self.vt_priv = 1;
                } else if ch.is_ascii_digit() {
                    self.vt_param = self.vt_param * 10 + (ch - b'0') as u32;
                }
                if (0x40..=0x7e).contains(&ch) {
                    self.end_vt_sequence(&mut replies, out);
                }
                continue;
            }
            if ch == 0x1b {
                self.vt_esc = true;
                self.vt_csi = 0;
                self.vt_seq.clear();
                self.vt_seq.push(0x1b);
                self.vt_param = 0;
                self.vt_priv = 0;
                self.vt_dsr = false;
                continue;
            }

            // Cursor tracking for the DSR replies (printable +1, BS -1).
            if (0x20..0x7f).contains(&ch) {
                self.vt_col += 1;
            } else if ch == b'\x08' {
                self.vt_col = self.vt_col.saturating_sub(1);
            } else if ch == b'\n' || ch == b'\r' {
                self.vt_col = 0;
                self.vt_row += 1;
            }

            self.emit_tx_byte(ch, out);

            if ch == b'\n' {
                self.tx_suppress_line = false;
                self.tx_hold.clear();
                let line = std::mem::take(&mut self.tx_line);
                self.process_console_line(&line);
            }
        }

        // Inject query replies into the console RX.
        if !replies.is_empty() {
            let mut blob = Vec::new();
            for r in &replies {
                blob.extend_from_slice(r);
            }
            console
                .lock()
                .unwrap()
                .push_rx_and_drain(memory.as_shared_slice(), ram_base, &blob);
            self.replied = true;
        }
    }

    /// Finish the escape sequence accumulated in `vt_seq`: answer terminal
    /// queries, forward everything else verbatim, apply cursor movement.
    fn end_vt_sequence(&mut self, replies: &mut Vec<Vec<u8>>, out: &mut Vec<u8>) {
        let seq = std::mem::take(&mut self.vt_seq);
        self.vt_esc = false;
        self.vt_csi = 0;

        let final_byte = seq[seq.len() - 1];
        let is_csi = seq.len() >= 3 && seq[1] == b'[';

        // Alternate-screen tracking (DEC private modes 47/1047/1049): a
        // fullscreen app (tmux) owns the terminal while set — see the
        // `alt_screen` field docs for why DSR replies are suppressed then.
        if is_csi
            && self.vt_priv == 1
            && (final_byte == b'h' || final_byte == b'l')
            && matches!(self.vt_param, 47 | 1047 | 1049)
        {
            self.alt_screen = final_byte == b'h';
        }

        // DSR cursor-position query: `ESC [ 6 n` (empty parameter = same).
        // Suppressed under alt-screen: the outer shell is parked and the
        // reply would be forwarded by the attached client into the focused
        // pane as keys (the pane-level probes are answered by the guest's
        // own tmux with the pane cursor, so nothing needs this reply).
        if is_csi && self.vt_priv == 0 && final_byte == b'n' && self.vt_param <= 6 {
            if !self.alt_screen {
                replies.push(format!("\x1b[{};{}R", self.vt_row, self.vt_col + 1).into_bytes());
            }
            self.vt_param = 0;
            return;
        }
        // DA1 (primary device attributes): `ESC [ c` / `ESC [ 0 c`. tmux and
        // friends block their first draw waiting for this reply. Answered
        // once; tmux re-sends DA1 around redraws while its first reply is
        // still in flight, and its parser treats every later response as
        // plain keys (TTY_HAVEDA is already set) which would leak into the
        // focused pane as typed text — later queries are swallowed silently.
        if is_csi && self.vt_priv == 0 && final_byte == b'c' && self.vt_param <= 1 {
            if !self.da1_answered {
                replies.push(b"\x1b[?1;2c".to_vec()); // VT102 with AVO
                self.da1_answered = true;
            }
            self.vt_param = 0;
            return;
        }
        // DA2 (secondary device attributes): `ESC [ > c` — once only.
        if is_csi && self.vt_priv == 2 && final_byte == b'c' {
            if !self.da2_answered {
                replies.push(b"\x1b[>0;95;0c".to_vec());
                self.da2_answered = true;
            }
            self.vt_param = 0;
            return;
        }
        // XTGETTCAP (`ESC [ > q`): swallowed without forwarding or reply —
        // forwarding reaches the outer terminal, whose answer returns as
        // console input at an unpredictable time and can leak into the
        // focused pane; not answering is handled fine by tmux.
        if is_csi && self.vt_priv == 2 && final_byte == b'q' {
            self.vt_param = 0;
            return;
        }
        self.vt_dsr = false;
        self.vt_param = 0;

        // Apply cursor movement so the tracker stays usable across redraws.
        match final_byte {
            b'C' => self.vt_col += self.vt_param.max(1),
            b'D' => self.vt_col = self.vt_col.saturating_sub(self.vt_param.max(1)),
            b'G' => self.vt_col = self.vt_param.saturating_sub(1),
            _ => {}
        }

        // Forward the sequence to the user's terminal verbatim.
        for b in seq {
            self.emit_tx_byte(b, out);
        }
    }

    fn emit_tx_byte(&mut self, ch: u8, out: &mut Vec<u8>) {
        self.tx_line.push(ch);

        if self.tx_suppress_line {
            return;
        }
        let markers: [&[u8]; 2] = [
            self.exit_marker.as_bytes(),
            initramfs::EXPORT_PATH_MARKER.as_bytes(),
        ];
        self.tx_hold.push(ch);
        if markers.iter().any(|m| self.tx_hold.ends_with(m)) {
            self.tx_hold.clear();
            self.tx_suppress_line = true;
        } else {
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
                out.extend_from_slice(&self.tx_hold[..flush_len]);
                self.tx_hold.drain(..flush_len);
            }
        }
    }

    /// Handle one complete guest console line (marker side effects only —
    /// visible output has already been streamed).
    fn process_console_line(&mut self, line: &[u8]) {
        let Ok(line) = std::str::from_utf8(line) else {
            return;
        };
        let trimmed = line.trim_end_matches(['\n', '\r']);

        if let Some(pos) = trimmed.find(&self.exit_marker) {
            let code = trimmed[pos + self.exit_marker.len()..].trim();
            // Only a real integer is the exit protocol. Commands like
            // `cat /init` surface the script's unexpanded placeholder —
            // that must not shut the VM down.
            if let Ok(code) = code.parse::<i32>() {
                self.exit_code = Some(code);
                return;
            }
        }
        if let Some(pos) = trimmed.find(initramfs::EXPORT_PATH_MARKER) {
            let path = trimmed[pos + initramfs::EXPORT_PATH_MARKER.len()..].trim();
            if path.starts_with('/') {
                self.export_path = Some(path.to_string());
            }
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
    /// Shared console-TX pipeline state (escape tracking, terminal-query
    /// replies, protocol markers). The main loop and the net-kick thread
    /// BOTH drain the TX queue; the filter must be singular or escape
    /// sequences tear apart at drain boundaries.
    #[cfg(target_os = "linux")]
    console_tx_filter: Arc<Mutex<ConsoleTxFilter>>,
    /// x86_64: base of the MMIO device window (above the guest RAM).
    #[cfg(target_arch = "x86_64")]
    mmio_base: u64,
    /// Terminal-query reply dedup for the macOS path (no shared filter —
    /// the run loop's own tracker does the answering).
    #[cfg(target_os = "macos")]
    da1_answered: bool,
    #[cfg(target_os = "macos")]
    da2_answered: bool,
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
    /// Guest command exit status from the exit marker.
    guest_exit_code: Option<i32>,
    /// Virtual-terminal escape tracking for the macOS run loop (on Linux
    /// this state lives in the shared `console_tx_filter` instead): the
    /// guest's line editor (busybox ash) probes the terminal with
    /// `ESC [ 6 n` (device status report: cursor position) and reads the
    /// reply from its input. The VMM is the virtual terminal: it intercepts
    /// that one query and answers it from a conservatively tracked cursor
    /// position, so the editor's line-wrap and redraw logic stay correct on
    /// long input lines. Every OTHER escape sequence (erase, colors, cursor
    /// movement) is forwarded to the user's terminal untouched — swallowing
    /// those breaks guest-side erases like the backspace path's `ESC [ J`.
    #[cfg(target_os = "macos")]
    tx_line: Vec<u8>,
    #[cfg(target_os = "macos")]
    tx_hold: Vec<u8>,
    #[cfg(target_os = "macos")]
    tx_suppress_line: bool,
    #[cfg(target_os = "macos")]
    vt_esc: bool,
    #[cfg(target_os = "macos")]
    vt_csi: u8,
    /// Bytes of the escape sequence currently being parsed.
    #[cfg(target_os = "macos")]
    vt_seq: Vec<u8>,
    /// Numeric parameter accumulated from the current CSI sequence.
    #[cfg(target_os = "macos")]
    vt_param: u32,
    /// True when the accumulated CSI parameter is 6 (a DSR query).
    #[cfg(target_os = "macos")]
    vt_dsr: bool,
    /// CSI private-marker byte: 0 = none, 1 = `?` (DEC), 2 = `>` (VT).
    #[cfg(target_os = "macos")]
    vt_priv: u8,
    /// Tracked terminal cursor (1-based) for DSR cursor-position replies.
    #[cfg(target_os = "macos")]
    vt_row: u32,
    #[cfg(target_os = "macos")]
    vt_col: u32,
    /// Alternate-screen state for DSR suppression (see `ConsoleTxFilter`).
    #[cfg(target_os = "macos")]
    alt_screen: bool,
}

// ─────────────────────────────────────────────────────────────────────────
// Host terminal geometry
// ─────────────────────────────────────────────────────────────────────────

/// Set by the SIGWINCH handler when the host terminal is resized.
static HOST_WINCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn winch_handler(_sig: i32) {
    HOST_WINCH.store(true, Ordering::Relaxed);
}

/// The guest console geometry: the host tty's size, so the guest screen
/// matches the terminal it renders into. A hardcoded size mismatches the
/// user's pane — a guest screen taller than the host pane scrolls the
/// prompt out of view (the guest tmux status line would be the only thing
/// left visible). Falls back to 120x40 when stdout is not a tty (tests
/// drive their own pty and pipes have no size).
fn host_tty_size() -> (u16, u16) {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    for fd in [libc::STDOUT_FILENO, libc::STDIN_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `ws` is a valid winsize; TIOCGWINSZ only fills it in.
        let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0;
        if ok && ws.ws_col > 0 && ws.ws_row > 0 {
            return (ws.ws_col, ws.ws_row);
        }
    }
    (120, 40)
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

    /// Map a guest physical address to a virtiofs device index, if in range.
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
    use std::io::Write;
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{msg}\r");
}

/// Process-start timestamp for BOOT_TIMING diagnostics.
pub static BOOT_T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub fn run(args: Args) -> Result<i32> {
    let timing = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
    let t0 = BOOT_T0.get_or_init(std::time::Instant::now);
    let mut vmm = Vmm::new(&args)?;
    if timing {
        eprintln!("BOOT_TIMING vmm_new: {:?}", t0.elapsed());
    }
    vmm.boot(&args)?;
    if timing {
        eprintln!("BOOT_TIMING boot (disks+rootfs+kernel): {:?}", t0.elapsed());
    }
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
        let layer_data = fs::read(layer)
            .map_err(|e| anyhow!("failed to read layer {}: {e}", layer.display()))?;
        let entries = crate::tar::read_tar_zst(&layer_data)?;
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

        let console = {
            let (cols, rows) = host_tty_size();
            Arc::new(Mutex::new(VirtioConsoleDevice::new(cols, rows)))
        };

        // Track host terminal resizes: the SIGWINCH handler only sets a
        // flag; the run loop applies the new geometry (and interrupts the
        // guest) on its next iteration.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = winch_handler as extern "C" fn(i32) as usize;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
        }

        // User-space networking (enabled unless --no-network). The run loops
        // poll the backend after every guest exit and the Linux net-kick
        // thread pumps it independently, so an idle guest never waits for
        // its own delayed-ACK timer before more host data is delivered.
        if tt {
            eprintln!("BOOT_TIMING   console+winch: {:?}", tp.elapsed());
            tp = std::time::Instant::now();
        }
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
        if tt {
            eprintln!("BOOT_TIMING   net: {:?}", tp.elapsed());
        }

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
            let irq_levels = linux::new_irq_levels();
            let (stdin_thread, stdin_stop_w) = linux::spawn_stdin_poller(
                vm.clone(),
                console.clone(),
                memory.clone(),
                irq_lock.clone(),
                irq_levels.clone(),
            )?;
            linux::KvmHost {
                irq_lock,
                stdin_stop_w,
                stdin_thread: Some(stdin_thread),
                irq_levels,
            }
        };

        #[cfg(target_os = "linux")]
        let net_kick_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(target_os = "linux")]
        let console_tx_filter = Arc::new(Mutex::new(ConsoleTxFilter::new(
            exit_marker.trim_end_matches(':').to_string(),
        )));

        #[cfg(target_os = "linux")]
        linux::spawn_net_kicker(
            vm.clone(),
            net.clone(),
            console.clone(),
            memory.clone(),
            console_tx_filter.clone(),
            host.irq_lock.clone(),
            host.irq_levels.clone(),
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
            #[cfg(target_os = "linux")]
            console_tx_filter,
            #[cfg(target_arch = "x86_64")]
            mmio_base,
            #[cfg(target_os = "macos")]
            da1_answered: false,
            #[cfg(target_os = "macos")]
            da2_answered: false,
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
            // -v or SANDAL_VERBOSE_UART=1: mirror guest serial-port (0x3f8)
            // THR writes to stderr — a diagnostics channel that bypasses
            // the guest tty stack entirely (see tests/test_tmux_attached.py).
            verbose_uart: args.verbose || std::env::var_os("SANDAL_VERBOSE_UART").is_some(),
            exit_marker,
            export_save_path: None,
            #[cfg(target_os = "macos")]
            tx_line: Vec::new(),
            #[cfg(target_os = "macos")]
            tx_hold: Vec::new(),
            #[cfg(target_os = "macos")]
            tx_suppress_line: false,
            guest_exit_code: None,
            #[cfg(target_os = "macos")]
            vt_esc: false,
            #[cfg(target_os = "macos")]
            vt_csi: 0,
            #[cfg(target_os = "macos")]
            vt_seq: Vec::new(),
            #[cfg(target_os = "macos")]
            vt_param: 0,
            #[cfg(target_os = "macos")]
            vt_priv: 0,
            #[cfg(target_os = "macos")]
            vt_dsr: false,
            #[cfg(target_os = "macos")]
            vt_row: 1,
            #[cfg(target_os = "macos")]
            vt_col: 1,
            #[cfg(target_os = "macos")]
            alt_screen: false,
        })
    }

    fn boot(&mut self, args: &Args) -> Result<()> {
        let timing = std::env::var_os("SANDAL_DEBUG_TIMING").is_some();
        let t0 = std::time::Instant::now();
        // ── Writable data disk (vdb): --disk-size / --layer ────────────
        // Created first: DISK_MODE in the init config selects the overlay
        // upperdir (disk vs tmpfs), so `data_blk` must be known by then.
        if args.disk_size.is_some() || !args.layers.is_empty() {
            self.data_blk = Some(VirtioBlkDevice::new(build_data_disk(args)?));
        }
        if timing {
            eprintln!("BOOT_TIMING data_disk: {:?}", t0.elapsed());
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
            None => {
                let t = std::time::Instant::now();
                let img = crate::rootfs::load();
                if timing {
                    eprintln!("BOOT_TIMING rootfs_gunzip: {:?}", t.elapsed());
                }
                img
            }
        };

        crate::ext2::inject_runtime_files(&mut rootfs_img, !args.no_network, self.mmio_window())?;

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
        if timing {
            eprintln!("BOOT_TIMING kernel_load: {:?}", t0.elapsed());
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

        if (mw + MMIO_OFF_CONSOLE..mw + MMIO_OFF_CONSOLE + 0x200).contains(&addr) {
            return self
                .console
                .lock()
                .unwrap()
                .mmio_read(addr - mw - MMIO_OFF_CONSOLE, sas);
        }

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

        if (mw + MMIO_OFF_CONSOLE..mw + MMIO_OFF_CONSOLE + 0x200).contains(&addr) {
            let mut console = self.console.lock().unwrap();
            let notify = console.mmio_write(addr - mw - MMIO_OFF_CONSOLE, val as u32);
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
                // Hypercall page: a u32 write of the port number signals the VMM
                // (the x86 analog of the ARM64 BRK immediates).
                match val as u16 {
                    crate::elf::x86_64_linux::EXPORT_RESIZE_PORT => self.handle_export_resize(),
                    crate::elf::x86_64_linux::EXPORT_DONE_PORT => self.handle_export_done(),
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

    /// `export done`: turn the guest's overlay upper tree into a
    /// zstd-compressed `.layer` file on the host.
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

        let tar_data = match crate::ext2::read_upper_tar_entries(&dev.disk_image).map(|entries| {
            // Shell history is session state, not guest data: the
            // export deliberately skips it so it never round-trips
            // through layers. History still lives in the data disk for
            // the running VM.
            let mut entries: Vec<_> = entries;
            entries.retain(|e| !e.path.ends_with("/.ash_history"));
            entries
        }) {
            Ok(entries) if !entries.is_empty() => crate::tar::write_tar(&entries),
            _ => {
                // Fall back to a raw tar the guest wrote to the device.
                let end = crate::tar::find_tar_end(&dev.disk_image);
                if end == 0 {
                    log::warn!("export done: no exportable data found");
                    console_eprintln("sandal: export failed: no exportable data found");
                    return;
                }
                dev.disk_image[..end].to_vec()
            }
        };

        let layer_data = match zstd::bulk::compress(&tar_data, 3) {
            Ok(data) => data,
            Err(e) => {
                console_eprintln(&format!("sandal: export failed to compress layer: {e}"));
                return;
            }
        };

        let save_path = match self.export_save_path.take() {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => {
                let mut hasher = DefaultHasher::new();
                layer_data.hash(&mut hasher);
                PathBuf::from(format!("layer-{:016x}.layer", hasher.finish()))
            }
        };

        match fs::write(&save_path, &layer_data) {
            Ok(()) => console_eprintln(&format!("Layer saved to: {}", save_path.display())),
            Err(e) => console_eprintln(&format!("sandal: failed to save layer: {e}")),
        }
    }

    /// Feed guest console TX bytes to stdout while intercepting the VMM
    /// protocol markers (the per-boot exit token and
    /// `SANDAL_EXPORT_PATH:`), which are consumed here instead of being
    /// shown to the user. macOS only: on Linux the run loop and the
    /// net-kick thread share `console_tx_filter` instead (a singular
    /// escape/marker state — two trackers would tear sequences apart at
    /// drain boundaries).
    #[cfg(target_os = "macos")]
    fn process_console_tx(&mut self, data: &[u8]) {
        let mut replies: Vec<Vec<u8>> = Vec::new();
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
                        self.end_vt_sequence(&mut replies);
                    }
                    continue;
                }

                if ch.is_ascii_digit() {
                    self.vt_param = self.vt_param * 10 + (ch - b'0') as u32;
                }

                if (0x40..=0x7e).contains(&ch) {
                    // Final byte: the sequence is complete.
                    self.end_vt_sequence(&mut replies);
                }

                continue;
            }

            if ch == 0x1b {
                self.vt_esc = true;
                self.vt_csi = 0;
                self.vt_seq.clear();
                self.vt_seq.push(0x1b);
                self.vt_param = 0;
                self.vt_priv = 0;
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

        // Answer terminal queries (DSR, DA, XTGETTCAP): the replies go
        // into the console RX — guest terminal applications read them as
        // input. One IRQ pulse for the whole batch.
        if !replies.is_empty() {
            let mut blob = Vec::new();
            for r in &replies {
                blob.extend_from_slice(r);
            }
            self.console.lock().unwrap().push_rx_and_drain(
                self.memory.as_shared_slice(),
                RAM_BASE,
                &blob,
            );

            #[cfg(target_os = "linux")]
            {
                // Raise the console line under the irq_lock so this raise
                // can never be reordered after the pollers'/main loop's
                // line updates (a lost interrupt).
                let _guard = self.host.irq_lock.lock();
                let idx = (crate::irqs::SPI_CONSOLE - crate::irqs::SPI_NET) as usize;
                linux::irq_pulse(
                    &self.host.irq_levels,
                    idx,
                    &self.vm,
                    self.irq_line_for_spi(crate::irqs::SPI_CONSOLE),
                );
            }
        }
    }

    /// Finish the escape sequence accumulated in `vt_seq`: answer DSR
    /// cursor-position queries, forward everything else to the user's
    /// terminal, and apply cursor-movement sequences to the tracker.
    #[cfg(target_os = "macos")]
    fn end_vt_sequence(&mut self, replies: &mut Vec<Vec<u8>>) {
        let seq = std::mem::take(&mut self.vt_seq);
        if std::env::var_os("SANDAL_DEBUG_KVM").is_some() {
            console_eprintln(&format!("DBG-SEQ param={} seq={seq:02x?}", self.vt_param));
        }

        self.vt_esc = false;
        self.vt_csi = 0;

        let final_byte = seq[seq.len() - 1];
        let is_csi = seq.len() >= 3 && seq[1] == b'[';

        // Alternate-screen tracking (see `ConsoleTxFilter`).
        if is_csi
            && self.vt_priv == 1
            && (final_byte == b'h' || final_byte == b'l')
            && matches!(self.vt_param, 47 | 1047 | 1049)
        {
            self.alt_screen = final_byte == b'h';
        }

        // DSR cursor-position query: `ESC [ 6 n` (empty parameter = same).
        // Suppressed under alt-screen (a fullscreen app owns the terminal;
        // the reply would have no consumer).
        if is_csi && self.vt_priv == 0 && final_byte == b'n' && self.vt_param <= 6 {
            if !self.alt_screen {
                // Cursor position is 1-based: after N printable columns the
                // cursor sits at column N+1.
                replies.push(format!("\x1b[{};{}R", self.vt_row, self.vt_col + 1).into_bytes());
            }
            self.vt_param = 0;
            return;
        }
        // DA1 (primary device attributes): `ESC [ c` / `ESC [ 0 c`. tmux and
        // friends block their first draw waiting for this reply. Answered
        // once; later queries are swallowed (see `da1_answered`).
        if is_csi && self.vt_priv == 0 && final_byte == b'c' && self.vt_param <= 1 {
            if !self.da1_answered {
                replies.push(b"\x1b[?1;2c".to_vec()); // VT102 with AVO
                self.da1_answered = true;
            }
            self.vt_param = 0;
            return;
        }
        // DA2 (secondary device attributes): `ESC [ > c` — once only.
        if is_csi && self.vt_priv == 2 && final_byte == b'c' {
            if !self.da2_answered {
                replies.push(b"\x1b[>0;95;0c".to_vec());
                self.da2_answered = true;
            }
            self.vt_param = 0;
            return;
        }
        // XTGETTCAP (`ESC [ > q`): swallowed without forwarding and without
        // a reply. Forwarding it would reach the user's outer terminal,
        // whose answer comes back as console input at an unpredictable time
        // and can leak into the focused pane as keys; not answering just
        // leaves tmux's terminfo-feature probing unanswered, which it
        // handles fine (it worked before query answering existed).
        if is_csi && self.vt_priv == 2 && final_byte == b'q' {
            self.vt_param = 0;
            return;
        }
        self.vt_dsr = false;
        self.vt_param = 0;

        // Apply cursor movement so the tracker stays usable across
        // redraws: `C` (forward), `D` (back), `G` (column absolute).
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
    #[cfg(target_os = "macos")]
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
    #[cfg(target_os = "macos")]
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
