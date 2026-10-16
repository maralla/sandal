/// Virtio-console device implementation.
///
/// Provides a paravirtualized serial console (hvc0) to the guest via the
/// virtio MMIO transport.  Replaces the traditional MMIO UART for interactive
/// terminal I/O, batching characters through virtqueues instead of trapping
/// per-byte.
///
/// Three ports, eight queues (virtio-console "multiport"; see
/// [`VirtioConsoleDevice::pump_control_sequence`]):
///   - port 0 — the console port (hvc0): kernel printk and the guest init.
///   - port 1 — a host device port (/dev/virtio-ports/vport1p1): the
///     interactive session rides a guest pty bridged to this port by the
///     guest-side agent, because the console port's tty path spends one full
///     hypervisor round trip per output LINE (measured ~150 KB/s) while the
///     host port moves whole buffers per round trip.
///   - port 2 — the export path port (/dev/virtio-ports/vport1p2): the
///     export script writes the host-side layer path there; the VMM reads
///     it from the port's TX queue (see
///     [`VirtioConsoleDevice::process_export_tx`]). A dedicated channel —
///     the whole stream IS the path — so no string matching happens
///     anywhere (the old `SANDAL_EXPORT_PATH:` console marker is gone).
///
/// Queues (two per port, plus one control pair — the order the guest driver
/// requests them in, see its init_vqs):
///   - queue 0: console RX (host → guest)
///   - queue 1: console TX (guest → host)
///   - queue 2: control RX (host → guest control messages)
///   - queue 3: control TX (guest → host control replies)
///   - queue 4: port RX (host → guest)
///   - queue 5: port TX (guest → host)
///   - queue 6: export RX (host → guest; unused — nothing to inject)
///   - queue 7: export TX (guest → host: the export path)
use std::mem;

use super::*;

// Virtio device ID for console (virtio spec §5.3)
const VIRTIO_ID_CONSOLE: u32 = 3;

const QUEUE_SIZE: u32 = 128;
const NUM_QUEUES: usize = 8;

/// Queue roles (the guest driver's own ordering; see the module docs).
pub const CONSOLE_RX: usize = 0;
pub const CONSOLE_TX: usize = 1;
pub const CONTROL_RX: usize = 2;
pub const CONTROL_TX: usize = 3;
pub const PORT_RX: usize = 4;
pub const PORT_TX: usize = 5;
/// The export port's RX half is unused (nothing is ever injected there —
/// the path only flows guest → host), kept for the queue map's symmetry.
#[allow(dead_code)]
pub const EXPORT_RX: usize = 6;
pub const EXPORT_TX: usize = 7;

/// Feature bit: console size (cols, rows) is available in config space.
const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;
/// Feature bit: multiple ports (the host device port).
const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;

/// How many ports the device offers (the console port, the host port, and
/// the export path port). The guest driver validates this against its own
/// maximum (0x8000) and requests (ports + 1) * 2 queues.
const MAX_NR_PORTS: u32 = 3;

/// Control message events (the guest driver's uapi numbering).
const CTRL_PORT_ADD: u16 = 1;
#[allow(dead_code)]
const CTRL_PORT_REMOVE: u16 = 2;
#[allow(dead_code)]
const CTRL_PORT_READY: u16 = 3;
const CTRL_CONSOLE_PORT: u16 = 4;
#[allow(dead_code)]
const CTRL_RESIZE: u16 = 5;
const CTRL_PORT_OPEN: u16 = 6;

/// One control message: { u32 id, u16 event, u16 value }.
fn control_message(id: u32, event: u16, value: u16) -> [u8; 8] {
    let mut m = [0u8; 8];
    m[0..4].copy_from_slice(&id.to_le_bytes());
    m[4..6].copy_from_slice(&event.to_le_bytes());
    m[6..8].copy_from_slice(&value.to_le_bytes());
    m
}

/// Parse a CONTROL_TX stream (8-byte `{ u32 id, u16 event, u16 value }`
/// messages, possibly batched) for the session signal: the last
/// `PORT_OPEN(1, guest_connected)` wins — Some(true) = the guest agent
/// opened the host device port (session on the port), Some(false) = it
/// closed it. MEASURED in the guest driver (kernel-build/linux-7.2.10/
/// drivers/char/virtio_console.c): port_fops_open sends
/// `send_control_msg(port, VIRTIO_CONSOLE_PORT_OPEN, 1)` and
/// port_fops_release sends value 0 — every open/release, nothing else
/// carries the session state.
fn parse_control_session(bytes: &[u8]) -> Option<bool> {
    let mut session = None;
    for m in bytes.as_chunks::<8>().0 {
        let id = u32::from_le_bytes(m[0..4].try_into().unwrap());
        let event = u16::from_le_bytes(m[4..6].try_into().unwrap());
        let value = u16::from_le_bytes(m[6..8].try_into().unwrap());
        if id == 1 && event == CTRL_PORT_OPEN {
            session = Some(value == 1);
        }
    }
    session
}

/// ARM64 Data Abort ISS `SAS` field: access size for the faulting load/store.
#[inline]
fn mmio_fault_access_bytes(sas: u8) -> usize {
    match sas & 3 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Read virtio-console config bytes (`§5.3.7`, 16 bytes LE) honoring guest load width and offset.
fn read_console_config_le(cfg: &[u8; 16], byte_off: usize, sas: u8) -> u64 {
    let width = mmio_fault_access_bytes(sas);
    if byte_off >= 16 {
        return 0;
    }
    let n = (16 - byte_off).min(width);
    let mut buf = [0u8; 8];
    buf[..n].copy_from_slice(&cfg[byte_off..byte_off + n]);
    match width {
        1 => buf[0] as u64,
        2 => u16::from_le_bytes(buf[..2].try_into().unwrap()) as u64,
        4 => u32::from_le_bytes(buf[..4].try_into().unwrap()) as u64,
        _ => u64::from_le_bytes(buf),
    }
}

/// One RX (host → guest) channel's delivery state: the undelivered
/// backlog (see [`VirtioConsoleDevice::drain_rx_backlog`]).
pub struct RxChannel {
    /// Host bytes not yet copied into the guest receiveq — survives `read()`
    /// when the guest has not posted RX buffers yet.
    pub backlog: Vec<u8>,
    /// When the backlog last failed to make progress (the guest refusing
    /// input). Past the stall timeout the backlog is dropped: a permanently
    /// refusing guest must not turn host input into a silent infinite wait.
    pub stall_since: Option<std::time::Instant>,
    /// A pending terminal-resize record (see [`VirtioConsoleDevice::`]
    /// `set_resize_record`): delivered WHOLE, in one direct injection ahead
    /// of the backlog — never through the backlog itself, whose adaptive
    /// window would split it (a split record leaks its magic into the
    /// input stream) and whose size an idle session never grew (a host
    /// zoom on an idle session would resize nothing).
    pub resize_record: Option<[u8; 8]>,
}

impl RxChannel {
    fn new() -> Self {
        RxChannel {
            backlog: Vec::new(),
            stall_since: None,
            resize_record: None,
        }
    }

    fn reset(&mut self) {
        self.backlog.clear();
        self.stall_since = None;
        self.resize_record = None;
    }
}

pub struct VirtioConsoleDevice {
    // MMIO state
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,

    // Console config
    pub cols: u16,
    pub rows: u16,

    /// Host→guest delivery state per RX channel: the console port (queue 0)
    /// and the host device port (queue 4).
    pub console_rx: RxChannel,
    pub port_rx: RxChannel,

    /// The port-instantiation control sequence's delivery mask: one bit
    /// per message, cleared as each message lands in its own posted
    /// control-RX head (see [`VirtioConsoleDevice::pump_control_sequence`]).
    /// Covers boot ordering only — a partial batch is re-delivered next
    /// pump call; once every bit lands the sequence is never touched again.
    pub control_seq_pending: u8,

    /// True once the guest's init signaled `SESSION:port`: the interactive
    /// session moved onto the host device port, so host stdin is injected
    /// into the port RX queue instead of the console RX queue.
    ///
    /// Marker-free since the control channel carries it: the guest driver
    /// sends `PORT_OPEN(1, guest_connected=1/0)` on every open/release of
    /// the port device (see [`VirtioConsoleDevice::process_control_tx`]) —
    /// the old `<token>SESSION:port` echo is gone.
    pub session_input_on_port: bool,

    /// The export path, read from the export port's TX stream (see
    /// [`VirtioConsoleDevice::process_export_tx`]). Either drainer — the
    /// run loop or the net-kick thread — may be the one pumping when the
    /// export script writes it; `handle_export_done` takes it.
    pub export_path: Option<String>,

    /// Monotonically increments each time the VMM delivers RX data or processes TX.
    /// Used to detect work that arrives between the guest's ISR read of INTERRUPT_STATUS
    /// and its INTERRUPT_ACK write, preventing lost interrupts.
    pub work_gen: u64,

    /// Snapshot of `work_gen` captured when the guest last read INTERRUPT_STATUS.
    /// If `work_gen > work_gen_at_read` at ACK time, new work arrived after the guest
    /// last sampled the status register, so the interrupt must not be cleared.
    pub work_gen_at_read: u64,
}

impl VirtioConsoleDevice {
    /// Max transmitq avail heads per `process_tx` call so Tab-sized bursts do not monopolize the
    /// VMM thread (stdin + main loop make progress between `vcpu.run()` entries).
    const TX_HEADS_PER_SLICE: u16 = 256;

    /// How long a refusing guest may hold host input before it is dropped.
    const RX_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    /// Maximum host bytes moved into the guest per call: a constant page.
    /// The old adaptive window (grow on acceptance, reset to 1 on refusal)
    /// ramped delivery back up over seconds after every refusal — the typed
    /// line's terminating Enter lagged behind its characters — while the
    /// driver takes exactly one page per cycle either way (measured in
    /// kernel-build/linux-7.2.10/drivers/char/virtio_console.c: in_intr
    /// stashes one PAGE_SIZE buffer per IRQ): the adaptivity was pure lag.
    const MAX_RX_CHUNK: usize = 4096;

    /// The advertised terminal geometry (cols, rows). The guest tty needs a
    /// real window size: without it, fullscreen editors (vi) that size
    /// themselves from TIOCGWINSZ lay out a degenerate 0x0 grid.
    pub fn terminal_size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    pub fn new(cols: u16, rows: u16) -> Self {
        VirtioConsoleDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: std::array::from_fn(|_| VirtqState::new(QUEUE_SIZE)),
            status: 0,
            interrupt_status: 0,
            cols,
            rows,
            console_rx: RxChannel::new(),
            port_rx: RxChannel::new(),
            control_seq_pending: 0b111_1111,
            session_input_on_port: false,
            export_path: None,
            work_gen: 0,
            work_gen_at_read: 0,
        }
    }

    fn virtio_console_config_bytes(&self) -> [u8; 16] {
        let mut cfg = [0u8; 16];
        cfg[0..2].copy_from_slice(&self.cols.to_le_bytes());
        cfg[2..4].copy_from_slice(&self.rows.to_le_bytes());
        // max_nr_ports (virtio spec §5.3.7): the console port + the host
        // device port. The guest driver only instantiates hvc0 and the
        // /dev/virtio-ports node after the control sequence says so.
        cfg[4..8].copy_from_slice(&MAX_NR_PORTS.to_le_bytes());
        cfg
    }

    /// Resize the advertised console geometry (the host window changed).
    /// Returns whether the config changed (the caller must raise the
    /// config-change interrupt so the guest re-reads it — the virtio
    /// console driver feeds this to hvc_resize).
    pub fn set_size(&mut self, cols: u16, rows: u16) -> bool {
        if self.cols == cols && self.rows == rows {
            return false;
        }
        self.cols = cols;
        self.rows = rows;
        self.interrupt_status |= VIRTIO_MMIO_INT_CONFIG;
        self.work_gen += 1;
        true
    }

    /// True once the control handshake's whole sequence has been DELIVERED
    /// Handle an MMIO read at `offset` within the device's MMIO region.
    ///
    /// `sas` is the ARM64 Data Abort ISS access size (`0` byte … `3` doubleword). Required for
    /// `DEVICE_CONFIG` loads: Linux may use `readl` on `cols`/`rows` or byte/halfword probes.
    pub fn mmio_read(&mut self, offset: u64, sas: u8) -> u64 {
        let cfg = self.virtio_console_config_bytes();
        if (REG_CONFIG_BASE..REG_CONFIG_BASE + 16).contains(&offset) {
            return read_console_config_le(&cfg, (offset - REG_CONFIG_BASE) as usize, sas);
        }
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC as u64,
            REG_VERSION => VIRTIO_MMIO_VERSION as u64,
            REG_DEVICE_ID => VIRTIO_ID_CONSOLE as u64,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR as u64,
            REG_DEVICE_FEATURES => {
                let features =
                    VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_SIZE | VIRTIO_CONSOLE_F_MULTIPORT;
                if self.device_features_sel == 0 {
                    features & 0xFFFFFFFF
                } else {
                    (features >> 32) & 0xFFFFFFFF
                }
            }
            REG_QUEUE_NUM_MAX => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].num_max as u64
                } else {
                    0
                }
            }
            REG_QUEUE_READY => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].ready as u64
                } else {
                    0
                }
            }
            REG_INTERRUPT_STATUS => {
                self.work_gen_at_read = self.work_gen;
                self.interrupt_status as u64
            }
            REG_STATUS => self.status as u64,
            REG_SHM_LEN_LOW | REG_SHM_LEN_HIGH => 0xFFFFFFFF,
            REG_SHM_BASE_LOW | REG_SHM_BASE_HIGH => 0,
            REG_CONFIG_GENERATION => 0,
            _ => 0,
        }
    }

    /// Handle an MMIO write at `offset` within the device's MMIO region.
    /// Returns Some(queue_index) if QueueNotify was written.
    pub fn mmio_write(&mut self, offset: u64, value: u32) -> Option<u32> {
        match offset {
            REG_DEVICE_FEATURES_SEL => {
                self.device_features_sel = value;
            }
            REG_DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFFFFFF00000000) | value as u64;
                } else {
                    self.driver_features =
                        (self.driver_features & 0x00000000FFFFFFFF) | ((value as u64) << 32);
                }
            }
            REG_DRIVER_FEATURES_SEL => {
                self.driver_features_sel = value;
            }
            REG_QUEUE_SEL => {
                self.queue_sel = value;
            }
            REG_QUEUE_NUM => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].num = value;
                }
            }
            REG_QUEUE_READY => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let sel = self.queue_sel as usize;
                    let was_ready = self.queues[sel].ready;
                    self.queues[sel].ready = value != 0;
                    // A queue re-setup (ready 0→1 with new addresses) without a
                    // device reset: the driver allocated a fresh vring and its
                    // counters start over — ours must too, or we drain phantoms.
                    if value != 0 && !was_ready {
                        crate::vmm_trace::write_console_io(format_args!(
                            "QUEUE_SETUP q={sel} avail={:#x} used={:#x} num={} last_avail={}",
                            self.queues[sel].avail_addr,
                            self.queues[sel].used_addr,
                            self.queues[sel].num,
                            self.queues[sel].last_avail_idx
                        ));
                    }
                }
            }
            REG_QUEUE_NOTIFY => {
                return Some(value);
            }
            REG_INTERRUPT_ACK => {
                self.interrupt_status &= !value;
                // If new work arrived after the guest last read INTERRUPT_STATUS,
                // the ACK must not clear the interrupt for that work.
                if self.work_gen > self.work_gen_at_read {
                    self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
                }
            }
            REG_STATUS => {
                self.status = value;
                if value == 0 {
                    crate::vmm_trace::write_console_io(format_args!(
                        "TX_RESET last_avail={}",
                        self.queues[CONSOLE_TX].last_avail_idx
                    ));
                    self.reset();
                }
            }
            REG_QUEUE_DESC_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.desc_addr = (q.desc_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            REG_QUEUE_DESC_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.desc_addr = (q.desc_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            REG_QUEUE_DRIVER_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.avail_addr = (q.avail_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            REG_QUEUE_DRIVER_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.avail_addr = (q.avail_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            REG_QUEUE_DEVICE_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.used_addr = (q.used_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            REG_QUEUE_DEVICE_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let q = &mut self.queues[self.queue_sel as usize];
                q.used_addr = (q.used_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            _ => {}
        }
        None
    }

    fn reset(&mut self) {
        self.status = 0;
        self.interrupt_status = 0;
        self.driver_features = 0;
        self.console_rx.reset();
        self.port_rx.reset();
        self.control_seq_pending = 0b111_1111;
        self.session_input_on_port = false;
        self.export_path = None;
        self.work_gen = 0;
        self.work_gen_at_read = 0;
        for q in &mut self.queues {
            *q = VirtqState::new(QUEUE_SIZE);
        }
    }

    fn rx_channel(&mut self, q: usize) -> Option<&mut RxChannel> {
        match q {
            CONSOLE_RX => Some(&mut self.console_rx),
            PORT_RX => Some(&mut self.port_rx),
            _ => None,
        }
    }

    /// Append host bytes then inject as much as the guest receiveq can take.
    /// `q` is the RX queue (CONSOLE_RX or PORT_RX). Returns whether any byte
    /// was delivered (and thus `interrupt_status` may be non-zero), plus the
    /// byte count dropped after refusing input for the stall timeout.
    pub fn push_rx_and_drain(
        &mut self,
        memory: &mut [u8],
        ram_base: u64,
        q: usize,
        chunk: &[u8],
    ) -> (bool, usize) {
        if let Some(ch) = self.rx_channel(q) {
            if !chunk.is_empty() {
                ch.backlog.extend_from_slice(chunk);
            }
        }
        self.drain_rx_backlog(memory, ram_base, q)
    }

    /// Retry injecting the backlog of RX queue `q` (e.g. after the guest
    /// posts new receiveq buffers). Returns `(progressed, dropped)`:
    /// `dropped` is the byte count the guest refused for longer than the
    /// stall timeout and that was discarded. Dropping is deliberate: a guest
    /// that stops accepting input (a full tty line discipline, a busy guest)
    /// must not turn host input into a silent infinite wait — the input is
    /// lost and the caller reports it, so the sender can retry.
    /// Queue a terminal-resize record for the port input stream (see the
    /// session agent's RESIZE_MAGIC): delivered WHOLE, in ONE direct
    /// injection ahead of the backlog — never through the backlog itself:
    /// its adaptive window would split the record (a split record leaks
    /// its magic into the input stream), and an idle session's window
    /// never grew past 1, so a window-gated record would never deliver
    /// at all (a host zoom on an idle session would resize nothing). It
    /// is idempotent, and the boot geometry never depends on it (the init
    /// script passes it on the agent's command line).
    pub fn set_resize_record(&mut self, q: usize, record: [u8; 8]) {
        if let Some(ch) = self.rx_channel(q) {
            ch.resize_record = Some(record);
        }
    }

    /// The pending resize record, delivered whole if the port's input
    /// path has a posted buffer. Returns whether anything was delivered
    /// (the caller pulses).
    pub fn drain_resize_record(&mut self, memory: &mut [u8], ram_base: u64, q: usize) -> bool {
        let record = match self.rx_channel(q) {
            Some(ch) => match ch.resize_record {
                Some(record) => record,
                None => return false,
            },
            None => return false,
        };
        // ONE injection, whole: the record never rides the backlog (whose
        // adaptive window would split it — a split record leaks its magic
        // into the input stream, and an idle session's window never grew
        // past 1, so a window-gated record would never deliver at all —
        // a host zoom on an idle session would resize nothing). The one
        // direct injection is atomic by construction: the whole 8 bytes
        // in one buffer, one completion.
        let n = self.inject_rx(memory, ram_base, q, &record);
        if n == record.len() {
            if let Some(ch) = self.rx_channel(q) {
                ch.resize_record = None;
            }
            return true;
        }
        false
    }

    pub fn drain_rx_backlog(
        &mut self,
        memory: &mut [u8],
        ram_base: u64,
        q: usize,
    ) -> (bool, usize) {
        let mut progressed = false;
        // The resize record goes first, whole: it must never interleave
        // with the backlog (a split record leaks its magic; see
        // set_resize_record).
        if self.drain_resize_record(memory, ram_base, q) {
            progressed = true;
        }
        loop {
            let mut pending = match self.rx_channel(q) {
                Some(ch) => {
                    if ch.backlog.is_empty() {
                        ch.stall_since = None;
                        break;
                    }
                    mem::take(&mut ch.backlog)
                }
                None => return (progressed, 0),
            };
            // A constant page per call — the old adaptive window (grow on
            // acceptance, reset to 1 on refusal) only added ramp lag: the
            // driver takes one page per cycle either way (see MAX_RX_CHUNK).
            let chunk_len = pending.len().min(Self::MAX_RX_CHUNK);
            let n = self.inject_rx(memory, ram_base, q, &pending[..chunk_len]);
            pending.drain(..n);
            let Some(ch) = self.rx_channel(q) else {
                return (progressed, 0);
            };
            ch.backlog = pending;
            if n == 0 {
                crate::vmm_trace::write_console_io(format_args!(
                    "RX_BACKLOG_STALL q={q} pending_len={}",
                    ch.backlog.len()
                ));
                // Refused: start (or keep) the stall timer.
                let since = *ch.stall_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() >= Self::RX_STALL_TIMEOUT {
                    let dropped = ch.backlog.len();
                    ch.backlog.clear();
                    ch.stall_since = None;
                    return (progressed, dropped);
                }
                break;
            }
            progressed = true;
            ch.stall_since = None;
        }
        (progressed, 0)
    }

    /// Process TX queue `q` (guest → host): CONSOLE_TX (the console/init
    /// stream), CONTROL_TX (the driver's control replies), or PORT_TX (the
    /// session stream). Returns the captured bytes RAW — the caller applies
    /// stream policy (the console stream's \n → \r\n translation, the
    /// marker/query filter); the port stream passes verbatim (the guest pty
    /// already formed those bytes).
    ///
    /// At most [`Self::TX_HEADS_PER_SLICE`] heads per call.
    pub fn process_tx(&mut self, memory: &mut [u8], ram_base: u64, q: usize) -> Vec<u8> {
        let qs = self.queues[q].clone();
        if !qs.ready || qs.num == 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SKIP q={q} reason=queue_not_ready ready={} num={}",
                qs.ready, qs.num
            ));
            return Vec::new();
        }

        let avail_idx = match read_avail_idx(memory, ram_base, qs.avail_addr) {
            Some(idx) => idx,
            None => {
                crate::vmm_trace::write_console_io(format_args!(
                    "TX_SKIP q={q} reason=bad_avail_ring"
                ));
                return Vec::new();
            }
        };

        let mut last_avail = self.queues[q].last_avail_idx;
        // Overtake guard (guest lapping the avail ring): the avail ring has
        // only `num` slots: once the driver is a full ring ahead of
        // `last_avail`, the slot for every older submission has been
        // overwritten with a newer head. Draining the older window would
        // complete a *phantom* head — the same descriptor id twice — and the
        // guest's second `virtqueue_get_buf` then hits `desc_state[id].data
        // == NULL`, trips BAD_RING ("is not a head"), marks the queue
        // broken, and the console TX dies permanently (every later
        // `virtqueue_add_outbuf` is -ENOENT, so a nonblocking writer like
        // tmux gets EAGAIN once and its write event is never re-armed).
        // Only the last `num` submissions have trustworthy slots: drop the
        // contaminated prefix and drain that window.
        let num16 = qs.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            let target = avail_idx.wrapping_sub(num16);
            crate::vmm_trace::write_console_io(format_args!(
                "TX_OVERTAKE q={q} last_avail={last_avail}->{} avail_idx={avail_idx} num={num16}",
                target
            ));
            last_avail = target;
        }

        if last_avail == avail_idx {
            let used_idx = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SKIP q={q} reason=no_new_heads last_avail={last_avail} avail_idx={avail_idx} used_idx={used_idx} avail_addr={:#x} used_addr={:#x} num={} ready={}",
                qs.avail_addr, qs.used_addr, qs.num, qs.ready
            ));
        }
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
        let mut output = Vec::new();

        while last_avail != avail_idx {
            if used_count >= Self::TX_HEADS_PER_SLICE {
                break;
            }

            let desc_head = match read_avail_ring(
                memory,
                ram_base,
                qs.avail_addr,
                last_avail,
                qs.num,
            ) {
                Some(d) => d,
                None => {
                    crate::vmm_trace::write_console_io(format_args!(
                        "TX_SKIP q={q} reason=bad_avail_ring_entry last_avail={last_avail} avail_idx={avail_idx}"
                    ));
                    break;
                }
            };

            // Walk the descriptor chain, collecting readable (guest→host) bytes
            let mut idx = desc_head;
            let mut chain_len = 0u32;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, qs.desc_addr, idx)
            {
                // TX descriptors are device-readable (no WRITE flag)
                if flags & VIRTQ_DESC_F_WRITE == 0 {
                    if let Some(offset) = addr.checked_sub(ram_base) {
                        let offset = offset as usize;
                        let len = len as usize;
                        if offset + len <= memory.len() {
                            output.extend_from_slice(&memory[offset..offset + len]);
                            chain_len += len as u32;
                        }
                    }
                }

                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                idx = next;
            }

            if write_used_ring(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count),
                qs.num,
                desc_head as u32,
                chain_len,
            )
            .is_none()
            {
                crate::vmm_trace::write_console_io(format_args!(
                    "TX_SKIP q={q} reason=bad_used_ring used_count={used_count}"
                ));
                break;
            }
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[q].last_avail_idx = last_avail;

        if used_count > 0 {
            let _ = write_used_idx(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
            self.work_gen += 1;
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SET_IRQ q={q} used_count={used_count} out_bytes={} irq_status={} last_avail={}",
                output.len(),
                self.interrupt_status,
                last_avail
            ));
        }

        if crate::vmm_trace::console_io_enabled() && used_count > 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "TX_BATCH q={q} heads={used_count} out_bytes={} preview=\"{}\"",
                output.len(),
                crate::vmm_trace::bytes_preview(&output, 32)
            ));
        }

        output
    }

    /// Deliver the port-instantiation control sequence into the control RX
    /// queue, once: the guest driver only instantiates the console port
    /// (hvc0) and the host device port (/dev/virtio-ports/vport0p1) after
    /// these messages, so without them NO console exists at all — this is
    /// what keeps every platform's console alive in multiport mode.
    ///
    /// The sequence is delivered as soon as the driver has posted control RX
    /// buffers (its probe does that before anything else), one 8-byte
    /// message per buffer — exactly the shape its poll loop expects. It is
    /// idempotent and needs no handshake: the driver's own DEVICE_READY
    /// reply on CONTROL_TX is not waited for, so no platform has to drain
    /// the control queue to get its console.
    ///
    ///   - PORT_ADD(0) → the console port (its RX buffers are posted
    ///     by the driver itself, exactly as before)
    ///   - PORT_ADD(1) → the host device port
    ///   - PORT_ADD(2) → the export path port
    ///   - CONSOLE_PORT(0) → instantiate hvc0 on port 0
    ///   - PORT_OPEN(1) → mark the host port connected (its file
    ///     operations refuse I/O until this)
    ///   - PORT_OPEN(2) → mark the export port connected (same)
    ///   - PORT_OPEN(0) → mark the console port connected
    ///
    /// Returns true if the sequence was delivered this call (the caller must
    /// raise the device interrupt so the driver's control work runs).
    /// Deliver the port-instantiation control sequence, BATCHED: every
    /// message in its own posted control-RX head, in one pump call, with
    /// one pulse (the caller raises the line once per delivery). This used
    /// to be a five-field proof-gated state machine with a 40-retry
    /// watchdog, working around "the driver posts exactly ONE control RX
    /// buffer" — which was never measured: the HOST re-filled the same
    /// head (`last_avail_idx.wrapping_sub(1)`) and gated each message on
    /// the driver's reply. MEASURED in the driver
    /// (kernel-build/linux-7.2.10/drivers/char/virtio_console.c): it posts
    /// QUEUE_SIZE (128) control heads at probe (`fill_queue` loops until
    /// `num_free == 0`), and its control work handler LOOPS
    /// `virtqueue_get_buf` over EVERY filled head in ONE work run — so a
    /// batched sequence is processed whole, in order, with nothing to
    /// overwrite and nothing to lose: each message sits in its own
    /// descriptor until the work run consumes all of them. The delivery
    /// mask covers boot ordering only (the queue is not ready in the
    /// first pump calls); a partial batch is re-delivered next call, and
    /// once every bit lands the sequence is never touched again. No proof
    /// gating, no stall timing, no watchdog: a guest whose control work
    /// never runs delivers nothing, and its session falls back to the
    /// console device (the init script's 121 path) — the same end state
    /// the watchdog's give-up produced, without the 20 s of re-delivery.
    pub fn pump_control_sequence(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        const SEQ: [(u32, u16, u16); 7] = [
            (0, CTRL_PORT_ADD, 0),
            (1, CTRL_PORT_ADD, 0),
            (2, CTRL_PORT_ADD, 0),
            (0, CTRL_CONSOLE_PORT, 1),
            (1, CTRL_PORT_OPEN, 1),
            (2, CTRL_PORT_OPEN, 1),
            (0, CTRL_PORT_OPEN, 1),
        ];
        if self.control_seq_pending == 0 {
            return false; // delivered whole, never again
        }
        let mut delivered_any = false;
        for (i, &(id, event, value)) in SEQ.iter().enumerate() {
            let bit = 1u8 << i;
            if self.control_seq_pending & bit == 0 {
                continue;
            }
            let msg = control_message(id, event, value);
            // One message per head, via the same path the input stream
            // takes: inject_rx advances the used ring and last_avail_idx
            // per head and sets the vring interrupt itself.
            let n = self.inject_rx(memory, ram_base, CONTROL_RX, &msg);
            if n == msg.len() {
                self.control_seq_pending &= !bit;
                delivered_any = true;
                crate::vmm_trace::write_console_io(format_args!(
                    "CONTROL_SEQ msg={} of {} delivered (batched) pending={:#04x}",
                    i + 1,
                    SEQ.len(),
                    self.control_seq_pending
                ));
            }
        }
        delivered_any
    }

    /// Drain the control replies (queue CONTROL_TX) and apply them:
    /// `PORT_OPEN(1, guest_connected)` — the kernel driver's own message on
    /// every open/release of the host device port — is the session signal:
    /// the guest agent opening the port moves host stdin onto the port RX
    /// queue; closing it moves stdin back. This is the marker-free session
    /// routing: the old `<token>SESSION:port`/`SESSION:console` echoes
    /// reinvented a signal the bus already provides. Returns the drained
    /// bytes (the caller traces them / passes them on).
    pub fn process_control_tx(&mut self, memory: &mut [u8], ram_base: u64) -> Vec<u8> {
        let tx = self.process_tx(memory, ram_base, CONTROL_TX);
        if let Some(on_port) = parse_control_session(&tx) {
            self.session_input_on_port = on_port;
        }
        tx
    }

    /// Drain the export path port (queue EXPORT_TX): the whole stream is
    /// the export path — one write from the export script (`printf '%s\n'`),
    /// guest → host, no framing, no matching. Stored on the device (either
    /// drainer may be the one pumping when it arrives); `handle_export_done`
    /// takes it. The protocol always carries an absolute host path; a
    /// non-path stream is ignored.
    pub fn process_export_tx(&mut self, memory: &mut [u8], ram_base: u64) {
        let tx = self.process_tx(memory, ram_base, EXPORT_TX);
        if tx.is_empty() {
            return;
        }
        let path = String::from_utf8_lossy(&tx);
        let path = path.trim_matches(['\n', '\r', ' ', '\t']);
        if path.starts_with('/') {
            self.export_path = Some(path.to_string());
            crate::vmm_trace::write_console_io(format_args!(
                "EXPORT_PATH bytes={} path={path:?}",
                tx.len()
            ));
        }
    }

    /// Dump the raw vring state of every queue from guest RAM (wedge
    /// diagnostics): the device's `last_avail_idx` beside the rings' own
    /// indices, the full avail-ring head-id window, the full used-ring
    /// (id, len) window, and the descriptor table entries for every id the
    /// used ring references. From these three arrays the entire recent
    /// submit/complete history can be reconstructed off-guest, which is the
    /// only way to see the driver↔device desync when the guest console
    /// writer is wedged in `__send_to_port`'s completion spin.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)] // x86_64-only diagnostics
    pub fn dump_vrings(&self, memory: &[u8], ram_base: u64) {
        for q in 0..NUM_QUEUES {
            self.dump_one_vring(memory, ram_base, q);
        }
    }

    /// One queue's vring state (see [`Self::dump_vrings`]).
    #[cfg(target_os = "linux")]
    fn dump_one_vring(&self, memory: &[u8], ram_base: u64, q: usize) {
        let qs = &self.queues[q];
        if !qs.ready || qs.num == 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "VRING q={q} not-ready num={} ready={}",
                qs.num, qs.ready
            ));
            return;
        }
        let avail_idx = read_avail_idx(memory, ram_base, qs.avail_addr).unwrap_or(0);
        let used_idx = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
        crate::vmm_trace::write_console_io(format_args!(
                "VRING q={q} num={} last_avail(dev)={} avail_idx(ring)={avail_idx} used_idx(ring)={used_idx} desc={:#x} avail={:#x} used={:#x}",
                qs.num, qs.last_avail_idx, qs.desc_addr, qs.avail_addr, qs.used_addr,
            ));

        // Avail ring: the head id in each of the `num` slots.
        let mut slots = String::new();
        for s in 0..qs.num as u16 {
            let id = read_avail_ring(memory, ram_base, qs.avail_addr, s, qs.num).unwrap_or(0xffff);
            slots.push_str(&format!("{id},"));
        }
        crate::vmm_trace::write_console_io(format_args!(
            "VRING q={q} AVAIL_SLOTS(id per slot 0..num): {slots}"
        ));

        // Used ring: every (id, len) entry in the window.
        let mut entries = String::new();
        let mut used_ids: Vec<u16> = Vec::new();
        for s in 0..qs.num as u16 {
            match read_used_ring_entry(memory, ram_base, qs.used_addr, s, qs.num) {
                Some((id, len)) => {
                    entries.push_str(&format!("{id}:{len},"));
                    used_ids.push(id as u16);
                }
                None => entries.push_str("?,"),
            }
        }
        crate::vmm_trace::write_console_io(format_args!(
            "VRING q={q} USED_ENTRIES(id:len per slot 0..num): {entries}"
        ));

        // Descriptor table entries for the ids the used ring references.
        used_ids.sort_unstable();
        used_ids.dedup();
        for id in used_ids.iter() {
            match read_descriptor(memory, ram_base, qs.desc_addr, *id) {
                Some((addr, len, flags, next)) => {
                    crate::vmm_trace::write_console_io(format_args!(
                            "VRING q={q} DESC[{id}] addr={addr:#x} len={len} flags={flags:#x} next={next}"
                        ));
                }
                None => {
                    crate::vmm_trace::write_console_io(format_args!(
                        "VRING q={q} DESC[{id}] unreadable"
                    ));
                }
            }
        }
    }
    pub fn inject_rx(&mut self, memory: &mut [u8], ram_base: u64, q: usize, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        let data = &data[..data.len().min(Self::MAX_RX_CHUNK)];

        let qs = self.queues[q].clone();
        if !qs.ready || qs.num == 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "INJECT_RX_SKIP q={q} in_len={} reason=queue_not_ready ready={} num={}",
                data.len(),
                qs.ready,
                qs.num
            ));
            return 0;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, qs.avail_addr) {
            Some(idx) => idx,
            None => {
                crate::vmm_trace::write_console_io(format_args!(
                    "INJECT_RX_SKIP q={q} in_len={} reason=bad_avail_ring",
                    data.len()
                ));
                return 0;
            }
        };

        let mut last_avail = self.queues[q].last_avail_idx;

        // Overtake guard, mirroring `process_tx`: if the driver posted a full
        // ring of RX buffers past `last_avail`, the older slots now hold
        // newer heads and draining them would complete phantom descriptors
        // (BAD_RING in the guest kills the queue permanently). Only trust
        // the last `num` posts.
        let num16 = qs.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            crate::vmm_trace::write_console_io(format_args!(
                "RX_OVERTAKE q={q} last_avail={last_avail}->{} avail_idx={avail_idx} num={num16}",
                avail_idx.wrapping_sub(num16)
            ));
            last_avail = avail_idx.wrapping_sub(num16);
        }

        if last_avail == avail_idx {
            crate::vmm_trace::write_console_io(format_args!(
                "INJECT_RX_SKIP q={q} in_len={} reason=no_avail_buffers avail_idx={last_avail}",
                data.len()
            ));
            return 0;
        }

        let used_idx_start = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
        let mut used_count = 0u16;
        let mut data_offset = 0usize;
        let last_avail_start = last_avail;
        // Cap heads per call so the used ring and `last_avail_idx` stay consistent under load.
        let max_rx_heads: u16 = (qs.num as u16).clamp(1, 64);

        while data_offset < data.len() && last_avail != avail_idx {
            if used_count >= max_rx_heads {
                break;
            }
            let desc_head =
                match read_avail_ring(memory, ram_base, qs.avail_addr, last_avail, qs.num) {
                    Some(d) => d,
                    None => break,
                };

            // Walk the descriptor chain, filling writable (host→guest) buffers
            let mut idx = desc_head;
            let mut chain_written = 0u32;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, qs.desc_addr, idx)
            {
                if flags & VIRTQ_DESC_F_WRITE != 0 && data_offset < data.len() {
                    if let Some(offset) = addr.checked_sub(ram_base) {
                        let offset = offset as usize;
                        let buf_len = len as usize;
                        if offset + buf_len <= memory.len() {
                            let to_copy = (data.len() - data_offset).min(buf_len);
                            memory[offset..offset + to_copy]
                                .copy_from_slice(&data[data_offset..data_offset + to_copy]);
                            data_offset += to_copy;
                            chain_written += to_copy as u32;
                        }
                    }
                }

                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                idx = next;
            }

            // Never consume a receiveq avail entry without transferring when stdin remains — wedges
            // the Linux virtio-console driver (Attempt log / virtio spec).
            if chain_written == 0 && data_offset < data.len() {
                break;
            }

            if write_used_ring(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count),
                qs.num,
                desc_head as u32,
                chain_written,
            )
            .is_none()
            {
                break;
            }
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[q].last_avail_idx = last_avail;

        if used_count > 0 {
            let _ = write_used_idx(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
            self.work_gen += 1;
        }

        let last_avail_end = self.queues[q].last_avail_idx;
        let irq = self.interrupt_status != 0;
        if used_count > 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "RX_SET_IRQ q={q} in_len={} heads={used_count} irq_status={}",
                data.len(),
                self.interrupt_status,
            ));
        }
        crate::vmm_trace::write_console_io(format_args!(
            "INJECT_RX q={q} in_len={} consumed={} heads={} avail={} last_avail {}->{} irq={}",
            data.len(),
            data_offset,
            used_count,
            avail_idx,
            last_avail_start,
            last_avail_end,
            irq
        ));

        data_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmio_config_word_matches_le_cols_rows() {
        let mut c = VirtioConsoleDevice::new(80, 25);
        let v = c.mmio_read(REG_CONFIG_BASE, 2);
        let want = u32::from_le_bytes([80u8, 0, 25, 0]) as u64;
        assert_eq!(v, want);
    }

    #[test]
    fn mmio_config_byte_second_byte_of_cols() {
        let mut c = VirtioConsoleDevice::new(0x3412, 0);
        assert_eq!(c.mmio_read(REG_CONFIG_BASE + 1, 0), 0x34);
    }

    #[test]
    fn mmio_config_halfword_rows() {
        let mut c = VirtioConsoleDevice::new(80, 25);
        assert_eq!(c.mmio_read(REG_CONFIG_BASE + 2, 1), 25);
    }

    #[test]
    fn mmio_config_word_max_nr_ports() {
        // The multiport port count: the guest driver reads this to decide how
        // many ports (and queues) to instantiate.
        let mut c = VirtioConsoleDevice::new(80, 25);
        assert_eq!(c.mmio_read(REG_CONFIG_BASE + 4, 2), MAX_NR_PORTS as u64);
    }
}
