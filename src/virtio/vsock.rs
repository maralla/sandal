//! The userspace virtio-vsock device: per-command host channels.
//!
//! The guest's `af_vsock` (CONFIG_VIRTIO_VSOCKETS, our kernel fragment)
//! talks to this device; the device terminates every guest connection and
//! bridges it to a host channel the VMM itself owns — a TCP loopback
//! listener whose port the VMM writes to a file for the spawning agent.
//! One connection per command: concurrent foreground execution with
//! per-connection attribution (the command's bytes and its output never
//! share a stream with another command's), and no host kernel vsock
//! anywhere (the userspace-device choice, same as the netstack for
//! virtio-net).
//!
//! Direction conventions (the virtio spec's vsock device):
//!   queue 0 (RX): the guest posts receive buffers; the VMM injects into
//!                 them (the connection REQUESTs the agent's connections
//!                 synthesize, the command bytes, the resets)
//!   queue 1 (TX): the guest sends (the RESPONSEs, the command output,
//!                 the shutdowns); the VMM drains
//!   queue 2 (event): the guest posts buffers; never filled — the
//!                 transport is never reset
//!
//! Packet framing, per the guest kernel's own driver
//! (net/vmw_vsock/virtio_transport.c): the guest posts ONE 4 KiB
//! single-descriptor buffer per RX slot and DROPS any used entry whose
//! length does not cover a whole [header + payload] packet — so the
//! stream is framed PER POSTED BUFFER: each used entry carries one fresh
//! 44-byte header plus as much of the pending stream as fits, and the
//! remainder stays pending for the next buffer (exactly what vhost-vsock
//! does; the guest's af_vsock reassembles the stream).
//!
//! Flow control (the protocol's credit system): the guest's headers carry
//! its receive window (`buf_alloc`) and its consumption counter
//! (`fwd_cnt`). The window starts CLOSED (the guest admitted nothing) and
//! opens only with the guest's RESPONSE — its real per-socket budget —
//! re-opening by exactly the consumption its CREDIT_UPDATEs report. The
//! VMM injects at most the open window per connection (in-flight =
//! injected − consumed) and backlogs the rest until the guest's credit
//! updates reopen it; the VMM's own headers advertise a 4 MiB window —
//! far above any command's output — so the guest's send side never
//! blocks in practice.
//!
//! Threading: this file is the device only. The listener thread (accept
//! → [`register_connection`]) and the bridge thread (the host sockets ↔
//! this device's channels, plus ONE [`process`] pass + IRQ pulse per
//! round under the VMM's irq lock) live in `vm/linux.rs` next to the
//! net kicker — they need the VMM's IRQ plumbing, and their shutdown is
//! the run loop's.

use super::{
    read_avail_idx, read_avail_ring, read_descriptor, read_used_idx, write_used_idx,
    write_used_ring, VirtqState, REG_CONFIG_BASE, REG_DEVICE_FEATURES, REG_DEVICE_FEATURES_SEL,
    REG_DEVICE_ID, REG_DRIVER_FEATURES, REG_DRIVER_FEATURES_SEL, REG_INTERRUPT_ACK,
    REG_INTERRUPT_STATUS, REG_MAGIC_VALUE, REG_QUEUE_NOTIFY, REG_QUEUE_NUM, REG_QUEUE_NUM_MAX,
    REG_QUEUE_READY, REG_QUEUE_SEL, REG_STATUS, REG_VENDOR_ID, REG_VERSION, VIRTIO_F_VERSION_1,
    VIRTIO_MMIO_INT_VRING, VIRTIO_MMIO_MAGIC, VIRTIO_MMIO_VENDOR, VIRTIO_MMIO_VERSION,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use std::collections::{HashMap, VecDeque};

/// The host side of one connection: a TCP loopback stream (the Unix
/// stream this once also was is gone — measured broken, accept() never
/// returned pending connections; see vm/linux.rs), behind one object so
/// the device never cares which.
pub trait HostStream: std::io::Read + std::io::Write + Send {
    fn shutdown_both(&self);
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd;
}

impl HostStream for std::os::unix::net::UnixStream {
    fn shutdown_both(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        AsRawFd::as_raw_fd(self)
    }
}

impl HostStream for std::net::TcpStream {
    fn shutdown_both(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        AsRawFd::as_raw_fd(self)
    }
}

/// The device's debug sink: `SANDAL_VSOCK_DEBUG` set to an ABSOLUTE
/// path appends there (one write per line); any other value goes to
/// stderr. The file mode exists because the stderr mode rides the
/// console's pty: a busy debug stream blocks the writing thread on the
/// pty's own buffer, and the run loop wedging on it stalls the vCPU
/// (the debug session then measures its own artifact — the transport
/// looks broken while only the diagnostics were).
fn debug_print(args: std::fmt::Arguments) {
    use std::io::Write;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    static SINK: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    let sink = SINK.get_or_init(|| {
        let path = std::env::var_os("SANDAL_VSOCK_DEBUG")?;
        let bytes = path.as_encoded_bytes();
        let is_path = bytes.first() == Some(&b'/');
        if !is_path {
            return None;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });
    match sink {
        Some(file) => {
            if let Ok(mut file) = file.lock() {
                let _ = writeln!(file, "{args}");
            }
        }
        None => eprintln!("{args}"),
    }
}

/// One debug line (gated on `SANDAL_VSOCK_DEBUG`; see [`debug_print`]).
macro_rules! vdbg {
    ($($arg:tt)*) => {
        if std::env::var_os("SANDAL_VSOCK_DEBUG").is_some() {
            crate::virtio::vsock::debug_print(format_args!($($arg)*));
        }
    };
}

/// The virtio device id for vsock (include/uapi/linux/virtio_ids.h).
pub const VIRTIO_ID_VSOCK: u32 = 19;

/// `struct virtio_vsock_hdr`, packed little-endian: 44 bytes.
const VSOCK_HDR_LEN: usize = 44;

/// `enum virtio_vsock_type`: stream sockets only.
const TYPE_STREAM: u16 = 1;

/// `enum virtio_vsock_op` (include/uapi/linux/virtio_vsock.h): the
/// connect ops, the payload op (RW), and the credit ops. Every op the
/// protocol defines is handled; nothing is sent with an op the guest's
/// stack would reset the connection over.
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;

/// This side's advertised receive window (the credit the guest may have
/// in flight toward us): 4 MiB — far above any command's output, so the
/// window never closes in practice, while bounding the bridge's outbox
/// to about one window. The consumption counter reported back
/// (`fwd_cnt`, on every header plus explicit CREDIT_UPDATEs) reopens it
/// as the client drains, so the bound is a bound, not a throttle.
const HOST_WINDOW: u32 = 4 * 1024 * 1024;

/// The vsock CID convention: 2 is the host. The agent's connections are
/// synthesized as originating from the host — exactly what a vhost-based
/// deployment would present, without the host kernel.
pub const HOST_CID: u64 = 2;

/// The guest CID this VMM assigns (the device config space). The
/// convention: 1 = local, 2 = host, 3+ = guests; the agent never dials
/// it (it connects to the VMM's own listener), and the guest never
/// connects out — the value only has to be stable and non-host.
pub const GUEST_CID: u64 = 3;

/// The vsock port the channel forwards (`/bin/vsockrelay`'s listen
/// port — see initramfs/tools/x86_64/vsockrelay.rs): the VMM
/// synthesizes its REQUESTs with this dst_port, and the guest's
/// vsockrelay — started by the init script off the VMM's own config —
/// binds it and forwards each connection to the guest's TCP loopback
/// (sshd there, unmodified: OpenSSH has no AF_VSOCK listen support).
pub const RELAY_VSOCK_PORT: u32 = 22;

/// Queue indices (the guest driver's VSOCK_VQ_* order).
pub const RX_QUEUE: usize = 0;
pub const TX_QUEUE: usize = 1;
#[allow(dead_code)]
pub const EVENT_QUEUE: usize = 2;

const NUM_QUEUES: usize = 3;
const QUEUE_SIZE: u32 = 256;

/// Posted-buffer heads consumed per `process` call, across all
/// connections: the full ring — exactly what a vhost worker drains per
/// wakeup. The pass is bounded by the posted set (itself bounded by the
/// ring size) and the protocol's own credit windows bound the payload,
/// so the cap adds nothing beyond the ring's own bound; what it does buy
/// is ONE pass per event (see vm/linux.rs — never a spin): the ring
/// drains at the guest's own pace, one interrupt pulse per pass, and a
/// stream up to the ring's capacity never needs a second pass.
const MAX_HEADS_PER_SLICE: usize = QUEUE_SIZE as usize;

/// The per-connection stream chunk cap: one packet per posted buffer, and
/// never more than the guest driver's own send-side cap
/// (VIRTIO_VSOCK_MAX_PKT_BUF_SIZE, 64 KiB) even if a buffer were
/// larger.
const MAX_CHUNK: usize = 64 * 1024;

/// One guest connection, keyed by the per-connection host port.
struct Connection {
    /// The agent's host socket, parked on the device between bridge
    /// rounds.
    host: Option<Box<dyn HostStream>>,
    host_port: u32,
    /// The guest's advertised receive window and consumption counter,
    /// from the guest's own headers.
    guest_buf_alloc: u32,
    guest_fwd_cnt: u32,
    /// Total data bytes injected host→guest (the credit accounting).
    injected: u32,
    /// Total guest bytes delivered to the client (the credit this side
    /// reports back, on every header plus explicit CREDIT_UPDATEs, so
    /// the guest's send window reopens as the client drains).
    tx_reported: u32,
    /// Framed control packets, delivered whole and in order, never
    /// counted against the data window: the connection REQUEST, the
    /// CREDIT_UPDATEs that report this side's consumption, and the RST
    /// when the host side closed.
    rx_control: VecDeque<Vec<u8>>,
    /// The pending host→guest stream (the command): framed per posted
    /// buffer as the window allows, backlogged when it closes.
    rx_pending: Vec<u8>,
    /// Pending guest→host bytes (the command's output), drained from the
    /// TX queue; moved to the host socket by the bridge.
    tx_outbox: Vec<u8>,
    /// True once the guest's RESPONSE landed (the guest accepted).
    guest_accepted: bool,
    /// True once the host side closed: the RST is queued, and no
    /// further host bytes are read.
    host_closed: bool,

    /// True once either side is done: dropped at the next sweep.
    closed: bool,
}

/// The userspace virtio-vsock device. Shared behind one mutex by the run
/// loop, the listener thread, and the bridge thread (see vm/linux.rs).
pub struct VirtioVsockDevice {
    // MMIO state
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,

    /// Work generation: bumped whenever guest-visible progress lands;
    /// snapshotted when the guest reads INTERRUPT_STATUS so a later ACK
    /// cannot clear the interrupt for work that arrived after the read
    /// (the console device's guard).
    work_gen: u64,
    work_gen_at_read: u64,

    connections: HashMap<u32, Connection>,
    /// The next per-connection host port.
    next_host_port: u32,
}

impl VirtioVsockDevice {
    pub fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: std::array::from_fn(|_| VirtqState::new(QUEUE_SIZE)),
            status: 0,
            interrupt_status: 0,
            work_gen: 0,
            work_gen_at_read: 0,
            connections: HashMap::new(),
            next_host_port: 1024,
        }
    }

    /// The relay mode, for the VMM's own config plumbing (the guest
    /// init starts /bin/vsockrelay off it — see vm/mod.rs). Always
    /// true: the per-command mode is gone (the SSH channel is the only
    /// consumer), kept as a method so the config plumbing reads the
    /// same.
    pub fn relay_mode(&self) -> bool {
        true
    }

    /// Driver reset (STATUS = 0): the queues and every connection go —
    /// the guest's af_vsock is gone, so the agent's host sockets close
    /// with it (the bridge parks nothing back into a reset device).
    fn reset(&mut self) {
        self.status = 0;
        self.interrupt_status = 0;
        self.driver_features = 0;
        self.work_gen = 0;
        self.work_gen_at_read = 0;
        for queue in &mut self.queues {
            *queue = VirtqState::new(QUEUE_SIZE);
        }
        let connections = std::mem::take(&mut self.connections);
        for connection in connections.into_values() {
            if let Some(host) = connection.host {
                host.shutdown_both();
            }
        }
    }

    /// Register one accepted host connection (the listener thread): the
    /// per-connection host port and the synthesized REQUEST (from the
    /// host CID, exactly what a vhost deployment would present). The
    /// REQUEST is a control packet: delivered whole, never counted
    /// against the data window.
    ///
    /// The data window starts CLOSED (zero): the guest admits nothing
    /// until its own RESPONSE carries its real receive budget (its
    /// socket buffer), and reopens only as its consumption counter
    /// (fwd_cnt, on every packet plus explicit CREDIT_UPDATEs) advances.
    /// Pre-opening the window instead (the earlier u32::MAX bootstrap,
    /// added when a broken guest kernel never delivered the RESPONSE)
    /// lets the first pass blow straight past the guest's budget — and
    /// the guest's core DROPS everything beyond it, silently: the bytes
    /// are gone, the stream can never complete, and the whole transport
    /// stalls (MEASURED: a 900 KB command wedged its leg at ~a quarter
    /// of the stream; the protocol's own flow control is what keeps the
    /// stream intact, one window per credit round-trip).
    pub fn register_connection(&mut self, host: Box<dyn HostStream>) {
        let host_port = self.next_host_port;
        self.next_host_port = self.next_host_port.wrapping_add(1).max(1024);
        let mut control = VecDeque::new();
        control.push_back(guest_header(RELAY_VSOCK_PORT, host_port, 0, OP_REQUEST, 0));
        self.connections.insert(
            host_port,
            Connection {
                host: Some(host),
                host_port,
                // The window opens with the guest's RESPONSE (see the
                // method note) — never before the guest admitted it.
                guest_buf_alloc: 0,
                guest_fwd_cnt: 0,
                injected: 0,
                tx_reported: 0,
                rx_control: control,
                rx_pending: Vec::new(),
                tx_outbox: Vec::new(),
                guest_accepted: false,
                host_closed: false,
                closed: false,
            },
        );
    }

    /// One `process` pass: drain the TX queue (the guest's packets),
    /// then inject the pending host→guest streams into the posted RX
    /// buffers as the credit windows allow. Returns true when the guest
    /// must be interrupted (a used entry was written: the guest's driver
    /// must reap the completion or the delivered data) — the caller
    /// pulses the device IRQ line under the VMM's irq lock.
    ///
    /// ONE pass per call, by design: the caller invokes this once per
    /// event (a vCPU exit, a bridge round) and never in a loop. Whatever
    /// the pass could not deliver stays pending for the next event — the
    /// guest must act first (re-post its RX ring, advance its credit
    /// counter), and spinning here would only starve the vCPU the
    /// pending work is waiting on (the wedge the earlier inner loops
    /// produced: a closed credit window or an exhausted RX ring made
    /// every pass a no-op, and the loop never let the guest run again).
    pub fn process(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let mut progressed = false;
        if self.process_tx(memory, ram_base) {
            progressed = true;
        }
        if self.inject_pending(memory, ram_base) {
            progressed = true;
        }
        // Drop finished connections: their host sockets were closed above
        // (the bridge parks nothing back into a closed connection). A host
        // side that closed finishes closing once its RST has landed — the
        // entry goes the moment nothing is left to deliver.
        self.connections.retain(|_, connection| {
            if connection.host_closed && connection.rx_control.is_empty() {
                connection.closed = true;
            }
            if connection.closed {
                if let Some(host) = connection.host.take() {
                    host.shutdown_both();
                }
            }
            !connection.closed
        });
        if progressed {
            // Progress only: an idle pass prints nothing — the per-event
            // call sites (a vCPU exit, a bridge round) would otherwise
            // flood the log at their own rate and drown the one line that
            // matters.
            vdbg!("VDBG PROCESS: progressed={progressed}");
        }
        if progressed {
            self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
            self.work_gen += 1;
        }
        progressed
    }

    /// Drain the TX queue (queue 1): the guest's packets. The RESPONSE
    /// establishes the connection (and carries the guest's real window);
    /// the data is the command's output (into the outbox for the
    /// bridge); the SHUTDOWN/RST closes; the credit updates reopen the
    /// injection window.
    fn process_tx(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let qs = self.queues[TX_QUEUE].clone();
        if !qs.ready || qs.num == 0 {
            return false;
        }
        let Some(avail_idx) = read_avail_idx(memory, ram_base, qs.avail_addr) else {
            return false;
        };
        let mut last_avail = self.queues[TX_QUEUE].last_avail_idx;
        // Overtake guard (the console device's): only the last `num`
        // submissions have trustworthy slots — draining an older window
        // completes a phantom head and the guest's driver kills the queue.
        let num16 = qs.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            last_avail = avail_idx.wrapping_sub(num16);
        }
        let used_idx_start = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
        let mut used_count = 0usize;
        let mut packets: Vec<Vec<u8>> = Vec::new();
        if last_avail == avail_idx {
            return false;
        }
        while last_avail != avail_idx && used_count < MAX_HEADS_PER_SLICE {
            let Some(desc_head) =
                read_avail_ring(memory, ram_base, qs.avail_addr, last_avail, qs.num)
            else {
                break;
            };
            // Walk the chain and assemble the whole head: one packet per
            // head (the guest's send buffers chain up to 64 KiB), so the
            // used entry describes the full chain and nothing is split.
            let mut packet: Vec<u8> = Vec::new();
            let mut idx = desc_head;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, qs.desc_addr, idx)
            {
                // TX descriptors are device-readable (no WRITE flag).
                if flags & VIRTQ_DESC_F_WRITE == 0 {
                    if let Some(offset) = addr.checked_sub(ram_base) {
                        let (offset, len) = (offset as usize, len as usize);
                        if offset + len <= memory.len() {
                            packet.extend_from_slice(&memory[offset..offset + len]);
                        }
                    }
                }
                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                idx = next;
            }
            packets.push(packet);
            let _ = write_used_ring(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count as u16),
                qs.num,
                desc_head as u32,
                0,
            );
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }
        self.queues[TX_QUEUE].last_avail_idx = last_avail;
        if used_count > 0 {
            let _ = write_used_idx(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count as u16),
            );
        }
        let mut progressed = false;
        for packet in packets {
            {
                vdbg!(
                    "VDBG TX-DRAIN: op={} len={} -> handle",
                    parse_header(&packet).map(|h| h.op).unwrap_or(0),
                    packet.len()
                );
            }
            if self.handle_tx_packet(&packet) {
                progressed = true;
            }
        }
        progressed
    }

    /// Handle one guest packet (a vsock header + optional payload).
    fn handle_tx_packet(&mut self, packet: &[u8]) -> bool {
        let Some(header) = parse_header(packet) else {
            return false;
        };
        if header.vtype != TYPE_STREAM {
            return false;
        }
        // The connection this packet belongs to: the guest's vsockrelay
        // answers to the host port the connection was synthesized from.
        let Some(connection) = self
            .connections
            .values_mut()
            .find(|connection| connection.host_port == header.dst_port)
        else {
            return false;
        };
        // The payload: exactly the header's len field, if it all arrived.
        let payload_end = VSOCK_HDR_LEN
            .saturating_add(header.len as usize)
            .min(packet.len());
        let payload = &packet[VSOCK_HDR_LEN.min(packet.len())..payload_end];
        {
            vdbg!(
                "VDBG TX-HANDLE: op={} dst_port={} len={}",
                header.op,
                header.dst_port,
                header.len
            );
        }
        match header.op {
            OP_RESPONSE => {
                // The guest accepted: the connection is live, and the
                // guest's first header carries its real window.
                connection.guest_accepted = true;
                connection.guest_buf_alloc = header.buf_alloc;
                connection.guest_fwd_cnt = header.fwd_cnt;
                true
            }
            OP_CREDIT_UPDATE => {
                // The guest consumed `fwd_cnt` bytes of this side's data:
                // reopen this side's send window.
                connection.guest_fwd_cnt = header.fwd_cnt;
                true
            }
            OP_CREDIT_REQUEST => {
                // The guest asked for this side's credit: answer with a
                // CREDIT_UPDATE carrying the current consumption (the
                // protocol's keep-alive for its send window), so its
                // output never stalls on a stale counter.
                connection.guest_fwd_cnt = header.fwd_cnt;
                connection.guest_buf_alloc = header.buf_alloc;
                let update = guest_header(
                    RELAY_VSOCK_PORT,
                    connection.host_port,
                    0,
                    OP_CREDIT_UPDATE,
                    connection.tx_reported,
                );
                connection.rx_control.push_back(update);
                true
            }
            OP_SHUTDOWN | OP_RST => {
                connection.closed = true;
                if let Some(host) = connection.host.take() {
                    host.shutdown_both();
                }
                true
            }
            OP_RW => {
                // The command's output. The header also carries the
                // guest's window bookkeeping (its consumption of this
                // side's data, and its current receive window).
                connection.guest_fwd_cnt = header.fwd_cnt;
                connection.guest_buf_alloc = header.buf_alloc;
                if !payload.is_empty() && !connection.closed {
                    connection.tx_outbox.extend_from_slice(payload);
                }
                !payload.is_empty()
            }
            _ => false,
        }
    }

    /// Inject the pending host→guest streams (queue 0), per posted
    /// buffer: control packets whole, then the stream chunked at
    /// [buffer capacity − header] and the open credit window. The
    /// remainder stays pending; a closed window consumes no buffer.
    fn inject_pending(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let qs = self.queues[RX_QUEUE].clone();
        if !qs.ready || qs.num == 0 {
            return false;
        }
        let Some(avail_idx) = read_avail_idx(memory, ram_base, qs.avail_addr) else {
            return false;
        };
        let mut last_avail = self.queues[RX_QUEUE].last_avail_idx;
        // Overtake guard (the console device's).
        let num16 = qs.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            last_avail = avail_idx.wrapping_sub(num16);
        }
        if last_avail == avail_idx {
            return false;
        }
        let used_idx_start = read_used_idx(memory, ram_base, qs.used_addr).unwrap_or(0);
        let mut used_count = 0usize;
        let mut heads_budget = MAX_HEADS_PER_SLICE;
        let mut progressed = false;
        // The per-connection loop: each connection gets whole packets
        // until its window closes or the head budget runs out.
        let connections: Vec<u32> = self.connections.keys().copied().collect();
        for host_port in connections {
            while heads_budget > 0 && last_avail != avail_idx {
                let Some(connection) = self.connections.get_mut(&host_port) else {
                    break;
                };
                if connection.closed {
                    break;
                }
                let Some(desc_head) =
                    read_avail_ring(memory, ram_base, qs.avail_addr, last_avail, qs.num)
                else {
                    break;
                };
                // Measure this head's writable capacity (the mapped
                // (offset, len) pairs of its chain).
                let mut capacity = 0usize;
                let mut buffers: Vec<(usize, usize)> = Vec::new();
                let mut idx = desc_head;
                while let Some((addr, len, flags, next)) =
                    read_descriptor(memory, ram_base, qs.desc_addr, idx)
                {
                    if flags & VIRTQ_DESC_F_WRITE != 0 {
                        if let Some(offset) = addr.checked_sub(ram_base) {
                            let (offset, len) = (offset as usize, len as usize);
                            if offset + len <= memory.len() {
                                capacity += len;
                                buffers.push((offset, len));
                            }
                        }
                    }
                    if flags & VIRTQ_DESC_F_NEXT == 0 {
                        break;
                    }
                    idx = next;
                }
                {
                    let in_flight = connection.injected.wrapping_sub(connection.guest_fwd_cnt);
                    let _ = in_flight;
                }
                // Control first, whole: never window-counted (no payload).
                let mut wrote = 0usize;
                if let Some(packet) = connection.rx_control.front() {
                    {
                        vdbg!(
                            "VDBG INJECT-CTRL: op={} len={} cap={} -> {}",
                            parse_header(packet).map(|h| h.op).unwrap_or(0),
                            packet.len(),
                            capacity,
                            if packet.len() <= capacity {
                                "DELIVER"
                            } else {
                                "SKIP"
                            }
                        );
                    }
                    if packet.len() <= capacity {
                        copy_across(memory, &buffers, packet);
                        wrote = packet.len();
                        connection.rx_control.pop_front();
                    }
                }
                // Then the stream, as the window allows.
                if wrote == 0 && !connection.rx_pending.is_empty() {
                    // The open window: what the guest advertised minus
                    // what is in flight (injected but unconsumed).
                    let in_flight = connection.injected.wrapping_sub(connection.guest_fwd_cnt);
                    let window = connection.guest_buf_alloc.saturating_sub(in_flight) as usize;
                    if window == 0 {
                        // Credit closed: consume no buffer — the guest's
                        // next credit update reopens it.
                        break;
                    }
                    let chunk = connection
                        .rx_pending
                        .len()
                        .min(capacity.saturating_sub(VSOCK_HDR_LEN))
                        .min(window)
                        .min(MAX_CHUNK);
                    {
                        vdbg!(
                            "VDBG INJECT-DATA: pending={} cap={} window={} -> chunk={}",
                            connection.rx_pending.len(),
                            capacity,
                            window,
                            chunk
                        );
                    }
                    if chunk == 0 {
                        // Nothing fits (the window is closed or the buffer
                        // is smaller than a header). NEVER consume the
                        // buffer: completing it with a zero length makes
                        // the guest drop and re-post it, and doing that
                        // every round burns the ring dry — the inject then
                        // stalls with nothing ever delivered. Leave it
                        // posted; the next round retries.
                        break;
                    }
                    let packet = guest_header(
                        RELAY_VSOCK_PORT,
                        connection.host_port,
                        chunk as u32,
                        OP_RW,
                        connection.tx_reported,
                    );
                    let mut framed = packet;
                    framed.extend_from_slice(&connection.rx_pending[..chunk]);
                    copy_across(memory, &buffers, &framed);
                    connection.rx_pending.drain(..chunk);
                    connection.injected = connection.injected.wrapping_add(chunk as u32);
                    wrote = framed.len();
                }
                if wrote == 0 {
                    // Nothing fit: leave the buffer posted; the next
                    // round (or a fresh post) retries.
                    break;
                }
                let _ = write_used_ring(
                    memory,
                    ram_base,
                    qs.used_addr,
                    used_idx_start.wrapping_add(used_count as u16),
                    qs.num,
                    desc_head as u32,
                    wrote as u32,
                );
                used_count += 1;
                heads_budget -= 1;
                last_avail = last_avail.wrapping_add(1);
                progressed = true;
            }
        }
        if used_count > 0 {
            self.queues[RX_QUEUE].last_avail_idx = last_avail;
            let _ = write_used_idx(
                memory,
                ram_base,
                qs.used_addr,
                used_idx_start.wrapping_add(used_count as u16),
            );
        }
        progressed
    }

    /// Land bytes read from one connection's host socket: the command.
    /// Called by the bridge thread.
    pub fn land_host_bytes(&mut self, host_port: u32, bytes: &[u8]) {
        if let Some(connection) = self.connections.get_mut(&host_port) {
            if !connection.host_closed {
                connection.rx_pending.extend_from_slice(bytes);
            }
        }
    }

    /// Mark one connection's host side closed: queue the RST (the guest's
    /// socket is reset) and stop reading. The connection is dropped once
    /// the RST has landed (see `process`). Called by the bridge thread.
    pub fn mark_host_closed(&mut self, host_port: u32) {
        if let Some(connection) = self.connections.get_mut(&host_port) {
            if !connection.host_closed {
                connection.host_closed = true;
                let rst = guest_header(
                    RELAY_VSOCK_PORT,
                    connection.host_port,
                    0,
                    OP_RST,
                    connection.tx_reported,
                );
                connection.rx_control.push_back(rst);
            }
        }
    }

    /// Report this round's delivery of a connection's output to the
    /// client: advance the consumption counter and queue a
    /// CREDIT_UPDATE carrying it, so the guest's send window reopens as
    /// the client drains (the window bounds the bridge's outbox; the
    /// report keeps the bound from becoming a throttle). Called by the
    /// bridge thread, under the same lock as [`process`].
    pub fn report_tx_delivered(&mut self, host_port: u32, delivered: usize) {
        if delivered == 0 {
            return;
        }
        if let Some(connection) = self.connections.get_mut(&host_port) {
            connection.tx_reported = connection.tx_reported.wrapping_add(delivered as u32);
            let update = guest_header(
                RELAY_VSOCK_PORT,
                connection.host_port,
                0,
                OP_CREDIT_UPDATE,
                connection.tx_reported,
            );
            connection.rx_control.push_back(update);
        }
    }

    /// The bridge thread's exchange: park the host sockets back (with any
    /// outbox bytes that did not land), land the bytes read from them,
    /// mark the closed ones, and report this round's deliveries (each
    /// report queues a CREDIT_UPDATE carrying the new consumption).
    /// Called under the VMM's irq lock, immediately before [`process`].
    pub fn bridge_exchange(
        &mut self,
        work: Vec<(u32, Box<dyn HostStream>, Vec<u8>)>,
        read: Vec<(u32, Vec<u8>)>,
        closed: Vec<u32>,
        delivered: Vec<(u32, usize)>,
    ) {
        for (host_port, host, leftover) in work {
            if let Some(connection) = self.connections.get_mut(&host_port) {
                connection.host = Some(host);
                if !leftover.is_empty() {
                    connection.tx_outbox.extend_from_slice(&leftover);
                }
            } else {
                host.shutdown_both();
            }
        }
        for (host_port, bytes) in read {
            self.land_host_bytes(host_port, &bytes);
        }
        for host_port in closed {
            self.mark_host_closed(host_port);
        }
        for (host_port, delivered) in delivered {
            self.report_tx_delivered(host_port, delivered);
        }
    }

    /// Take the bridge thread's work: every live connection's host socket
    /// plus its outbox (the command output). The sockets are parked on
    /// the device between rounds.
    pub fn take_bridge_work(&mut self) -> Vec<(u32, Box<dyn HostStream>, Vec<u8>)> {
        let mut work = Vec::new();
        for connection in self.connections.values_mut() {
            if connection.closed {
                continue;
            }
            if let Some(host) = connection.host.take() {
                work.push((
                    connection.host_port,
                    host,
                    std::mem::take(&mut connection.tx_outbox),
                ));
            }
        }
        work
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    /// `sas` is the ARM64 Data Abort ISS access size (0 byte … 3
    /// doubleword), required for config-space loads of any width.
    pub fn mmio_read(&mut self, offset: u64, sas: u8) -> u64 {
        {
            vdbg!("VDBG MMIO-READ: offset={offset:#x} sas={sas}");
        }
        // The config space: the guest CID (u64 LE), byte-granular so any
        // load width works (the driver reads it as one u64). One source
        // of truth: the same constant the packet headers carry (see
        // [`guest_header`]), so the two can never diverge.
        if (REG_CONFIG_BASE..REG_CONFIG_BASE + 8).contains(&offset) {
            let cid = GUEST_CID.to_le_bytes();
            let start = (offset - REG_CONFIG_BASE) as usize;
            let size = (1usize << sas.min(3)).min(8 - start);
            let mut value = 0u64;
            for (i, byte) in cid[start..start + size].iter().enumerate() {
                value |= (*byte as u64) << (8 * i);
            }
            return value;
        }
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC as u64,
            REG_VERSION => VIRTIO_MMIO_VERSION as u64,
            REG_DEVICE_ID => VIRTIO_ID_VSOCK as u64,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR as u64,
            // Only VIRTIO_F_VERSION_1 (bit 32): the modern transport the
            // guest's virtio-vsock driver requires; vsock has no device
            // feature bits of its own.
            REG_DEVICE_FEATURES => {
                if self.device_features_sel == 0 {
                    0
                } else {
                    (VIRTIO_F_VERSION_1 >> 32) & 0xFFFFFFFF
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
            _ => 0,
        }
    }

    /// Handle an MMIO write at `offset` within the device's MMIO region.
    /// Returns Some(queue) if QueueNotify was written (the caller drives
    /// [`process`] on its own schedule — the run loop, after the exit).
    pub fn mmio_write(&mut self, offset: u64, value: u32) -> Option<u32> {
        {
            vdbg!("VDBG MMIO-WRITE: offset={offset:#x} value={value:#x}");
        }
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
                    self.queues[self.queue_sel as usize].ready = value != 0;
                }
            }
            REG_QUEUE_NOTIFY => {
                return Some(value);
            }
            REG_INTERRUPT_ACK => {
                self.interrupt_status &= !value;
                // Work that arrived after the guest last read
                // INTERRUPT_STATUS must survive the ACK (the console
                // device's guard): the interrupt for it was already
                // pulsed, and the guest's driver re-checks the queues
                // when it fires — clearing the bit here must not lower
                // the line for work the guest has not reaped.
                if self.work_gen > self.work_gen_at_read {
                    self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
                }
            }
            REG_STATUS => {
                self.status = value;
                if value == 0 {
                    self.reset();
                }
            }
            super::REG_QUEUE_DESC_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.desc_addr = (queue.desc_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            super::REG_QUEUE_DESC_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.desc_addr = (queue.desc_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            super::REG_QUEUE_DRIVER_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.avail_addr = (queue.avail_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            super::REG_QUEUE_DRIVER_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.avail_addr = (queue.avail_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            super::REG_QUEUE_DEVICE_LOW if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.used_addr = (queue.used_addr & 0xFFFFFFFF00000000) | value as u64;
            }
            super::REG_QUEUE_DEVICE_HIGH if (self.queue_sel as usize) < NUM_QUEUES => {
                let queue = &mut self.queues[self.queue_sel as usize];
                queue.used_addr = (queue.used_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
            }
            _ => {}
        }
        None
    }
}

/// Copy `data` across the mapped buffer list (the per-buffer framing:
/// each buffer receives a contiguous run of the pending stream).
fn copy_across(memory: &mut [u8], buffers: &[(usize, usize)], data: &[u8]) {
    let mut offset = 0usize;
    for (buffer_offset, buffer_len) in buffers {
        if offset >= data.len() {
            break;
        }
        let to_copy = (data.len() - offset).min(*buffer_len);
        memory[*buffer_offset..*buffer_offset + to_copy]
            .copy_from_slice(&data[offset..offset + to_copy]);
        offset += to_copy;
    }
}

/// Build one `struct virtio_vsock_hdr` (packed little-endian).
#[allow(clippy::too_many_arguments)]
fn build_header(
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    vtype: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(VSOCK_HDR_LEN);
    out.extend_from_slice(&src_cid.to_le_bytes());
    out.extend_from_slice(&dst_cid.to_le_bytes());
    out.extend_from_slice(&src_port.to_le_bytes());
    out.extend_from_slice(&dst_port.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&vtype.to_le_bytes());
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&buf_alloc.to_le_bytes());
    out.extend_from_slice(&fwd_cnt.to_le_bytes());
    out
}

/// One header for a packet this VMM sends to the guest. The credit
/// fields are filled here and nowhere else: this side's window
/// ([`HOST_WINDOW`]) and this side's consumption (`fwd_cnt` — the total
/// delivered to the client), so every packet — control or data — is also
/// a credit update, exactly as the protocol intends (the peer's send
/// window tracks these fields on every packet it receives).
fn guest_header(dst_port: u32, host_port: u32, len: u32, op: u16, fwd_cnt: u32) -> Vec<u8> {
    build_header(
        HOST_CID,
        GUEST_CID,
        host_port,
        dst_port,
        len,
        TYPE_STREAM,
        op,
        0,
        HOST_WINDOW,
        fwd_cnt,
    )
}

/// One parsed `struct virtio_vsock_hdr`.
struct ParsedHeader {
    #[allow(dead_code)]
    src_cid: u64,
    #[allow(dead_code)]
    dst_cid: u64,
    #[allow(dead_code)]
    src_port: u32,
    dst_port: u32,
    #[allow(dead_code)]
    len: u32,
    vtype: u16,
    op: u16,
    #[allow(dead_code)]
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

/// Parse one header from `data[..44]`.
fn parse_header(data: &[u8]) -> Option<ParsedHeader> {
    if data.len() < VSOCK_HDR_LEN {
        return None;
    }
    let rd_u16 = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
    let rd_u32 =
        |off: usize| u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    let rd_u64 = |off: usize| {
        u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ])
    };
    Some(ParsedHeader {
        src_cid: rd_u64(0),
        dst_cid: rd_u64(8),
        src_port: rd_u32(16),
        dst_port: rd_u32(20),
        len: rd_u32(24),
        vtype: rd_u16(28),
        op: rd_u16(30),
        flags: rd_u32(32),
        buf_alloc: rd_u32(36),
        fwd_cnt: rd_u32(40),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake guest: 16 MiB of RAM at a nonzero base, with the vring
    /// structures and the posted buffers placed inside it. The test
    /// drives the device through its real MMIO surface and its real
    /// `process`, exactly as the VMM does.
    struct FakeGuest {
        ram: Vec<u8>,
        ram_base: u64,
        desc: u64,
        avail: u64,
        used: u64,
        buffer: u64,
        buffer_len: usize,
    }

    impl FakeGuest {
        fn new() -> Self {
            let ram_base = 0x1000_0000u64;
            let ram = vec![0u8; 16 << 20];
            Self {
                ram,
                ram_base,
                desc: ram_base + 0x1000,
                avail: ram_base + 0x2000,
                used: ram_base + 0x3000,
                buffer: ram_base + 0x4000,
                buffer_len: 4096,
            }
        }

        fn offset(&self, addr: u64) -> usize {
            (addr - self.ram_base) as usize
        }

        /// Set up one queue through the device's real MMIO writes.
        fn setup_queue(&self, device: &mut VirtioVsockDevice, queue: usize) {
            use super::super::{
                REG_QUEUE_DESC_HIGH, REG_QUEUE_DESC_LOW, REG_QUEUE_DEVICE_HIGH,
                REG_QUEUE_DEVICE_LOW, REG_QUEUE_DRIVER_HIGH, REG_QUEUE_DRIVER_LOW, REG_QUEUE_NUM,
                REG_QUEUE_READY, REG_QUEUE_SEL,
            };
            let (desc, avail, used) = match queue {
                RX_QUEUE => (self.desc, self.avail, self.used),
                TX_QUEUE => (self.desc + 0x100, self.avail + 0x100, self.used + 0x100),
                _ => return,
            };
            device.mmio_write(REG_QUEUE_SEL, queue as u32);
            device.mmio_write(REG_QUEUE_NUM, QUEUE_SIZE);
            device.mmio_write(REG_QUEUE_DESC_LOW, desc as u32);
            device.mmio_write(REG_QUEUE_DESC_HIGH, (desc >> 32) as u32);
            device.mmio_write(REG_QUEUE_DRIVER_LOW, avail as u32);
            device.mmio_write(REG_QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
            device.mmio_write(REG_QUEUE_DEVICE_LOW, used as u32);
            device.mmio_write(REG_QUEUE_DEVICE_HIGH, (used >> 32) as u32);
            device.mmio_write(REG_QUEUE_READY, 1);
        }

        /// Post the fake buffer once more, exactly as the guest driver
        /// does: the avail-ring index advances one past the device's own
        /// consumption counter, so exactly one new head appears per post.
        fn post_rx(&mut self, device: &VirtioVsockDevice) {
            let idx = device.queues[RX_QUEUE].last_avail_idx.wrapping_add(1);
            let desc_off = self.offset(self.desc);
            // Descriptor 0: addr = buffer, len = buffer_len, flags =
            // WRITE, no next (the guest driver's own single-descriptor
            // shape).
            self.ram[desc_off..desc_off + 8].copy_from_slice(&self.buffer.to_le_bytes());
            self.ram[desc_off + 8..desc_off + 12]
                .copy_from_slice(&(self.buffer_len as u32).to_le_bytes());
            self.ram[desc_off + 12..desc_off + 14]
                .copy_from_slice(&VIRTQ_DESC_F_WRITE.to_le_bytes());
            self.ram[desc_off + 14..desc_off + 16].copy_from_slice(&0u16.to_le_bytes());
            // Avail ring: flags = 0, idx = idx, ring[idx-1] = descriptor 0.
            let avail_off = self.offset(self.avail);
            self.ram[avail_off..avail_off + 2].copy_from_slice(&0u16.to_le_bytes());
            self.ram[avail_off + 2..avail_off + 4].copy_from_slice(&idx.to_le_bytes());
            self.ram[avail_off + 4..avail_off + 6].copy_from_slice(&0u16.to_le_bytes());
        }

        /// Post one guest send packet: a single READ descriptor pointing
        /// at the packet bytes, with the avail ring advanced one past the
        /// device's own TX consumption counter.
        fn post_tx(&mut self, device: &VirtioVsockDevice, packet: &[u8]) {
            let idx = device.queues[TX_QUEUE].last_avail_idx.wrapping_add(1);
            let desc = self.desc + 0x100;
            let desc_off = self.offset(desc);
            self.ram[desc_off..desc_off + 8].copy_from_slice(&self.buffer.to_le_bytes());
            self.ram[desc_off + 8..desc_off + 12]
                .copy_from_slice(&(packet.len() as u32).to_le_bytes());
            self.ram[desc_off + 12..desc_off + 14].copy_from_slice(&0u16.to_le_bytes());
            self.ram[desc_off + 14..desc_off + 16].copy_from_slice(&0u16.to_le_bytes());
            let buffer_off = self.offset(self.buffer);
            self.ram[buffer_off..buffer_off + packet.len()].copy_from_slice(packet);
            let avail = self.avail + 0x100;
            let avail_off = self.offset(avail);
            self.ram[avail_off..avail_off + 2].copy_from_slice(&0u16.to_le_bytes());
            self.ram[avail_off + 2..avail_off + 4].copy_from_slice(&idx.to_le_bytes());
            self.ram[avail_off + 4..avail_off + 6].copy_from_slice(&0u16.to_le_bytes());
        }

        /// The used-ring entry `idx` (descriptor id, written length).
        fn used_entry(&self, queue: usize, idx: usize) -> (u32, u32) {
            let used = match queue {
                RX_QUEUE => self.used,
                _ => self.used + 0x100,
            };
            let off = self.offset(used) + 4 + idx * 8;
            let mut id = [0u8; 4];
            let mut len = [0u8; 4];
            id.copy_from_slice(&self.ram[off..off + 4]);
            len.copy_from_slice(&self.ram[off + 4..off + 8]);
            (u32::from_le_bytes(id), u32::from_le_bytes(len))
        }

        fn used_idx(&self, queue: usize) -> usize {
            let used = match queue {
                RX_QUEUE => self.used,
                _ => self.used + 0x100,
            };
            let off = self.offset(used) + 2;
            u16::from_le_bytes([self.ram[off], self.ram[off + 1]]) as usize
        }
    }

    #[test]
    fn header_round_trips() {
        let header = build_header(
            HOST_CID,
            0x1122_3344_5566_7788,
            1024,
            RELAY_VSOCK_PORT,
            4096,
            TYPE_STREAM,
            OP_REQUEST,
            0xdead_beef,
            0xfeed_face,
            0x1234_5678,
        );
        assert_eq!(header.len(), VSOCK_HDR_LEN);
        let parsed = parse_header(&header).unwrap();
        assert_eq!(parsed.src_cid, HOST_CID);
        assert_eq!(parsed.dst_cid, 0x1122_3344_5566_7788);
        assert_eq!(parsed.src_port, 1024);
        assert_eq!(parsed.dst_port, RELAY_VSOCK_PORT);
        assert_eq!(parsed.len, 4096);
        assert_eq!(parsed.vtype, TYPE_STREAM);
        assert_eq!(parsed.op, OP_REQUEST);
        assert_eq!(parsed.flags, 0xdead_beef);
        assert_eq!(parsed.buf_alloc, 0xfeed_face);
        assert_eq!(parsed.fwd_cnt, 0x1234_5678);
        // And a short buffer does not parse.
        assert!(parse_header(&header[..43]).is_none());
    }

    /// The whole connection lifecycle through the real surfaces: the
    /// REQUEST lands in a posted buffer (one used entry, whole packet),
    /// the window starts CLOSED (the guest admitted nothing yet — the
    /// pre-open would let a pass blow past the guest's budget and the
    /// guest would DROP the excess, silently), the guest's RESPONSE
    /// then opens it to the guest's real window, the command stream is
    /// chunked per posted buffer and never split mid-packet, the output
    /// lands in the outbox, and the host close queues the RST.
    #[test]
    fn connection_lifecycle() {
        let mut device = VirtioVsockDevice::new();
        let mut guest = FakeGuest::new();
        guest.setup_queue(&mut device, RX_QUEUE);
        guest.setup_queue(&mut device, TX_QUEUE);
        guest.setup_queue(&mut device, EVENT_QUEUE);

        // ── Phase 1: the REQUEST (a control packet) ──────────────────
        // The host socket is a dummy: the queue machinery never touches
        // it (the bridge paths are the bridge's own, tested below only
        // through the device's public methods).
        device.register_connection(dummy_socket());
        let host_port = *device.connections.keys().next().unwrap();
        guest.post_rx(&device);
        let progressed = device.process(&mut guest.ram, guest.ram_base);
        assert!(progressed);
        assert_eq!(
            device.interrupt_status & VIRTIO_MMIO_INT_VRING,
            VIRTIO_MMIO_INT_VRING
        );
        // The REQUEST landed whole: one used entry of exactly 44 bytes.
        assert_eq!(guest.used_entry(RX_QUEUE, 0), (0, VSOCK_HDR_LEN as u32));
        assert_eq!(guest.used_idx(RX_QUEUE), 1);
        let landed = &guest.ram[guest.offset(guest.buffer)..];
        let landed_header = parse_header(&landed[..VSOCK_HDR_LEN]).unwrap();
        assert_eq!(landed_header.op, OP_REQUEST);
        assert_eq!(landed_header.src_cid, HOST_CID);
        assert_eq!(landed_header.dst_cid, GUEST_CID);
        assert_eq!(landed_header.dst_port, RELAY_VSOCK_PORT);
        assert_eq!(landed_header.src_port, host_port);
        // The control packet is consumed: nothing else pending.
        // The connection is NOT accepted and the window is CLOSED: the
        // guest admitted nothing yet (see register_connection — the
        // pre-open that used to live here dropped whole streams on the
        // guest's floor).
        let connection = device.connections.get(&host_port).unwrap();
        assert!(connection.rx_control.is_empty());
        assert!(!connection.guest_accepted);
        assert_eq!(connection.guest_buf_alloc, 0);

        // ── Phase 2: the guest's RESPONSE opens the window ────────
        // No RX re-post this round: nothing is pending host→guest, so the
        // inject path must consume nothing (the window opens for the NEXT
        // round, when there is something to deliver).
        let response = build_header(
            GUEST_CID,
            HOST_CID,
            RELAY_VSOCK_PORT,
            host_port,
            0,
            TYPE_STREAM,
            OP_RESPONSE,
            0,
            1024 * 1024,
            0,
        );
        guest.post_tx(&device, &response);
        assert!(device.process(&mut guest.ram, guest.ram_base));
        let connection = device.connections.get(&host_port).unwrap();
        assert!(connection.guest_accepted);
        assert_eq!(connection.guest_buf_alloc, 1024 * 1024);
        // Nothing was consumed on the RX side: the used ring did not move.
        assert_eq!(guest.used_idx(RX_QUEUE), 1);
        assert_eq!(device.queues[RX_QUEUE].last_avail_idx, 1);

        // ── Phase 3: the command stream, chunked per posted buffer ───
        // A stream larger than one posted buffer: this `process` delivers
        // exactly one whole packet (header + what fits) and keeps the rest
        // pending — never a split packet (the guest's driver would drop
        // a short one, so nothing may ever be split).
        let mut stream = Vec::new();
        while stream.len() < 32768 {
            stream.extend_from_slice(b"command stream ");
        }
        stream.truncate(32768);
        device.land_host_bytes(host_port, &stream);
        guest.post_rx(&device);
        assert!(device.process(&mut guest.ram, guest.ram_base));
        let (id, written) = guest.used_entry(RX_QUEUE, 1);
        assert_eq!(id, 0);
        // Exactly one whole packet: header + as much as fit.
        let connection = device.connections.get(&host_port).unwrap();
        let delivered = guest.buffer_len - VSOCK_HDR_LEN;
        assert_eq!(written as usize, VSOCK_HDR_LEN + delivered);
        assert_eq!(
            connection.rx_pending.len(),
            32768 - delivered,
            "the remainder stays pending, never split mid-packet"
        );
        // The landed chunk is framed with its own header (len = the
        // chunk) — the guest's driver accepts exactly this shape.
        let landed = &guest.ram[guest.offset(guest.buffer)..];
        let landed_header = parse_header(&landed[..VSOCK_HDR_LEN]).unwrap();
        assert_eq!(landed_header.len as usize, delivered);
        assert_eq!(landed_header.op, OP_RW);
        // And the injected counter tracks it (the credit accounting).
        assert_eq!(connection.injected as usize, delivered);

        // ── Phase 4: the output lands in the outbox ──────────────────
        // The payload is exactly the header's len field (8 bytes): the
        // device takes no more and no less.
        let output = build_header(
            GUEST_CID,
            HOST_CID,
            RELAY_VSOCK_PORT,
            host_port,
            8,
            TYPE_STREAM,
            OP_RW,
            0,
            0,
            0,
        );
        let mut output_packet = output;
        output_packet.extend_from_slice(b"output!\n");
        guest.post_tx(&device, &output_packet);
        assert!(device.process(&mut guest.ram, guest.ram_base));
        let connection = device.connections.get(&host_port).unwrap();
        assert_eq!(connection.tx_outbox, b"output!\n");
        // The TX side consumed its head: the completion moved.
        assert_eq!(device.queues[TX_QUEUE].last_avail_idx, 2);

        // ── Phase 5: the host close queues the RST ───────────────────
        device.mark_host_closed(host_port);
        guest.post_rx(&device);
        assert!(device.process(&mut guest.ram, guest.ram_base));
        let landed = &guest.ram[guest.offset(guest.buffer)..];
        let landed_header = parse_header(&landed[..VSOCK_HDR_LEN]).unwrap();
        assert_eq!(landed_header.op, OP_RST);
        // The RST landed whole: one used entry of exactly 44 bytes.
        assert_eq!(guest.used_entry(RX_QUEUE, 2), (0, VSOCK_HDR_LEN as u32));
        assert_eq!(guest.used_idx(RX_QUEUE), 3);
        // And the connection is gone: the host side closed, its RST was
        // delivered, and the sweep dropped it.
        assert!(!device.connections.contains_key(&host_port));
    }

    /// A dummy host socket for the lifecycle test: the queue machinery
    /// never reads or writes it (the bridge paths are exercised only
    /// through the device's public methods above).
    fn dummy_socket() -> Box<dyn HostStream> {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        Box::new(a)
    }
}
