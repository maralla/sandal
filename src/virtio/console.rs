/// Virtio-console device implementation.
///
/// Provides a paravirtualized serial console (hvc0) to the guest via the
/// virtio MMIO transport.  Replaces the traditional MMIO UART for interactive
/// terminal I/O, batching characters through virtqueues instead of trapping
/// per-byte.
///
/// Two queues:
///   - Queue 0 (receiveq / RX): host → guest (stdin keypresses)
///   - Queue 1 (transmitq / TX): guest → host (stdout output)
use std::mem;

use super::*;

// Virtio device ID for console (virtio spec §5.3)
const VIRTIO_ID_CONSOLE: u32 = 3;

const QUEUE_SIZE: u32 = 128;
const NUM_QUEUES: usize = 2;

const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;

/// Feature bit: console size (cols, rows) is available in config space.
const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;

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

    /// Host stdin (and init blob) not yet copied into the guest receiveq — survives `read()` when
    /// the guest has not posted RX buffers yet.
    pub rx_backlog: Vec<u8>,

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

    /// The advertised terminal geometry (cols, rows). Used by the x86_64
    /// init config (the guest tty needs a real window size).
    #[cfg(target_arch = "x86_64")]
    pub fn terminal_size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    pub fn new(cols: u16, rows: u16) -> Self {
        VirtioConsoleDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [VirtqState::new(QUEUE_SIZE), VirtqState::new(QUEUE_SIZE)],
            status: 0,
            interrupt_status: 0,
            cols,
            rows,
            rx_backlog: Vec::new(),
            work_gen: 0,
            work_gen_at_read: 0,
        }
    }

    fn virtio_console_config_bytes(&self) -> [u8; 16] {
        let mut cfg = [0u8; 16];
        cfg[0..2].copy_from_slice(&self.cols.to_le_bytes());
        cfg[2..4].copy_from_slice(&self.rows.to_le_bytes());
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
                let features = VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_SIZE;
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
                            "TX_QUEUE_SETUP sel={sel} avail={:#x} used={:#x} num={} last_avail={}",
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
                        self.queues[TX_QUEUE].last_avail_idx
                    ));
                    self.reset();
                }
            }
            REG_QUEUE_DESC_LOW => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.desc_addr = (q.desc_addr & 0xFFFFFFFF00000000) | value as u64;
                }
            }
            REG_QUEUE_DESC_HIGH => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.desc_addr = (q.desc_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
                }
            }
            REG_QUEUE_DRIVER_LOW => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.avail_addr = (q.avail_addr & 0xFFFFFFFF00000000) | value as u64;
                }
            }
            REG_QUEUE_DRIVER_HIGH => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.avail_addr = (q.avail_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
                }
            }
            REG_QUEUE_DEVICE_LOW => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.used_addr = (q.used_addr & 0xFFFFFFFF00000000) | value as u64;
                }
            }
            REG_QUEUE_DEVICE_HIGH => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    let q = &mut self.queues[self.queue_sel as usize];
                    q.used_addr = (q.used_addr & 0x00000000FFFFFFFF) | ((value as u64) << 32);
                }
            }
            _ => {}
        }
        None
    }

    fn reset(&mut self) {
        self.status = 0;
        self.interrupt_status = 0;
        self.driver_features = 0;
        self.rx_backlog.clear();
        self.work_gen = 0;
        self.work_gen_at_read = 0;
        for q in &mut self.queues {
            *q = VirtqState::new(QUEUE_SIZE);
        }
    }

    /// Append host bytes then inject as much as the guest receiveq can take. Returns whether any
    /// byte was delivered (and thus `interrupt_status` may be non-zero).
    pub fn push_rx_and_drain(&mut self, memory: &mut [u8], ram_base: u64, chunk: &[u8]) -> bool {
        if !chunk.is_empty() {
            self.rx_backlog.extend_from_slice(chunk);
        }
        self.drain_rx_backlog(memory, ram_base)
    }

    /// Retry injecting [`Self::rx_backlog`] (e.g. after the guest posts new receiveq buffers).
    pub fn drain_rx_backlog(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let mut progressed = false;
        loop {
            if self.rx_backlog.is_empty() {
                break;
            }
            let mut pending = mem::take(&mut self.rx_backlog);
            let n = self.inject_rx(memory, ram_base, &pending);
            pending.drain(..n);
            self.rx_backlog = pending;
            if n == 0 {
                crate::vmm_trace::write_console_io(format_args!(
                    "RX_BACKLOG_STALL pending_len={}",
                    self.rx_backlog.len()
                ));
                break;
            }
            progressed = true;
        }
        progressed
    }

    /// Process the TX queue (guest → host), at most [`Self::TX_HEADS_PER_SLICE`] heads per call.
    pub fn process_tx(&mut self, memory: &mut [u8], ram_base: u64) -> Vec<u8> {
        let q = self.queues[TX_QUEUE].clone();
        if !q.ready || q.num == 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SKIP reason=queue_not_ready ready={} num={}",
                q.ready, q.num
            ));
            return Vec::new();
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => {
                crate::vmm_trace::write_console_io(format_args!("TX_SKIP reason=bad_avail_ring"));
                return Vec::new();
            }
        };

        let mut last_avail = self.queues[TX_QUEUE].last_avail_idx;
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
        let num16 = q.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            let target = avail_idx.wrapping_sub(num16);
            crate::vmm_trace::write_console_io(format_args!(
                "TX_OVERTAKE last_avail={last_avail}->{} avail_idx={avail_idx} num={num16}",
                target
            ));
            last_avail = target;
        }

        if last_avail == avail_idx {
            let used_idx = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SKIP reason=no_new_heads last_avail={last_avail} avail_idx={avail_idx} used_idx={used_idx} avail_addr={:#x} used_addr={:#x} num={} ready={}",
                q.avail_addr, q.used_addr, q.num, q.ready
            ));
        }
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
        let mut output = Vec::new();

        while last_avail != avail_idx {
            if used_count >= Self::TX_HEADS_PER_SLICE {
                break;
            }

            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => {
                    crate::vmm_trace::write_console_io(format_args!(
                        "TX_SKIP reason=bad_avail_ring_entry last_avail={last_avail} avail_idx={avail_idx}"
                    ));
                    break;
                }
            };

            // Walk the descriptor chain, collecting readable (guest→host) bytes
            let mut idx = desc_head;
            let mut chain_len = 0u32;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, q.desc_addr, idx)
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
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                chain_len,
            )
            .is_none()
            {
                crate::vmm_trace::write_console_io(format_args!(
                    "TX_SKIP reason=bad_used_ring used_count={used_count}"
                ));
                break;
            }
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[TX_QUEUE].last_avail_idx = last_avail;

        if used_count > 0 {
            let _ = write_used_idx(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
            self.work_gen += 1;
            crate::vmm_trace::write_console_io(format_args!(
                "TX_SET_IRQ used_count={used_count} out_bytes={} irq_status={} last_avail={}",
                output.len(),
                self.interrupt_status,
                last_avail
            ));
        }

        if crate::vmm_trace::console_io_enabled() && used_count > 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "TX_BATCH heads={} out_bytes={} preview=\"{}\"",
                used_count,
                output.len(),
                crate::vmm_trace::bytes_preview(&output, 32)
            ));
        }

        output
    }

    /// Dump the raw vring state of both queues from guest RAM (wedge
    /// diagnostics): the device's `last_avail_idx` beside the rings' own
    /// indices, the full avail-ring head-id window, the full used-ring
    /// (id, len) window, and the descriptor table entries for every id the
    /// used ring references. From these three arrays the entire recent
    /// submit/complete history can be reconstructed off-guest, which is the
    /// only way to see the driver↔device desync when the guest console
    /// writer is wedged in `__send_to_port`'s completion spin.
    #[cfg(target_os = "linux")]
    pub fn dump_vrings(&self, memory: &[u8], ram_base: u64) {
        for (name, q) in [
            ("RX", &self.queues[RX_QUEUE]),
            ("TX", &self.queues[TX_QUEUE]),
        ] {
            if !q.ready || q.num == 0 {
                crate::vmm_trace::write_console_io(format_args!(
                    "VRING {name} not-ready num={} ready={}",
                    q.num, q.ready
                ));
                continue;
            }
            let avail_idx = read_avail_idx(memory, ram_base, q.avail_addr).unwrap_or(0);
            let used_idx = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
            crate::vmm_trace::write_console_io(format_args!(
                "VRING {name} num={} last_avail(dev)={} avail_idx(ring)={avail_idx} used_idx(ring)={used_idx} desc={:#x} avail={:#x} used={:#x}",
                q.num, q.last_avail_idx, q.desc_addr, q.avail_addr, q.used_addr,
            ));

            // Avail ring: the head id in each of the `num` slots.
            let mut slots = String::new();
            for s in 0..q.num as u16 {
                let id =
                    read_avail_ring(memory, ram_base, q.avail_addr, s, q.num).unwrap_or(0xffff);
                slots.push_str(&format!("{id},"));
            }
            crate::vmm_trace::write_console_io(format_args!(
                "VRING {name} AVAIL_SLOTS(id per slot 0..num): {slots}"
            ));

            // Used ring: every (id, len) entry in the window.
            let mut entries = String::new();
            let mut used_ids: Vec<u16> = Vec::new();
            for s in 0..q.num as u16 {
                match read_used_ring_entry(memory, ram_base, q.used_addr, s, q.num) {
                    Some((id, len)) => {
                        entries.push_str(&format!("{id}:{len},"));
                        used_ids.push(id as u16);
                    }
                    None => entries.push_str("?,"),
                }
            }
            crate::vmm_trace::write_console_io(format_args!(
                "VRING {name} USED_ENTRIES(id:len per slot 0..num): {entries}"
            ));

            // Descriptor table entries for the ids the used ring references.
            used_ids.sort_unstable();
            used_ids.dedup();
            for id in used_ids.iter() {
                match read_descriptor(memory, ram_base, q.desc_addr, *id) {
                    Some((addr, len, flags, next)) => {
                        crate::vmm_trace::write_console_io(format_args!(
                            "VRING {name} DESC[{id}] addr={addr:#x} len={len} flags={flags:#x} next={next}"
                        ));
                    }
                    None => {
                        crate::vmm_trace::write_console_io(format_args!(
                            "VRING {name} DESC[{id}] unreadable"
                        ));
                    }
                }
            }
        }
    }

    /// Inject a prefix of `data` into the RX queue. Returns **how many bytes** from the start of
    /// `data` were copied into guest memory and **completed** on the used ring (possibly across
    /// multiple avail heads). `0` means no progress (no buffers, stale ring, or not ready).
    pub fn inject_rx(&mut self, memory: &mut [u8], ram_base: u64, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }

        let q = self.queues[RX_QUEUE].clone();
        if !q.ready || q.num == 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "INJECT_RX_SKIP in_len={} reason=queue_not_ready ready={} num={}",
                data.len(),
                q.ready,
                q.num
            ));
            return 0;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => {
                crate::vmm_trace::write_console_io(format_args!(
                    "INJECT_RX_SKIP in_len={} reason=bad_avail_ring",
                    data.len()
                ));
                return 0;
            }
        };

        let mut last_avail = self.queues[RX_QUEUE].last_avail_idx;

        // Overtake guard, mirroring `process_tx`: if the driver posted a full
        // ring of RX buffers past `last_avail`, the older slots now hold
        // newer heads and draining them would complete phantom descriptors
        // (BAD_RING in the guest kills the queue permanently). Only trust
        // the last `num` posts.
        let num16 = q.num as u16;
        if num16 != 0 && avail_idx.wrapping_sub(last_avail) > num16 {
            crate::vmm_trace::write_console_io(format_args!(
                "RX_OVERTAKE last_avail={last_avail}->{} avail_idx={avail_idx} num={num16}",
                avail_idx.wrapping_sub(num16)
            ));
            last_avail = avail_idx.wrapping_sub(num16);
        }

        if last_avail == avail_idx {
            crate::vmm_trace::write_console_io(format_args!(
                "INJECT_RX_SKIP in_len={} reason=no_avail_buffers avail_idx={last_avail}",
                data.len()
            ));
            return 0;
        }

        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
        let mut used_count = 0u16;
        let mut data_offset = 0usize;
        let last_avail_start = last_avail;
        // Cap heads per call so the used ring and `last_avail_idx` stay consistent under load.
        let max_rx_heads: u16 = (q.num as u16).clamp(1, 64);

        while data_offset < data.len() && last_avail != avail_idx {
            if used_count >= max_rx_heads {
                break;
            }
            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            // Walk the descriptor chain, filling writable (host→guest) buffers
            let mut idx = desc_head;
            let mut chain_written = 0u32;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, q.desc_addr, idx)
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
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
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

        self.queues[RX_QUEUE].last_avail_idx = last_avail;

        if used_count > 0 {
            let _ = write_used_idx(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= VIRTIO_MMIO_INT_VRING;
            self.work_gen += 1;
        }

        let last_avail_end = self.queues[RX_QUEUE].last_avail_idx;
        let irq = self.interrupt_status != 0;
        if used_count > 0 {
            crate::vmm_trace::write_console_io(format_args!(
                "RX_SET_IRQ in_len={} heads={used_count} irq_status={}",
                data.len(),
                self.interrupt_status,
            ));
        }
        crate::vmm_trace::write_console_io(format_args!(
            "INJECT_RX in_len={} consumed={} heads={} avail={} last_avail {}->{} irq={}",
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
}
