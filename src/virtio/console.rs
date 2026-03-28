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
}

impl VirtioConsoleDevice {
    /// Max transmitq avail heads per `process_tx` call so Tab-sized bursts do not monopolize the
    /// VMM thread (stdin + main loop make progress between `vcpu.run()` entries).
    const TX_HEADS_PER_SLICE: u16 = 16_384;

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
        }
    }

    fn virtio_console_config_bytes(&self) -> [u8; 16] {
        let mut cfg = [0u8; 16];
        cfg[0..2].copy_from_slice(&self.cols.to_le_bytes());
        cfg[2..4].copy_from_slice(&self.rows.to_le_bytes());
        cfg
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    ///
    /// `sas` is the ARM64 Data Abort ISS access size (`0` byte … `3` doubleword). Required for
    /// `DEVICE_CONFIG` loads: Linux may use `readl` on `cols`/`rows` or byte/halfword probes.
    pub fn mmio_read(&self, offset: u64, sas: u8) -> u64 {
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
            REG_INTERRUPT_STATUS => self.interrupt_status as u64,
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
                    self.queues[self.queue_sel as usize].ready = value != 0;
                }
            }
            REG_QUEUE_NOTIFY => {
                return Some(value);
            }
            REG_INTERRUPT_ACK => {
                self.interrupt_status &= !value;
            }
            REG_STATUS => {
                self.status = value;
                if value == 0 {
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
                break;
            }
            progressed = true;
        }
        progressed
    }

    /// True if the guest transmitq still has descriptors we have not completed on the used ring.
    pub fn tx_queue_has_pending(&self, memory: &[u8], ram_base: u64) -> bool {
        let q = &self.queues[TX_QUEUE];
        if !q.ready || q.num == 0 {
            return false;
        }
        read_avail_idx(memory, ram_base, q.avail_addr).is_some_and(|a| a != q.last_avail_idx)
    }

    /// Process the TX queue (guest → host), at most [`Self::TX_HEADS_PER_SLICE`] heads per call.
    pub fn process_tx(&mut self, memory: &mut [u8], ram_base: u64) -> Vec<u8> {
        self.process_tx_inner(memory, ram_base, Some(Self::TX_HEADS_PER_SLICE))
    }

    fn process_tx_inner(
        &mut self,
        memory: &mut [u8],
        ram_base: u64,
        max_heads: Option<u16>,
    ) -> Vec<u8> {
        let q = self.queues[TX_QUEUE].clone();
        if !q.ready || q.num == 0 {
            return Vec::new();
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return Vec::new(),
        };

        let mut last_avail = self.queues[TX_QUEUE].last_avail_idx;
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
        let mut output = Vec::new();

        while last_avail != avail_idx {
            if max_heads.is_some_and(|m| used_count >= m) {
                break;
            }

            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
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
            self.interrupt_status |= 1;
        }

        output
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
            return 0;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return 0,
        };

        let mut last_avail = self.queues[RX_QUEUE].last_avail_idx;
        if last_avail == avail_idx {
            return 0;
        }

        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);
        let mut used_count = 0u16;
        let mut data_offset = 0usize;

        while data_offset < data.len() && last_avail != avail_idx {
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
            self.interrupt_status |= 1;
        }
        data_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmio_config_word_matches_le_cols_rows() {
        let c = VirtioConsoleDevice::new(80, 25);
        let v = c.mmio_read(REG_CONFIG_BASE, 2);
        let want = u32::from_le_bytes([80u8, 0, 25, 0]) as u64;
        assert_eq!(v, want);
    }

    #[test]
    fn mmio_config_byte_second_byte_of_cols() {
        let c = VirtioConsoleDevice::new(0x3412, 0);
        assert_eq!(c.mmio_read(REG_CONFIG_BASE + 1, 0), 0x34);
    }

    #[test]
    fn mmio_config_halfword_rows() {
        let c = VirtioConsoleDevice::new(80, 25);
        assert_eq!(c.mmio_read(REG_CONFIG_BASE + 2, 1), 25);
    }
}
