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
use super::*;

// Virtio device ID for console (virtio spec §5.3)
const VIRTIO_ID_CONSOLE: u32 = 3;

const QUEUE_SIZE: u32 = 128;
const NUM_QUEUES: usize = 2;

const RX_QUEUE: usize = 0;
const TX_QUEUE: usize = 1;

/// Feature bit: console size (cols, rows) is available in config space.
const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;

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
}

impl VirtioConsoleDevice {
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
        }
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => VIRTIO_ID_CONSOLE,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                let features = VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_SIZE;
                if self.device_features_sel == 0 {
                    (features & 0xFFFFFFFF) as u32
                } else {
                    ((features >> 32) & 0xFFFFFFFF) as u32
                }
            }
            REG_QUEUE_NUM_MAX => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].num_max
                } else {
                    0
                }
            }
            REG_QUEUE_READY => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].ready as u32
                } else {
                    0
                }
            }
            REG_INTERRUPT_STATUS => self.interrupt_status,
            REG_STATUS => self.status,
            REG_SHM_LEN_LOW | REG_SHM_LEN_HIGH => 0xFFFFFFFF,
            REG_SHM_BASE_LOW | REG_SHM_BASE_HIGH => 0,
            REG_CONFIG_GENERATION => 0,
            // Config space: cols (u16 at +0), rows (u16 at +2)
            REG_CONFIG_BASE => (self.rows as u32) << 16 | self.cols as u32,
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
        for q in &mut self.queues {
            *q = VirtqState::new(QUEUE_SIZE);
        }
    }

    /// Process the TX queue (guest → host): collect output bytes from
    /// the transmitq descriptors.  Returns the bytes the VMM should
    /// write to stdout.
    pub fn process_tx(&mut self, memory: &mut [u8], ram_base: u64) -> Vec<u8> {
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

            write_used_ring(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                chain_len,
            );
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[TX_QUEUE].last_avail_idx = last_avail;

        if used_count > 0 {
            write_used_idx(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= 1;
        }

        output
    }

    /// Inject bytes into the RX queue (host → guest): place `data` into
    /// pre-posted receiveq descriptors.  Returns true if data was injected
    /// (interrupt needed).
    pub fn inject_rx(&mut self, memory: &mut [u8], ram_base: u64, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        let q = self.queues[RX_QUEUE].clone();
        if !q.ready || q.num == 0 {
            return false;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return false,
        };

        let mut last_avail = self.queues[RX_QUEUE].last_avail_idx;
        if last_avail == avail_idx {
            // No pre-posted buffers available
            return false;
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

            write_used_ring(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                chain_written,
            );
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[RX_QUEUE].last_avail_idx = last_avail;

        if used_count > 0 {
            write_used_idx(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
            );
            self.interrupt_status |= 1;
            true
        } else {
            false
        }
    }
}
