/// Virtio-rng device implementation.
///
/// Provides entropy from the host to the guest via the virtio MMIO transport.
/// This is essential for guests that need cryptographic random numbers (e.g. TLS),
/// especially on kernels without hardware RNG support (like kernel 4.14 on ARM64 VMs).
use super::*;
use std::io::Read;

// Virtio-rng device ID
const VIRTIO_ID_RNG: u32 = 4;

const QUEUE_SIZE: u32 = 64;
const NUM_QUEUES: usize = 1;

/// Virtio-rng device that provides host entropy to the guest.
pub struct VirtioRngDevice {
    // MMIO state
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,
}

impl VirtioRngDevice {
    pub fn new() -> Self {
        VirtioRngDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [VirtqState::new(QUEUE_SIZE)],
            status: 0,
            interrupt_status: 0,
        }
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => VIRTIO_ID_RNG,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                let features = VIRTIO_F_VERSION_1;
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
        for q in &mut self.queues {
            *q = VirtqState::new(QUEUE_SIZE);
        }
    }

    /// Process the requestq: fill guest buffers with random data from the host.
    /// Returns true if the used ring was updated (interrupt needed).
    pub fn process_queue(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let q = self.queues[0].clone();
        if !q.ready || q.num == 0 {
            return false;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return false,
        };

        let mut last_avail = self.queues[0].last_avail_idx;
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);

        // Open /dev/urandom once for this batch
        let mut rng = match std::fs::File::open("/dev/urandom") {
            Ok(f) => f,
            Err(_) => return false,
        };

        while last_avail != avail_idx {
            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            let total_written = self.fill_random(memory, ram_base, &q, desc_head, &mut rng);

            write_used_ring(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                total_written,
            );
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[0].last_avail_idx = last_avail;

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

    /// Fill a descriptor chain with random data from the host.
    /// Returns total bytes written.
    fn fill_random(
        &self,
        memory: &mut [u8],
        ram_base: u64,
        q: &VirtqState,
        head: u16,
        rng: &mut std::fs::File,
    ) -> u32 {
        let mut total_written = 0u32;
        let mut idx = head;

        while let Some((addr, len, flags, next)) =
            read_descriptor(memory, ram_base, q.desc_addr, idx)
        {
            // Only write to device-writable descriptors
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                let offset = match addr.checked_sub(ram_base) {
                    Some(o) => o as usize,
                    None => break,
                };
                let len = len as usize;
                if offset + len > memory.len() {
                    break;
                }

                // Fill buffer with random data from host
                let _ = rng.read_exact(&mut memory[offset..offset + len]);
                total_written += len as u32;
            }

            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }

        total_written
    }
}
