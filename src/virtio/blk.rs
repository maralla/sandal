/// Virtio-blk device implementation.
///
/// Provides a paravirtualized block device to the guest using
/// the virtio MMIO transport. Backed by an in-memory disk image.
use super::*;

// Virtio-blk device ID
const VIRTIO_ID_BLOCK: u32 = 2;

// Virtio-blk feature bits
const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

// Virtio-blk request types
const VIRTIO_BLK_T_IN: u32 = 0; // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write
const VIRTIO_BLK_T_FLUSH: u32 = 4; // Flush
const VIRTIO_BLK_T_GET_ID: u32 = 8; // Get device ID

// Virtio-blk status codes
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const SECTOR_SIZE: usize = 512;
const QUEUE_SIZE: u32 = 128;
const NUM_QUEUES: usize = 1;

/// Virtio-blk device backed by an in-memory image.
pub struct VirtioBlkDevice {
    // MMIO state (same pattern as virtio-net)
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,
    pub config_generation: u32,

    // Block device backing store
    pub disk_image: Vec<u8>,
    pub capacity_sectors: u64,
}

impl VirtioBlkDevice {
    pub fn new(disk_image: Vec<u8>) -> Self {
        let capacity_sectors = (disk_image.len() / SECTOR_SIZE) as u64;

        VirtioBlkDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [VirtqState::new(QUEUE_SIZE)],
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
            disk_image,
            capacity_sectors,
        }
    }

    /// Recalculate the capacity (in 512-byte sectors) from the current disk image size.
    /// Call after resizing `disk_image`.
    pub fn update_capacity(&mut self) {
        self.capacity_sectors = (self.disk_image.len() / SECTOR_SIZE) as u64;
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => VIRTIO_ID_BLOCK,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                let features = VIRTIO_BLK_F_SIZE_MAX
                    | VIRTIO_BLK_F_SEG_MAX
                    | VIRTIO_BLK_F_FLUSH
                    | VIRTIO_F_VERSION_1;
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
            // Shared memory region: length = ~0 means no SHM available
            REG_SHM_LEN_LOW | REG_SHM_LEN_HIGH => 0xFFFFFFFF,
            REG_SHM_BASE_LOW | REG_SHM_BASE_HIGH => 0,
            REG_CONFIG_GENERATION => self.config_generation,

            // Config space: virtio_blk_config
            // offset 0: capacity (u64, in 512-byte sectors)
            // offset 8: size_max (u32)
            // offset 12: seg_max (u32)
            offset if (REG_CONFIG_BASE..REG_CONFIG_BASE + 64).contains(&offset) => {
                let config_off = (offset - REG_CONFIG_BASE) as usize;
                match config_off {
                    0 => (self.capacity_sectors & 0xFFFFFFFF) as u32,
                    4 => ((self.capacity_sectors >> 32) & 0xFFFFFFFF) as u32,
                    8 => 32768, // size_max: must be >= PAGE_SIZE (4096 on arm64)
                    12 => 128,  // seg_max
                    _ => 0,
                }
            }

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

    /// Process the request queue.
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

        while last_avail != avail_idx {
            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            let total_len = self.handle_request(memory, ram_base, &q, desc_head);

            write_used_ring(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                total_len,
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

    /// Handle a single virtio-blk request (descriptor chain).
    /// Returns total bytes written to device-writable descriptors.
    fn handle_request(
        &mut self,
        memory: &mut [u8],
        ram_base: u64,
        q: &VirtqState,
        head: u16,
    ) -> u32 {
        // Collect all descriptors in the chain
        let mut descs: Vec<(u64, u32, u16)> = Vec::new(); // (addr, len, flags)
        let mut idx = head;
        while let Some((addr, len, flags, next)) =
            read_descriptor(memory, ram_base, q.desc_addr, idx)
        {
            descs.push((addr, len, flags));
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }

        if descs.len() < 2 {
            // Need at least header + status
            return 0;
        }

        // First descriptor: request header (device-readable)
        let (hdr_addr, hdr_len, _) = descs[0];
        if hdr_len < 16 {
            return 0;
        }

        let hdr_off = match hdr_addr.checked_sub(ram_base) {
            Some(o) => o as usize,
            None => return 0,
        };
        if hdr_off + 16 > memory.len() {
            return 0;
        }

        let req_type = u32::from_le_bytes(memory[hdr_off..hdr_off + 4].try_into().unwrap());
        let _reserved = u32::from_le_bytes(memory[hdr_off + 4..hdr_off + 8].try_into().unwrap());
        let sector = u64::from_le_bytes(memory[hdr_off + 8..hdr_off + 16].try_into().unwrap());

        // Last descriptor: status byte (device-writable)
        let (status_addr, _, _) = descs[descs.len() - 1];
        let status_off = match status_addr.checked_sub(ram_base) {
            Some(o) => o as usize,
            None => return 0,
        };
        if status_off >= memory.len() {
            return 0;
        }

        // Middle descriptors: data buffers
        let data_descs = &descs[1..descs.len() - 1];
        let mut total_written = 0u32;

        let status = match req_type {
            VIRTIO_BLK_T_IN => {
                // Read from disk image to guest memory
                let mut disk_offset = (sector as usize) * SECTOR_SIZE;
                let mut ok = true;

                for &(addr, len, _flags) in data_descs {
                    let guest_off = match addr.checked_sub(ram_base) {
                        Some(o) => o as usize,
                        None => {
                            ok = false;
                            break;
                        }
                    };
                    let len = len as usize;
                    if guest_off + len > memory.len() {
                        ok = false;
                        break;
                    }
                    if disk_offset + len > self.disk_image.len() {
                        // Read past end — zero-fill
                        let avail = self.disk_image.len().saturating_sub(disk_offset);
                        if avail > 0 {
                            memory[guest_off..guest_off + avail].copy_from_slice(
                                &self.disk_image[disk_offset..disk_offset + avail],
                            );
                        }
                        if avail < len {
                            memory[guest_off + avail..guest_off + len].fill(0);
                        }
                    } else {
                        memory[guest_off..guest_off + len]
                            .copy_from_slice(&self.disk_image[disk_offset..disk_offset + len]);
                    }
                    disk_offset += len;
                    total_written += len as u32;
                }

                if ok {
                    VIRTIO_BLK_S_OK
                } else {
                    VIRTIO_BLK_S_IOERR
                }
            }

            VIRTIO_BLK_T_OUT => {
                // Write from guest memory to disk image
                let mut disk_offset = (sector as usize) * SECTOR_SIZE;
                let mut ok = true;

                for &(addr, len, _flags) in data_descs {
                    let guest_off = match addr.checked_sub(ram_base) {
                        Some(o) => o as usize,
                        None => {
                            ok = false;
                            break;
                        }
                    };
                    let len = len as usize;
                    if guest_off + len > memory.len() {
                        ok = false;
                        break;
                    }

                    // Grow image if needed
                    let needed = disk_offset + len;
                    if needed > self.disk_image.len() {
                        self.disk_image.resize(needed, 0);
                    }

                    self.disk_image[disk_offset..disk_offset + len]
                        .copy_from_slice(&memory[guest_off..guest_off + len]);
                    disk_offset += len;
                }

                if ok {
                    VIRTIO_BLK_S_OK
                } else {
                    VIRTIO_BLK_S_IOERR
                }
            }

            VIRTIO_BLK_T_FLUSH => {
                // Flush — no-op for in-memory image
                VIRTIO_BLK_S_OK
            }

            VIRTIO_BLK_T_GET_ID => {
                // Return device ID string
                if let Some(&(addr, len, _)) = data_descs.first() {
                    let guest_off = match addr.checked_sub(ram_base) {
                        Some(o) => o as usize,
                        None => return 0,
                    };
                    let id = b"sandal-blk\0";
                    let copy_len = id.len().min(len as usize);
                    if guest_off + copy_len <= memory.len() {
                        memory[guest_off..guest_off + copy_len].copy_from_slice(&id[..copy_len]);
                        total_written += copy_len as u32;
                    }
                }
                VIRTIO_BLK_S_OK
            }

            _ => VIRTIO_BLK_S_UNSUPP,
        };

        // Write status byte
        memory[status_off] = status;
        total_written += 1; // status byte

        total_written
    }
}
