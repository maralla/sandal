/// Virtio-net device implementation.
///
/// Provides a paravirtualized network interface to the guest using the
/// virtio MMIO transport. The backend is a user-space network stack that
/// proxies TCP, UDP, ICMP, ARP, and DHCP through host-side BSD sockets
/// without requiring root privileges.
use super::*;
use crate::net::NetworkFilter;
use crate::unet::{NetPoller, UserNet};

// Virtio-net device ID
const VIRTIO_ID_NET: u32 = 1;

// Virtio-net feature bits
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1 << 16;

// Virtio-net header size: 12 bytes when VIRTIO_F_VERSION_1 is negotiated
// (Linux uses struct virtio_net_hdr_mrg_rxbuf which adds num_buffers field)
const VIRTIO_NET_HDR_SIZE: usize = 12;

// Queue indices
const RX_QUEUE: u32 = 0;
const TX_QUEUE: u32 = 1;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZE: u32 = 256;

/// The complete virtio-net device with MMIO state
pub struct VirtioNetDevice {
    // MMIO state
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,
    pub config_generation: u32,

    // Device-specific
    pub mac: [u8; 6],
    pub backend: UserNet,
    pub filter: NetworkFilter,
    #[allow(dead_code)]
    pub irq_spi: u32,

    // Scratch buffer for packet I/O
    pkt_buf: Vec<u8>,
}

impl VirtioNetDevice {
    pub fn new(backend: UserNet, filter: NetworkFilter, irq_spi: u32) -> Self {
        let mac = backend.mac_address();

        VirtioNetDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [VirtqState::new(QUEUE_SIZE), VirtqState::new(QUEUE_SIZE)],
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
            mac,
            backend,
            filter,
            irq_spi,
            pkt_buf: vec![0u8; 2048],
        }
    }

    /// Handle an MMIO read at `offset` within the device's MMIO region.
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => VIRTIO_ID_NET,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                let features = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | VIRTIO_F_VERSION_1;
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

            // Config space: MAC address (6 bytes) + status (2 bytes)
            // The kernel reads this byte-by-byte (vm_get8) for MAC and
            // halfword (vm_get16) for status. Return data at exact offset.
            offset if (REG_CONFIG_BASE..REG_CONFIG_BASE + 8).contains(&offset) => {
                let config_off = (offset - REG_CONFIG_BASE) as usize;
                let mut config = [0u8; 8];
                config[0..6].copy_from_slice(&self.mac);
                config[6] = 1; // VIRTIO_NET_S_LINK_UP (low byte of status)
                config[7] = 0;
                // Return byte at exact offset (the guest ldrb/ldrh extracts
                // the correct width from the low bits of the register)
                config[config_off] as u32
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

    /// Create a kqueue-based network poller for the user-space networking backend.
    pub fn create_poller(&mut self, vcpu_id: u32) -> NetPoller {
        self.backend.create_poller(vcpu_id)
    }

    /// Poll the network backend for incoming data.
    pub fn poll_backend(&mut self) {
        self.backend.poll();
    }

    /// Process the TX queue: read packets from guest memory and send to backend.
    /// Returns true if the used ring was updated (interrupt needed).
    pub fn process_tx(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        let q = self.queues[TX_QUEUE as usize].clone();
        if !q.ready || q.num == 0 {
            return false;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return false,
        };

        let mut last_avail = self.queues[TX_QUEUE as usize].last_avail_idx;
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);

        while last_avail != avail_idx {
            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            let mut packet = Vec::new();
            let mut desc_idx = desc_head;
            let mut total_len = 0u32;
            while let Some((addr, len, flags, next)) =
                read_descriptor(memory, ram_base, q.desc_addr, desc_idx)
            {
                let offset = match addr.checked_sub(ram_base) {
                    Some(o) => o as usize,
                    None => break,
                };
                if offset + len as usize > memory.len() {
                    break;
                }
                packet.extend_from_slice(&memory[offset..offset + len as usize]);
                total_len += len;

                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                desc_idx = next;
            }

            // Skip the virtio-net header
            if packet.len() > VIRTIO_NET_HDR_SIZE {
                let eth_frame = &packet[VIRTIO_NET_HDR_SIZE..];

                // Apply network filter
                if self.filter.filter_tx_packet(eth_frame) {
                    let _ = self.backend.write_packet(eth_frame);
                }
            }

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

        self.queues[TX_QUEUE as usize].last_avail_idx = last_avail;

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

    /// Check backend for incoming packets and deliver them to the RX queue.
    /// Returns true if packets were delivered (interrupt needed).
    pub fn process_rx(&mut self, memory: &mut [u8], ram_base: u64) -> bool {
        if !self.backend.has_packets() {
            return false;
        }

        let q = self.queues[RX_QUEUE as usize].clone();
        if !q.ready || q.num == 0 {
            return false;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return false,
        };

        let mut last_avail = self.queues[RX_QUEUE as usize].last_avail_idx;
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);

        while last_avail != avail_idx {
            let pkt_len = match self.backend.read_packet(&mut self.pkt_buf) {
                Some(len) => len,
                None => break,
            };

            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            let (addr, len, _flags, _next) =
                match read_descriptor(memory, ram_base, q.desc_addr, desc_head) {
                    Some(d) => d,
                    None => break,
                };

            let total_write = VIRTIO_NET_HDR_SIZE + pkt_len;
            if total_write > len as usize {
                continue;
            }

            let offset = match addr.checked_sub(ram_base) {
                Some(o) => o as usize,
                None => break,
            };
            if offset + total_write > memory.len() {
                break;
            }

            // Zero out the virtio-net header
            memory[offset..offset + VIRTIO_NET_HDR_SIZE].fill(0);
            // Write packet data after the header
            memory[offset + VIRTIO_NET_HDR_SIZE..offset + total_write]
                .copy_from_slice(&self.pkt_buf[..pkt_len]);

            write_used_ring(
                memory,
                ram_base,
                q.used_addr,
                used_idx_start.wrapping_add(used_count),
                q.num,
                desc_head as u32,
                total_write as u32,
            );
            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[RX_QUEUE as usize].last_avail_idx = last_avail;

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
