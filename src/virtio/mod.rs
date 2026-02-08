#![allow(dead_code)]

pub mod blk;
/// Virtio MMIO transport implementation (virtio v2 / modern).
///
/// Implements the virtio over MMIO transport as defined in the virtio spec §4.2.
/// Each virtio device appears as a 0x200-byte MMIO region.
pub mod net;
pub mod rng;

// Virtio MMIO magic value ("virt")
pub const VIRTIO_MMIO_MAGIC: u32 = 0x74726976;
pub const VIRTIO_MMIO_VERSION: u32 = 2;
// "QEMU" in ASCII — the de-facto standard vendor ID recognized by Linux virtio drivers.
pub const VIRTIO_MMIO_VENDOR: u32 = 0x554D4551;

// Virtio MMIO register offsets
pub const REG_MAGIC_VALUE: u64 = 0x000;
pub const REG_VERSION: u64 = 0x004;
pub const REG_DEVICE_ID: u64 = 0x008;
pub const REG_VENDOR_ID: u64 = 0x00C;
pub const REG_DEVICE_FEATURES: u64 = 0x010;
pub const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const REG_DRIVER_FEATURES: u64 = 0x020;
pub const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const REG_QUEUE_SEL: u64 = 0x030;
pub const REG_QUEUE_NUM_MAX: u64 = 0x034;
pub const REG_QUEUE_NUM: u64 = 0x038;
pub const REG_QUEUE_READY: u64 = 0x044;
pub const REG_QUEUE_NOTIFY: u64 = 0x050;
pub const REG_INTERRUPT_STATUS: u64 = 0x060;
pub const REG_INTERRUPT_ACK: u64 = 0x064;
pub const REG_STATUS: u64 = 0x070;
pub const REG_QUEUE_DESC_LOW: u64 = 0x080;
pub const REG_QUEUE_DESC_HIGH: u64 = 0x084;
pub const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
pub const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
pub const REG_QUEUE_DEVICE_LOW: u64 = 0x0A0;
pub const REG_QUEUE_DEVICE_HIGH: u64 = 0x0A4;
pub const REG_CONFIG_GENERATION: u64 = 0x0FC;
pub const REG_CONFIG_BASE: u64 = 0x100;

// Virtio status bits
pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
pub const VIRTIO_STATUS_DRIVER: u32 = 2;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
pub const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
pub const VIRTIO_STATUS_FAILED: u32 = 128;

// Virtio features
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// Virtqueue descriptor flags
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// State of a single virtqueue
#[derive(Clone)]
pub struct VirtqState {
    pub num_max: u32, // Max queue size
    pub num: u32,     // Current queue size (set by driver)
    pub ready: bool,
    pub desc_addr: u64,  // Guest physical address of descriptor table
    pub avail_addr: u64, // Guest physical address of available ring
    pub used_addr: u64,  // Guest physical address of used ring
    pub last_avail_idx: u16,
}

impl VirtqState {
    pub fn new(num_max: u32) -> Self {
        VirtqState {
            num_max,
            num: 0,
            ready: false,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            last_avail_idx: 0,
        }
    }
}

/// Read a descriptor from the descriptor table in guest memory
pub fn read_descriptor(
    memory: &[u8],
    ram_base: u64,
    desc_addr: u64,
    index: u16,
) -> Option<(u64, u32, u16, u16)> {
    let entry_addr = desc_addr + (index as u64) * 16;
    let offset = entry_addr.checked_sub(ram_base)? as usize;
    if offset + 16 > memory.len() {
        return None;
    }

    let addr = u64::from_le_bytes(memory[offset..offset + 8].try_into().ok()?);
    let len = u32::from_le_bytes(memory[offset + 8..offset + 12].try_into().ok()?);
    let flags = u16::from_le_bytes(memory[offset + 12..offset + 14].try_into().ok()?);
    let next = u16::from_le_bytes(memory[offset + 14..offset + 16].try_into().ok()?);

    Some((addr, len, flags, next))
}

/// Read the current available ring index
pub fn read_avail_idx(memory: &[u8], ram_base: u64, avail_addr: u64) -> Option<u16> {
    let offset = avail_addr.checked_sub(ram_base)? as usize + 2;
    if offset + 2 > memory.len() {
        return None;
    }
    Some(u16::from_le_bytes(
        memory[offset..offset + 2].try_into().ok()?,
    ))
}

/// Read an entry from the available ring
pub fn read_avail_ring(
    memory: &[u8],
    ram_base: u64,
    avail_addr: u64,
    idx: u16,
    queue_size: u32,
) -> Option<u16> {
    let ring_offset = 4 + (idx % queue_size as u16) as u64 * 2;
    let offset = avail_addr.checked_sub(ram_base)? as usize + ring_offset as usize;
    if offset + 2 > memory.len() {
        return None;
    }
    Some(u16::from_le_bytes(
        memory[offset..offset + 2].try_into().ok()?,
    ))
}

/// Write an entry to the used ring
pub fn write_used_ring(
    memory: &mut [u8],
    ram_base: u64,
    used_addr: u64,
    used_idx: u16,
    queue_size: u32,
    desc_id: u32,
    len: u32,
) -> Option<()> {
    let ring_entry_offset = 4 + (used_idx % queue_size as u16) as u64 * 8;
    let offset = used_addr.checked_sub(ram_base)? as usize + ring_entry_offset as usize;
    if offset + 8 > memory.len() {
        return None;
    }

    memory[offset..offset + 4].copy_from_slice(&desc_id.to_le_bytes());
    memory[offset + 4..offset + 8].copy_from_slice(&len.to_le_bytes());
    Some(())
}

/// Update the used ring index
pub fn write_used_idx(memory: &mut [u8], ram_base: u64, used_addr: u64, idx: u16) -> Option<()> {
    let offset = used_addr.checked_sub(ram_base)? as usize + 2;
    if offset + 2 > memory.len() {
        return None;
    }
    memory[offset..offset + 2].copy_from_slice(&idx.to_le_bytes());
    Some(())
}

/// Read the current used ring index
pub fn read_used_idx(memory: &[u8], ram_base: u64, used_addr: u64) -> Option<u16> {
    let offset = used_addr.checked_sub(ram_base)? as usize + 2;
    if offset + 2 > memory.len() {
        return None;
    }
    Some(u16::from_le_bytes(
        memory[offset..offset + 2].try_into().ok()?,
    ))
}
