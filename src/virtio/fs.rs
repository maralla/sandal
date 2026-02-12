/// Virtiofs device implementation (FUSE over virtio).
///
/// Provides a shared filesystem between the host and guest using the
/// FUSE protocol over virtio MMIO transport. Each device exposes a host
/// directory to the guest, which mounts it via:
///
///     mount -t virtiofs <tag> <mountpoint>
use super::*;
use log::{debug, warn};
use std::collections::HashMap;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

// ============================================================================
// Virtio device constants
// ============================================================================

/// Virtio device ID for virtio-fs (virtio spec §5.11)
const VIRTIO_ID_FS: u32 = 26;

const QUEUE_SIZE: u32 = 128;
/// Two queues: hiprio (queue 0) for FORGET, requests (queue 1) for everything else.
const NUM_QUEUES: usize = 2;

/// Maximum FUSE write payload (128 KB)
const MAX_WRITE_SIZE: u32 = 128 * 1024;

// ============================================================================
// FUSE protocol constants
// ============================================================================

const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 31;

/// Root inode number (always 1 in FUSE)
const FUSE_ROOT_ID: u64 = 1;

// ---- FUSE opcodes (from include/uapi/linux/fuse.h) ----
const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_SYMLINK: u32 = 6;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_LINK: u32 = 13;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_SETXATTR: u32 = 21;
const FUSE_GETXATTR: u32 = 22;
const FUSE_LISTXATTR: u32 = 23;
const FUSE_REMOVEXATTR: u32 = 24;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_ACCESS: u32 = 34;
const FUSE_CREATE: u32 = 35;
const FUSE_DESTROY: u32 = 38;
const FUSE_BATCH_FORGET: u32 = 42;
const FUSE_READDIRPLUS: u32 = 44;
const FUSE_RENAME2: u32 = 45;

// ---- FUSE INIT capability flags ----
const FUSE_BIG_WRITES: u32 = 1 << 5;
const FUSE_DO_READDIRPLUS: u32 = 1 << 13;

/// Flags we advertise during FUSE_INIT negotiation.
const FUSE_SUPPORTED_FLAGS: u32 = FUSE_BIG_WRITES | FUSE_DO_READDIRPLUS;

// ---- Cache timeouts (seconds) ----
const ENTRY_TIMEOUT: u64 = 1;
const ATTR_TIMEOUT: u64 = 1;

// ---- FATTR valid bits (for FUSE_SETATTR) ----
const FATTR_MODE: u32 = 1;
const FATTR_SIZE: u32 = 1 << 3;

// ---- Linux errno values (cross-platform safe) ----
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;
const ENOTEMPTY: i32 = 39;
const ENODATA: i32 = 61;
const EOPNOTSUPP: i32 = 95;

// ============================================================================
// Helper types for parsing/building FUSE messages
// ============================================================================

/// Read cursor over a byte slice for parsing FUSE requests.
struct ParseBuf<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ParseBuf<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.data.len());
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.pos + 8 > self.data.len() {
            return None;
        }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().ok()?);
        self.pos += 8;
        Some(v)
    }

    /// Read a null-terminated C string from the current position.
    fn read_cstr(&mut self) -> Option<String> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        let s = String::from_utf8_lossy(&self.data[start..self.pos]).to_string();
        if self.pos < self.data.len() {
            self.pos += 1; // skip null terminator
        }
        Some(s)
    }

    /// Read the remaining bytes as a slice.
    fn read_remaining(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
}

/// Write buffer for building FUSE response messages.
struct WriteBuf {
    data: Vec<u8>,
}

impl WriteBuf {
    fn new() -> Self {
        Self {
            data: Vec::with_capacity(256),
        }
    }

    /// Create a FUSE response header (len placeholder + error=0 + unique).
    fn fuse_out(unique: u64) -> Self {
        let mut wb = Self::new();
        wb.write_u32(0); // len placeholder
        wb.write_i32(0); // error = success
        wb.write_u64(unique);
        wb
    }

    fn write_u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_i32(&mut self, v: i32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    fn write_zeros(&mut self, n: usize) {
        self.data.extend(std::iter::repeat_n(0u8, n));
    }

    /// Patch the length field and return the final response bytes.
    fn finish(mut self) -> Vec<u8> {
        let len = self.data.len() as u32;
        self.data[0..4].copy_from_slice(&len.to_le_bytes());
        self.data
    }
}

/// Build a FUSE error response (out_header only, 16 bytes).
fn make_error(unique: u64, errno: i32) -> Vec<u8> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&16u32.to_le_bytes()); // len = 16
    data.extend_from_slice(&(-errno).to_le_bytes()); // negative errno
    data.extend_from_slice(&unique.to_le_bytes());
    data
}

/// Write a fuse_attr (88 bytes) into a WriteBuf from filesystem metadata.
fn write_fuse_attr(wb: &mut WriteBuf, ino: u64, meta: &std::fs::Metadata) {
    wb.write_u64(ino); // ino
    wb.write_u64(meta.size()); // size
    wb.write_u64(meta.blocks()); // blocks
    wb.write_u64(meta.atime() as u64); // atime
    wb.write_u64(meta.mtime() as u64); // mtime
    wb.write_u64(meta.ctime() as u64); // ctime
    wb.write_u32(meta.atime_nsec() as u32); // atimensec
    wb.write_u32(meta.mtime_nsec() as u32); // mtimensec
    wb.write_u32(meta.ctime_nsec() as u32); // ctimensec
    wb.write_u32(meta.mode()); // mode
    wb.write_u32(meta.nlink() as u32); // nlink
    wb.write_u32(meta.uid()); // uid
    wb.write_u32(meta.gid()); // gid
    wb.write_u32(meta.rdev() as u32); // rdev
    wb.write_u32(meta.blksize() as u32); // blksize
    wb.write_u32(0); // flags (padding)
}

/// Write a fuse_entry_out (128 bytes) into a WriteBuf.
fn write_entry_out(wb: &mut WriteBuf, ino: u64, meta: &std::fs::Metadata) {
    wb.write_u64(ino); // nodeid
    wb.write_u64(0); // generation
    wb.write_u64(ENTRY_TIMEOUT); // entry_valid
    wb.write_u64(ATTR_TIMEOUT); // attr_valid
    wb.write_u32(0); // entry_valid_nsec
    wb.write_u32(0); // attr_valid_nsec
    write_fuse_attr(wb, ino, meta);
}

/// Write a fuse_attr_out (104 bytes) into a WriteBuf.
fn write_attr_out(wb: &mut WriteBuf, ino: u64, meta: &std::fs::Metadata) {
    wb.write_u64(ATTR_TIMEOUT); // attr_valid
    wb.write_u32(0); // attr_valid_nsec
    wb.write_u32(0); // dummy
    write_fuse_attr(wb, ino, meta);
}

// ============================================================================
// Inode and file-handle state
// ============================================================================

/// Per-inode state tracking a filesystem entry known to the guest.
struct InodeState {
    host_path: PathBuf,
    /// Reference count: incremented by LOOKUP/CREATE/MKDIR/etc.,
    /// decremented by FORGET. When it reaches 0 the inode can be evicted.
    nlookup: u64,
}

/// An open file or directory handle.
enum HandleInner {
    File(std::fs::File),
    Dir(PathBuf),
}

struct HandleState {
    inner: HandleInner,
}

// ============================================================================
// Virtiofs device
// ============================================================================

pub struct VirtioFsDevice {
    // Virtio MMIO state
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub queues: [VirtqState; NUM_QUEUES],
    pub status: u32,
    pub interrupt_status: u32,
    pub config_generation: u32,

    // Filesystem state
    root_path: PathBuf,
    mount_tag: String,
    inodes: HashMap<u64, InodeState>,
    path_to_inode: HashMap<PathBuf, u64>,
    handles: HashMap<u64, HandleState>,
    next_ino: u64,
    next_fh: u64,
}

impl VirtioFsDevice {
    pub fn new(root_path: PathBuf, mount_tag: String) -> Self {
        let mut inodes = HashMap::new();
        let mut path_to_inode = HashMap::new();

        // Root inode is always present and never forgotten
        inodes.insert(
            FUSE_ROOT_ID,
            InodeState {
                host_path: root_path.clone(),
                nlookup: u64::MAX,
            },
        );
        path_to_inode.insert(root_path.clone(), FUSE_ROOT_ID);

        VirtioFsDevice {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [VirtqState::new(QUEUE_SIZE), VirtqState::new(QUEUE_SIZE)],
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
            root_path,
            mount_tag,
            inodes,
            path_to_inode,
            handles: HashMap::new(),
            next_ino: 2, // 1 is reserved for root
            next_fh: 1,
        }
    }

    // ---- Virtio MMIO interface ----

    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            REG_MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            REG_VERSION => VIRTIO_MMIO_VERSION,
            REG_DEVICE_ID => VIRTIO_ID_FS,
            REG_VENDOR_ID => VIRTIO_MMIO_VENDOR,
            REG_DEVICE_FEATURES => {
                // virtio-fs has no device-specific feature bits beyond VERSION_1
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
            // Shared memory region registers: return length = ~0 to indicate
            // no shared memory region available (no DAX window)
            REG_SHM_LEN_LOW | REG_SHM_LEN_HIGH => 0xFFFFFFFF,
            REG_SHM_BASE_LOW | REG_SHM_BASE_HIGH => 0,
            REG_CONFIG_GENERATION => self.config_generation,

            // Config space: virtio_fs_config { tag[36], num_request_queues: u32 }
            offset if (REG_CONFIG_BASE..REG_CONFIG_BASE + 40).contains(&offset) => {
                let config_off = (offset - REG_CONFIG_BASE) as usize;
                let mut config = [0u8; 40];
                // tag: 36-byte null-padded UTF-8 string
                let tag_bytes = self.mount_tag.as_bytes();
                let copy_len = tag_bytes.len().min(36);
                config[..copy_len].copy_from_slice(&tag_bytes[..copy_len]);
                // num_request_queues at offset 36
                config[36..40].copy_from_slice(&1u32.to_le_bytes());

                let mut bytes = [0u8; 4];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    let idx = config_off + i;
                    if idx < config.len() {
                        *byte = config[idx];
                    }
                }
                u32::from_le_bytes(bytes)
            }

            _ => 0,
        }
    }

    pub fn mmio_write(&mut self, offset: u64, value: u32) -> Option<u32> {
        match offset {
            REG_DEVICE_FEATURES_SEL => self.device_features_sel = value,
            REG_DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFFFFFF00000000) | value as u64;
                } else {
                    self.driver_features =
                        (self.driver_features & 0x00000000FFFFFFFF) | ((value as u64) << 32);
                }
            }
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            REG_QUEUE_SEL => self.queue_sel = value,
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
            REG_QUEUE_NOTIFY => return Some(value),
            REG_INTERRUPT_ACK => self.interrupt_status &= !value,
            REG_SHM_SEL => { /* Accept SHM region selection; we have no SHM regions */ }
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
        self.inodes.clear();
        self.path_to_inode.clear();
        self.handles.clear();
        self.next_ino = 2;
        self.next_fh = 1;
        // Re-insert root inode
        self.inodes.insert(
            FUSE_ROOT_ID,
            InodeState {
                host_path: self.root_path.clone(),
                nlookup: u64::MAX,
            },
        );
        self.path_to_inode
            .insert(self.root_path.clone(), FUSE_ROOT_ID);
        for q in &mut self.queues {
            *q = VirtqState::new(QUEUE_SIZE);
        }
    }

    // ---- Queue processing ----

    /// Process a virtqueue notification. Returns true if used ring was updated.
    pub fn process_queue(&mut self, queue_idx: u32, memory: &mut [u8], ram_base: u64) -> bool {
        let qi = queue_idx as usize;
        if qi >= NUM_QUEUES {
            return false;
        }

        let q = self.queues[qi].clone();
        if !q.ready || q.num == 0 {
            return false;
        }

        let avail_idx = match read_avail_idx(memory, ram_base, q.avail_addr) {
            Some(idx) => idx,
            None => return false,
        };

        let mut last_avail = self.queues[qi].last_avail_idx;
        let mut used_count = 0u16;
        let used_idx_start = read_used_idx(memory, ram_base, q.used_addr).unwrap_or(0);

        while last_avail != avail_idx {
            let desc_head = match read_avail_ring(memory, ram_base, q.avail_addr, last_avail, q.num)
            {
                Some(d) => d,
                None => break,
            };

            let total_len = if qi == 0 {
                // Hiprio queue: FORGET operations (no response)
                self.process_hiprio_chain(memory, ram_base, &q, desc_head);
                0
            } else {
                // Request queue: normal FUSE operations
                self.process_request_chain(memory, ram_base, &q, desc_head)
            };

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

        self.queues[qi].last_avail_idx = last_avail;

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

    /// Process a hiprio descriptor chain (FORGET — no response needed).
    fn process_hiprio_chain(&mut self, memory: &[u8], ram_base: u64, q: &VirtqState, head: u16) {
        // Collect readable descriptors
        let mut request = Vec::new();
        let mut idx = head;
        while let Some((addr, len, flags, next)) =
            read_descriptor(memory, ram_base, q.desc_addr, idx)
        {
            if flags & VIRTQ_DESC_F_WRITE == 0 {
                let offset = match addr.checked_sub(ram_base) {
                    Some(o) => o as usize,
                    None => break,
                };
                let len = len as usize;
                if offset + len <= memory.len() {
                    request.extend_from_slice(&memory[offset..offset + len]);
                }
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }

        if request.len() < 40 {
            return;
        }
        let mut buf = ParseBuf::new(&request);
        let _len = buf.read_u32().unwrap();
        let opcode = buf.read_u32().unwrap();
        let _unique = buf.read_u64().unwrap();
        let nodeid = buf.read_u64().unwrap();
        buf.skip(12); // uid, gid, pid

        match opcode {
            FUSE_FORGET => {
                let nlookup = buf.read_u64().unwrap_or(1);
                self.do_forget(nodeid, nlookup);
            }
            FUSE_BATCH_FORGET => {
                let count = buf.read_u32().unwrap_or(0);
                buf.skip(4); // dummy
                for _ in 0..count {
                    let nid = buf.read_u64().unwrap_or(0);
                    let nl = buf.read_u64().unwrap_or(0);
                    if nid != 0 {
                        self.do_forget(nid, nl);
                    }
                }
            }
            _ => {
                warn!("virtiofs: unexpected opcode {opcode} on hiprio queue");
            }
        }
    }

    /// Process a request descriptor chain: read FUSE request, produce response.
    fn process_request_chain(
        &mut self,
        memory: &mut [u8],
        ram_base: u64,
        q: &VirtqState,
        head: u16,
    ) -> u32 {
        // Collect descriptors, separating readable (request) from writable (response)
        let mut readable: Vec<(u64, u32)> = Vec::new();
        let mut writable: Vec<(u64, u32)> = Vec::new();
        let mut idx = head;

        while let Some((addr, len, flags, next)) =
            read_descriptor(memory, ram_base, q.desc_addr, idx)
        {
            if flags & VIRTQ_DESC_F_WRITE != 0 {
                writable.push((addr, len));
            } else {
                readable.push((addr, len));
            }
            if flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }

        // Assemble the FUSE request from readable descriptors
        let mut request = Vec::new();
        for &(addr, len) in &readable {
            let offset = match addr.checked_sub(ram_base) {
                Some(o) => o as usize,
                None => return 0,
            };
            let len = len as usize;
            if offset + len > memory.len() {
                return 0;
            }
            request.extend_from_slice(&memory[offset..offset + len]);
        }

        // Process the FUSE message
        let response = self.handle_request(&request);

        // Write response to writable descriptors
        let mut resp_pos = 0;
        for &(addr, len) in &writable {
            let offset = match addr.checked_sub(ram_base) {
                Some(o) => o as usize,
                None => continue,
            };
            let len = len as usize;
            if offset + len > memory.len() {
                continue;
            }
            let copy_len = len.min(response.len() - resp_pos);
            if copy_len > 0 {
                memory[offset..offset + copy_len]
                    .copy_from_slice(&response[resp_pos..resp_pos + copy_len]);
            }
            resp_pos += copy_len;
            if resp_pos >= response.len() {
                break;
            }
        }

        response.len() as u32
    }

    // ---- FUSE message dispatch ----

    fn handle_request(&mut self, request: &[u8]) -> Vec<u8> {
        // fuse_in_header: len(4) + opcode(4) + unique(8) + nodeid(8) +
        //                 uid(4) + gid(4) + pid(4) + padding(4) = 40 bytes
        if request.len() < 40 {
            return make_error(0, EINVAL);
        }
        let mut buf = ParseBuf::new(request);
        let _len = buf.read_u32().unwrap();
        let opcode = buf.read_u32().unwrap();
        let unique = buf.read_u64().unwrap();
        let nodeid = buf.read_u64().unwrap();
        buf.skip(12); // uid, gid, pid
        buf.skip(4); // padding

        match opcode {
            FUSE_INIT => self.handle_init(&mut buf, unique),
            FUSE_DESTROY => self.handle_destroy(unique),
            FUSE_LOOKUP => self.handle_lookup(&mut buf, unique, nodeid),
            FUSE_FORGET => {
                let nlookup = buf.read_u64().unwrap_or(1);
                self.do_forget(nodeid, nlookup);
                // FORGET has no response — return empty vec so nothing is written
                Vec::new()
            }
            FUSE_BATCH_FORGET => {
                let count = buf.read_u32().unwrap_or(0);
                buf.skip(4); // dummy
                for _ in 0..count {
                    let nid = buf.read_u64().unwrap_or(0);
                    let nl = buf.read_u64().unwrap_or(0);
                    if nid != 0 {
                        self.do_forget(nid, nl);
                    }
                }
                Vec::new()
            }
            FUSE_GETATTR => self.handle_getattr(&mut buf, unique, nodeid),
            FUSE_SETATTR => self.handle_setattr(&mut buf, unique, nodeid),
            FUSE_OPEN => self.handle_open(&mut buf, unique, nodeid),
            FUSE_READ => self.handle_read(&mut buf, unique),
            FUSE_WRITE => self.handle_write(&mut buf, unique),
            FUSE_RELEASE => self.handle_release(&mut buf, unique),
            FUSE_FLUSH => self.handle_flush(&mut buf, unique),
            FUSE_FSYNC => self.handle_fsync(&mut buf, unique),
            FUSE_OPENDIR => self.handle_opendir(unique, nodeid),
            FUSE_READDIR => self.handle_readdir(&mut buf, unique),
            FUSE_READDIRPLUS => self.handle_readdirplus(&mut buf, unique),
            FUSE_RELEASEDIR => self.handle_releasedir(&mut buf, unique),
            FUSE_FSYNCDIR => self.handle_fsyncdir(unique),
            FUSE_CREATE => self.handle_create(&mut buf, unique, nodeid),
            FUSE_MKDIR => self.handle_mkdir(&mut buf, unique, nodeid),
            FUSE_UNLINK => self.handle_unlink(&mut buf, unique, nodeid),
            FUSE_RMDIR => self.handle_rmdir(&mut buf, unique, nodeid),
            FUSE_RENAME => self.handle_rename(&mut buf, unique, nodeid),
            FUSE_RENAME2 => self.handle_rename2(&mut buf, unique, nodeid),
            FUSE_SYMLINK => self.handle_symlink(&mut buf, unique, nodeid),
            FUSE_READLINK => self.handle_readlink(unique, nodeid),
            FUSE_LINK => self.handle_link(&mut buf, unique, nodeid),
            FUSE_STATFS => self.handle_statfs(unique),
            FUSE_ACCESS => self.handle_access(unique),
            // Extended attributes: return ENODATA (not supported on this filesystem)
            FUSE_GETXATTR | FUSE_LISTXATTR => make_error(unique, ENODATA),
            FUSE_SETXATTR | FUSE_REMOVEXATTR => make_error(unique, ENOSYS),
            _ => {
                warn!("virtiofs: unsupported opcode {opcode}");
                make_error(unique, ENOSYS)
            }
        }
    }

    // ---- FUSE protocol handlers ----

    fn handle_init(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        let major = buf.read_u32().unwrap_or(0);
        let minor = buf.read_u32().unwrap_or(0);
        let max_readahead = buf.read_u32().unwrap_or(0);
        let driver_flags = buf.read_u32().unwrap_or(0);

        debug!("virtiofs: INIT major={major} minor={minor} flags=0x{driver_flags:x}");

        if major != FUSE_KERNEL_VERSION {
            warn!("virtiofs: unsupported FUSE major version {major}");
            return make_error(unique, ENOSYS);
        }

        let negotiated_flags = driver_flags & FUSE_SUPPORTED_FLAGS;

        // fuse_init_out: 64 bytes
        let mut wb = WriteBuf::fuse_out(unique);
        wb.write_u32(FUSE_KERNEL_VERSION); // major
        wb.write_u32(FUSE_KERNEL_MINOR_VERSION); // minor
        wb.write_u32(max_readahead); // max_readahead (echo back)
        wb.write_u32(negotiated_flags); // flags
        wb.write_u16(0); // max_background
        wb.write_u16(0); // congestion_threshold
        wb.write_u32(MAX_WRITE_SIZE); // max_write
        wb.write_u32(1); // time_gran (nanosecond)
        wb.write_u16(0); // max_pages (default)
        wb.write_u16(0); // map_alignment
        wb.write_zeros(28); // flags2 + unused (7 * u32)
        wb.finish()
    }

    fn handle_destroy(&mut self, unique: u64) -> Vec<u8> {
        debug!("virtiofs: DESTROY");
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_lookup(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        // Security: reject path traversal
        if name.is_empty() || name.contains('/') || name == ".." {
            return make_error(unique, EINVAL);
        }

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let child_path = parent_path.join(&name);
        let meta = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let ino = self.lookup_or_create_inode(&child_path);
        // Increment nlookup for this inode
        if let Some(state) = self.inodes.get_mut(&ino) {
            state.nlookup = state.nlookup.saturating_add(1);
        }

        let mut wb = WriteBuf::fuse_out(unique);
        write_entry_out(&mut wb, ino, &meta);
        wb.finish()
    }

    fn handle_getattr(&self, buf: &mut ParseBuf, unique: u64, nodeid: u64) -> Vec<u8> {
        // fuse_getattr_in: getattr_flags(4) + dummy(4) + fh(8) = 16 bytes
        let _getattr_flags = buf.read_u32().unwrap_or(0);
        let _dummy = buf.read_u32();
        let _fh = buf.read_u64();

        let path = match self.inodes.get(&nodeid) {
            Some(s) => &s.host_path,
            None => return make_error(unique, ENOENT),
        };

        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let mut wb = WriteBuf::fuse_out(unique);
        write_attr_out(&mut wb, nodeid, &meta);
        wb.finish()
    }

    fn handle_setattr(&mut self, buf: &mut ParseBuf, unique: u64, nodeid: u64) -> Vec<u8> {
        // fuse_setattr_in: valid(4) + padding(4) + fh(8) + size(8) +
        //   lock_owner(8) + atime(8) + mtime(8) + ctime(8) +
        //   atimensec(4) + mtimensec(4) + ctimensec(4) + mode(4) +
        //   unused4(4) + uid(4) + gid(4) + unused5(4) = 88 bytes
        let valid = buf.read_u32().unwrap_or(0);
        buf.skip(4); // padding
        let _fh = buf.read_u64();
        let size = buf.read_u64().unwrap_or(0);
        buf.skip(8); // lock_owner
        let _atime = buf.read_u64();
        let _mtime = buf.read_u64();
        buf.skip(8); // ctime
        buf.skip(4); // atimensec
        buf.skip(4); // mtimensec
        buf.skip(4); // ctimensec
        let mode = buf.read_u32().unwrap_or(0);

        let path = match self.inodes.get(&nodeid) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        if valid & FATTR_MODE != 0 {
            let perm = std::fs::Permissions::from_mode(mode);
            if let Err(e) = std::fs::set_permissions(&path, perm) {
                return make_error(unique, io_error_to_errno(&e));
            }
        }

        if valid & FATTR_SIZE != 0 {
            let file = match std::fs::OpenOptions::new().write(true).open(&path) {
                Ok(f) => f,
                Err(e) => return make_error(unique, io_error_to_errno(&e)),
            };
            if let Err(e) = file.set_len(size) {
                return make_error(unique, io_error_to_errno(&e));
            }
        }

        // Re-stat after modifications
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let mut wb = WriteBuf::fuse_out(unique);
        write_attr_out(&mut wb, nodeid, &meta);
        wb.finish()
    }

    fn handle_open(&mut self, buf: &mut ParseBuf, unique: u64, nodeid: u64) -> Vec<u8> {
        // fuse_open_in: flags(4) + open_flags(4) = 8 bytes
        let flags = buf.read_u32().unwrap_or(0);

        let path = match self.inodes.get(&nodeid) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let mut opts = std::fs::OpenOptions::new();
        let access = flags & 3; // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
        match access {
            1 => {
                opts.write(true);
            }
            2 => {
                opts.read(true).write(true);
            }
            _ => {
                opts.read(true);
            }
        }
        if flags & 0o1000 != 0 {
            opts.truncate(true); // O_TRUNC
        }
        if flags & 0o2000 != 0 {
            opts.append(true); // O_APPEND
        }

        let file = match opts.open(&path) {
            Ok(f) => f,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let fh = self.alloc_handle(HandleState {
            inner: HandleInner::File(file),
        });

        // fuse_open_out: fh(8) + open_flags(4) + padding(4) = 16 bytes
        let mut wb = WriteBuf::fuse_out(unique);
        wb.write_u64(fh); // fh
        wb.write_u32(0); // open_flags (no special flags)
        wb.write_u32(0); // padding
        wb.finish()
    }

    fn handle_read(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_read_in: fh(8) + offset(8) + size(4) + ...
        let fh = buf.read_u64().unwrap_or(0);
        let offset = buf.read_u64().unwrap_or(0);
        let size = buf.read_u32().unwrap_or(0);

        let handle = match self.handles.get(&fh) {
            Some(h) => h,
            None => return make_error(unique, EBADF),
        };
        let file = match &handle.inner {
            HandleInner::File(f) => f,
            HandleInner::Dir(_) => return make_error(unique, EBADF),
        };

        let size = (size as usize).min(MAX_WRITE_SIZE as usize);
        let mut data = vec![0u8; size];
        let n = match file.read_at(&mut data, offset) {
            Ok(n) => n,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        // Response: out_header + data (no intermediate struct)
        let mut wb = WriteBuf::fuse_out(unique);
        wb.data.extend_from_slice(&data[..n]);
        wb.finish()
    }

    fn handle_write(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_write_in: fh(8) + offset(8) + size(4) + write_flags(4) +
        //                lock_owner(8) + flags(4) + padding(4) = 40 bytes
        let fh = buf.read_u64().unwrap_or(0);
        let offset = buf.read_u64().unwrap_or(0);
        let size = buf.read_u32().unwrap_or(0) as usize;
        buf.skip(4); // write_flags
        buf.skip(8); // lock_owner
        buf.skip(4); // flags
        buf.skip(4); // padding

        // Remaining bytes are the data to write
        let avail = buf.remaining().min(size);
        let data = buf.read_remaining();
        let write_data = &data[..avail];

        let handle = match self.handles.get(&fh) {
            Some(h) => h,
            None => return make_error(unique, EBADF),
        };
        let file = match &handle.inner {
            HandleInner::File(f) => f,
            HandleInner::Dir(_) => return make_error(unique, EBADF),
        };

        let n = match file.write_at(write_data, offset) {
            Ok(n) => n,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        // fuse_write_out: size(4) + padding(4) = 8 bytes
        let mut wb = WriteBuf::fuse_out(unique);
        wb.write_u32(n as u32);
        wb.write_u32(0); // padding
        wb.finish()
    }

    fn handle_release(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_release_in: fh(8) + flags(4) + release_flags(4) + lock_owner(8)
        let fh = buf.read_u64().unwrap_or(0);
        self.handles.remove(&fh);
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_flush(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_flush_in: fh(8) + unused(4) + padding(4) + lock_owner(8)
        let fh = buf.read_u64().unwrap_or(0);
        if let Some(h) = self.handles.get(&fh) {
            if let HandleInner::File(ref f) = h.inner {
                let _ = f.sync_all();
            }
        }
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_fsync(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_fsync_in: fh(8) + fsync_flags(4) + padding(4)
        let fh = buf.read_u64().unwrap_or(0);
        let fsync_flags = buf.read_u32().unwrap_or(0);
        if let Some(h) = self.handles.get(&fh) {
            if let HandleInner::File(ref f) = h.inner {
                let result = if fsync_flags & 1 != 0 {
                    f.sync_data() // FUSE_FSYNC_FDATASYNC
                } else {
                    f.sync_all()
                };
                if let Err(e) = result {
                    return make_error(unique, io_error_to_errno(&e));
                }
            }
        }
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_opendir(&mut self, unique: u64, nodeid: u64) -> Vec<u8> {
        let path = match self.inodes.get(&nodeid) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        // Verify it's a directory
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return make_error(unique, ENOTDIR),
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        }

        let fh = self.alloc_handle(HandleState {
            inner: HandleInner::Dir(path),
        });

        let mut wb = WriteBuf::fuse_out(unique);
        wb.write_u64(fh); // fh
        wb.write_u32(0); // open_flags
        wb.write_u32(0); // padding
        wb.finish()
    }

    fn handle_readdir(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_read_in: fh(8) + offset(8) + size(4) + ...
        let fh = buf.read_u64().unwrap_or(0);
        let dir_offset = buf.read_u64().unwrap_or(0);
        let size = buf.read_u32().unwrap_or(0) as usize;

        let dir_path = match self.handles.get(&fh) {
            Some(h) => match &h.inner {
                HandleInner::Dir(p) => p.clone(),
                HandleInner::File(_) => return make_error(unique, EBADF),
            },
            None => return make_error(unique, EBADF),
        };

        let entries = self.collect_dir_entries(&dir_path);

        // Build packed fuse_dirent data from dir_offset
        let start = dir_offset as usize;
        let mut data = Vec::new();

        for (i, (name, ino, dtype)) in entries.iter().enumerate() {
            if i < start {
                continue;
            }
            let namelen = name.len();
            // fuse_dirent: ino(8) + off(8) + namelen(4) + type(4) + name + padding
            let padded_namelen = (namelen + 7) & !7;
            let entry_len = 24 + padded_namelen;
            if data.len() + entry_len > size {
                break;
            }

            data.extend_from_slice(&ino.to_le_bytes()); // ino
            data.extend_from_slice(&((i + 1) as u64).to_le_bytes()); // off (next offset)
            data.extend_from_slice(&(namelen as u32).to_le_bytes()); // namelen
            data.extend_from_slice(&(*dtype as u32).to_le_bytes()); // type
            data.extend_from_slice(name.as_bytes());
            // Pad to 8-byte alignment
            let pad = padded_namelen - namelen;
            data.extend(std::iter::repeat_n(0u8, pad));
        }

        let mut wb = WriteBuf::fuse_out(unique);
        wb.data.extend_from_slice(&data);
        wb.finish()
    }

    fn handle_readdirplus(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        // fuse_read_in: fh(8) + offset(8) + size(4) + ...
        let fh = buf.read_u64().unwrap_or(0);
        let dir_offset = buf.read_u64().unwrap_or(0);
        let size = buf.read_u32().unwrap_or(0) as usize;

        let dir_path = match self.handles.get(&fh) {
            Some(h) => match &h.inner {
                HandleInner::Dir(p) => p.clone(),
                HandleInner::File(_) => return make_error(unique, EBADF),
            },
            None => return make_error(unique, EBADF),
        };

        let entries = self.collect_dir_entries_with_meta(&dir_path);

        let start = dir_offset as usize;
        let mut data = Vec::new();

        for (i, (name, child_path, meta)) in entries.iter().enumerate() {
            if i < start {
                continue;
            }
            let namelen = name.len();
            let padded_namelen = (namelen + 7) & !7;
            // fuse_direntplus: fuse_entry_out(128) + fuse_dirent(24 + padded_name)
            let entry_len = 128 + 24 + padded_namelen;
            if data.len() + entry_len > size {
                break;
            }

            let ino = self.lookup_or_create_inode(child_path);
            // Increment nlookup for READDIRPLUS entries
            if let Some(state) = self.inodes.get_mut(&ino) {
                state.nlookup = state.nlookup.saturating_add(1);
            }

            let dtype: u32 = if meta.is_dir() {
                4 // DT_DIR
            } else if meta.file_type().is_symlink() {
                10 // DT_LNK
            } else {
                8 // DT_REG
            };

            // Write fuse_entry_out (128 bytes)
            let mut entry_wb = WriteBuf::new();
            write_entry_out(&mut entry_wb, ino, meta);
            data.extend_from_slice(&entry_wb.data);

            // Write fuse_dirent
            data.extend_from_slice(&ino.to_le_bytes()); // ino
            data.extend_from_slice(&((i + 1) as u64).to_le_bytes()); // off
            data.extend_from_slice(&(namelen as u32).to_le_bytes()); // namelen
            data.extend_from_slice(&dtype.to_le_bytes()); // type
            data.extend_from_slice(name.as_bytes());
            let pad = padded_namelen - namelen;
            data.extend(std::iter::repeat_n(0u8, pad));
        }

        let mut wb = WriteBuf::fuse_out(unique);
        wb.data.extend_from_slice(&data);
        wb.finish()
    }

    fn handle_releasedir(&mut self, buf: &mut ParseBuf, unique: u64) -> Vec<u8> {
        let fh = buf.read_u64().unwrap_or(0);
        self.handles.remove(&fh);
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_fsyncdir(&self, unique: u64) -> Vec<u8> {
        // Nothing to sync for directories in our implementation
        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_create(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        // fuse_create_in: flags(4) + mode(4) + umask(4) + open_flags(4) = 16 bytes
        let flags = buf.read_u32().unwrap_or(0);
        let mode = buf.read_u32().unwrap_or(0o644);
        buf.skip(4); // umask
        buf.skip(4); // open_flags
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        if name.is_empty() || name.contains('/') || name == ".." {
            return make_error(unique, EINVAL);
        }

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let new_path = parent_path.join(&name);

        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true);
        let access = flags & 3;
        if access == 0 || access == 2 {
            opts.read(true);
        }
        if flags & 0o1000 != 0 {
            opts.truncate(true);
        }

        let file = match opts.open(&new_path) {
            Ok(f) => f,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        // Set permissions
        let perm = std::fs::Permissions::from_mode(mode);
        let _ = std::fs::set_permissions(&new_path, perm);

        let meta = match std::fs::symlink_metadata(&new_path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let ino = self.lookup_or_create_inode(&new_path);
        if let Some(state) = self.inodes.get_mut(&ino) {
            state.nlookup = state.nlookup.saturating_add(1);
        }

        let fh = self.alloc_handle(HandleState {
            inner: HandleInner::File(file),
        });

        // Response: fuse_entry_out (128) + fuse_open_out (16)
        let mut wb = WriteBuf::fuse_out(unique);
        write_entry_out(&mut wb, ino, &meta);
        wb.write_u64(fh); // fh
        wb.write_u32(0); // open_flags
        wb.write_u32(0); // padding
        wb.finish()
    }

    fn handle_mkdir(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        // fuse_mkdir_in: mode(4) + umask(4) = 8 bytes, followed by name\0
        let mode = buf.read_u32().unwrap_or(0o755);
        buf.skip(4); // umask
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        if name.is_empty() || name.contains('/') || name == ".." {
            return make_error(unique, EINVAL);
        }

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let new_dir = parent_path.join(&name);
        if let Err(e) = std::fs::create_dir(&new_dir) {
            return make_error(unique, io_error_to_errno(&e));
        }

        let perm = std::fs::Permissions::from_mode(mode);
        let _ = std::fs::set_permissions(&new_dir, perm);

        let meta = match std::fs::symlink_metadata(&new_dir) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let ino = self.lookup_or_create_inode(&new_dir);
        if let Some(state) = self.inodes.get_mut(&ino) {
            state.nlookup = state.nlookup.saturating_add(1);
        }

        let mut wb = WriteBuf::fuse_out(unique);
        write_entry_out(&mut wb, ino, &meta);
        wb.finish()
    }

    fn handle_unlink(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let target = parent_path.join(&name);
        if let Err(e) = std::fs::remove_file(&target) {
            return make_error(unique, io_error_to_errno(&e));
        }

        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_rmdir(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let target = parent_path.join(&name);
        if let Err(e) = std::fs::remove_dir(&target) {
            return make_error(unique, io_error_to_errno(&e));
        }

        WriteBuf::fuse_out(unique).finish()
    }

    fn handle_rename(&mut self, buf: &mut ParseBuf, unique: u64, old_parent: u64) -> Vec<u8> {
        // fuse_rename_in: newdir(8), followed by oldname\0 newname\0
        let new_parent = buf.read_u64().unwrap_or(0);
        let oldname = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };
        let newname = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        self.do_rename(unique, old_parent, &oldname, new_parent, &newname)
    }

    fn handle_rename2(&mut self, buf: &mut ParseBuf, unique: u64, old_parent: u64) -> Vec<u8> {
        // fuse_rename2_in: newdir(8) + flags(4) + padding(4), followed by oldname\0 newname\0
        let new_parent = buf.read_u64().unwrap_or(0);
        buf.skip(4); // flags (RENAME_NOREPLACE etc. — ignore for now)
        buf.skip(4); // padding
        let oldname = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };
        let newname = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        self.do_rename(unique, old_parent, &oldname, new_parent, &newname)
    }

    fn handle_symlink(&mut self, buf: &mut ParseBuf, unique: u64, parent: u64) -> Vec<u8> {
        // SYMLINK payload: name\0target\0
        let name = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };
        let target = match buf.read_cstr() {
            Some(t) => t,
            None => return make_error(unique, EINVAL),
        };

        if name.is_empty() || name.contains('/') || name == ".." {
            return make_error(unique, EINVAL);
        }

        let parent_path = match self.inodes.get(&parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let link_path = parent_path.join(&name);
        if let Err(e) = std::os::unix::fs::symlink(&target, &link_path) {
            return make_error(unique, io_error_to_errno(&e));
        }

        let meta = match std::fs::symlink_metadata(&link_path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        let ino = self.lookup_or_create_inode(&link_path);
        if let Some(state) = self.inodes.get_mut(&ino) {
            state.nlookup = state.nlookup.saturating_add(1);
        }

        let mut wb = WriteBuf::fuse_out(unique);
        write_entry_out(&mut wb, ino, &meta);
        wb.finish()
    }

    fn handle_readlink(&self, unique: u64, nodeid: u64) -> Vec<u8> {
        let path = match self.inodes.get(&nodeid) {
            Some(s) => &s.host_path,
            None => return make_error(unique, ENOENT),
        };

        let target = match std::fs::read_link(path) {
            Ok(t) => t,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        // Response: out_header + raw target path bytes (no null terminator)
        let target_bytes = target.to_string_lossy();
        let mut wb = WriteBuf::fuse_out(unique);
        wb.data.extend_from_slice(target_bytes.as_bytes());
        wb.finish()
    }

    fn handle_link(&mut self, buf: &mut ParseBuf, unique: u64, new_parent: u64) -> Vec<u8> {
        // fuse_link_in: oldnodeid(8), followed by newname\0
        let oldnodeid = buf.read_u64().unwrap_or(0);
        let newname = match buf.read_cstr() {
            Some(n) => n,
            None => return make_error(unique, EINVAL),
        };

        if newname.is_empty() || newname.contains('/') || newname == ".." {
            return make_error(unique, EINVAL);
        }

        let old_path = match self.inodes.get(&oldnodeid) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let new_parent_path = match self.inodes.get(&new_parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let link_path = new_parent_path.join(&newname);
        if let Err(e) = std::fs::hard_link(&old_path, &link_path) {
            return make_error(unique, io_error_to_errno(&e));
        }

        let meta = match std::fs::symlink_metadata(&link_path) {
            Ok(m) => m,
            Err(e) => return make_error(unique, io_error_to_errno(&e)),
        };

        // For hard links, reuse the existing inode (same underlying file)
        let ino = self.lookup_or_create_inode(&link_path);
        if let Some(state) = self.inodes.get_mut(&ino) {
            state.nlookup = state.nlookup.saturating_add(1);
        }

        let mut wb = WriteBuf::fuse_out(unique);
        write_entry_out(&mut wb, ino, &meta);
        wb.finish()
    }

    fn handle_statfs(&self, unique: u64) -> Vec<u8> {
        // fuse_kstatfs: blocks(8) + bfree(8) + bavail(8) + files(8) + ffree(8) +
        //   bsize(4) + namelen(4) + frsize(4) + padding(4) + spare(24) = 80 bytes
        let mut wb = WriteBuf::fuse_out(unique);
        wb.write_u64(1 << 20); // blocks (~4 GB)
        wb.write_u64(1 << 19); // bfree
        wb.write_u64(1 << 19); // bavail
        wb.write_u64(1 << 20); // files
        wb.write_u64(1 << 19); // ffree
        wb.write_u32(4096); // bsize
        wb.write_u32(255); // namelen
        wb.write_u32(4096); // frsize
        wb.write_u32(0); // padding
        wb.write_zeros(24); // spare
        wb.finish()
    }

    fn handle_access(&self, unique: u64) -> Vec<u8> {
        // Allow all access (we don't enforce permissions)
        WriteBuf::fuse_out(unique).finish()
    }

    // ---- Helper methods ----

    /// Decrement the nlookup count for an inode. Evicts when it reaches 0.
    fn do_forget(&mut self, nodeid: u64, nlookup: u64) {
        // Never forget the root inode
        if nodeid == FUSE_ROOT_ID {
            return;
        }
        if let Some(state) = self.inodes.get_mut(&nodeid) {
            state.nlookup = state.nlookup.saturating_sub(nlookup);
            if state.nlookup == 0 {
                let path = state.host_path.clone();
                self.inodes.remove(&nodeid);
                self.path_to_inode.remove(&path);
            }
        }
    }

    /// Shared rename logic for RENAME and RENAME2.
    fn do_rename(
        &mut self,
        unique: u64,
        old_parent: u64,
        oldname: &str,
        new_parent: u64,
        newname: &str,
    ) -> Vec<u8> {
        let old_parent_path = match self.inodes.get(&old_parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };
        let new_parent_path = match self.inodes.get(&new_parent) {
            Some(s) => s.host_path.clone(),
            None => return make_error(unique, ENOENT),
        };

        let old_path = old_parent_path.join(oldname);
        let new_path = new_parent_path.join(newname);

        if let Err(e) = std::fs::rename(&old_path, &new_path) {
            return make_error(unique, io_error_to_errno(&e));
        }

        // Update inode path mapping if we tracked this inode
        if let Some(&ino) = self.path_to_inode.get(&old_path) {
            self.path_to_inode.remove(&old_path);
            self.path_to_inode.insert(new_path.clone(), ino);
            if let Some(state) = self.inodes.get_mut(&ino) {
                state.host_path = new_path;
            }
        }

        WriteBuf::fuse_out(unique).finish()
    }

    /// Look up or allocate an inode number for a host path.
    fn lookup_or_create_inode(&mut self, path: &Path) -> u64 {
        if let Some(&ino) = self.path_to_inode.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes.insert(
            ino,
            InodeState {
                host_path: path.to_path_buf(),
                nlookup: 0,
            },
        );
        self.path_to_inode.insert(path.to_path_buf(), ino);
        ino
    }

    /// Allocate a file handle.
    fn alloc_handle(&mut self, state: HandleState) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, state);
        fh
    }

    /// Collect directory entries as (name, inode, dtype) tuples.
    fn collect_dir_entries(&self, dir_path: &Path) -> Vec<(String, u64, u8)> {
        let mut entries = Vec::new();

        // "." entry
        if let Some(&ino) = self.path_to_inode.get(dir_path) {
            entries.push((".".to_string(), ino, 4)); // DT_DIR
        }

        // ".." entry
        let parent = dir_path.parent().unwrap_or(dir_path);
        let parent_path = if parent.starts_with(&self.root_path) {
            parent
        } else {
            &self.root_path
        };
        if let Some(&ino) = self.path_to_inode.get(parent_path) {
            entries.push(("..".to_string(), ino, 4)); // DT_DIR
        }

        if let Ok(rd) = std::fs::read_dir(dir_path) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let entry_path = dir_path.join(&name);
                if let Ok(meta) = std::fs::symlink_metadata(&entry_path) {
                    // Use host inode as FUSE inode for readdir (readdir doesn't
                    // create inode references, so we don't allocate here)
                    let ino = meta.ino();
                    let dtype = if meta.is_dir() {
                        4 // DT_DIR
                    } else if meta.file_type().is_symlink() {
                        10 // DT_LNK
                    } else {
                        8 // DT_REG
                    };
                    entries.push((name, ino, dtype));
                }
            }
        }

        entries
    }

    /// Collect directory entries with full metadata for READDIRPLUS.
    fn collect_dir_entries_with_meta(
        &self,
        dir_path: &Path,
    ) -> Vec<(String, PathBuf, std::fs::Metadata)> {
        let mut entries = Vec::new();

        // "." entry
        if let Ok(meta) = std::fs::symlink_metadata(dir_path) {
            entries.push((".".to_string(), dir_path.to_path_buf(), meta));
        }

        // ".." entry
        let parent = dir_path.parent().unwrap_or(dir_path);
        let parent_path = if parent.starts_with(&self.root_path) {
            parent.to_path_buf()
        } else {
            self.root_path.clone()
        };
        if let Ok(meta) = std::fs::symlink_metadata(&parent_path) {
            entries.push(("..".to_string(), parent_path, meta));
        }

        if let Ok(rd) = std::fs::read_dir(dir_path) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let entry_path = dir_path.join(&name);
                if let Ok(meta) = std::fs::symlink_metadata(&entry_path) {
                    entries.push((name, entry_path, meta));
                }
            }
        }

        entries
    }
}

/// Convert a Rust I/O error to a Linux errno value.
fn io_error_to_errno(e: &std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::NotFound => ENOENT,
        std::io::ErrorKind::PermissionDenied => EACCES,
        std::io::ErrorKind::AlreadyExists => EEXIST,
        std::io::ErrorKind::InvalidInput => EINVAL,
        std::io::ErrorKind::Unsupported => EOPNOTSUPP,
        _ => e.raw_os_error().unwrap_or(EIO),
    }
}
