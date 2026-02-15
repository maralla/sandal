/// VM snapshot save/restore for instant boot.
///
/// Saves the complete VM state (memory, vCPU registers, virtio device MMIO
/// state) to a file after the kernel finishes booting.  On subsequent runs,
/// the snapshot is restored instead of re-booting, reducing startup from
/// ~250ms to ~5ms.
///
/// File format (all little-endian):
///   [Header]           — magic, version, sizes, fingerprint
///   [CpuState]         — all GPR + system registers + vtimer
///   [DeviceState]      — UART type, virtio MMIO state
///   [Memory]           — raw guest RAM (sparse on disk via seek-over-zeros)
use anyhow::{Context, Result};
use log::debug;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr;

use crate::hypervisor::{HvGicIccReg, HvReg, HvSysReg, Vcpu};
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::console::VirtioConsoleDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;

extern "C" {
    fn mach_absolute_time() -> u64;
}

// ── Snapshot file format ──────────────────────────────────────────────

/// Bump this version whenever the snapshot format or the init binary changes
/// to automatically invalidate stale caches.
const SNAPSHOT_VERSION: u32 = 11;
const SNAPSHOT_MAGIC: u32 = 0x534E4150; // "SNAP"
/// Page size for snapshot memory alignment.  macOS on Apple Silicon uses
/// 16 KB pages, so the memory section offset in the snapshot file must be
/// 16 KB-aligned for `mmap(MAP_PRIVATE)` to work.
const PAGE_SIZE: usize = 16384;

/// Fixed-size header at the start of the snapshot file.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SnapshotHeader {
    magic: u32,
    version: u32,
    memory_size: u64,
    fingerprint: u64,
    cpu_state_offset: u64,
    cpu_state_size: u64,
    device_state_offset: u64,
    device_state_size: u64,
    memory_offset: u64,
}

/// All vCPU register state needed for restore.
///
/// `#[repr(C)]` layout allows zero-cost serialization as a raw byte cast
/// (same approach as `SnapshotHeader`).  All fields are u64 so there are
/// no padding holes.  This is ARM64 macOS only (always little-endian).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuState {
    // General-purpose registers
    pub x: [u64; 31], // X0-X30
    pub pc: u64,
    pub cpsr: u64,
    pub fpcr: u64,
    pub fpsr: u64,

    // System registers
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub sctlr_el1: u64,
    pub cpacr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub spsr_el1: u64,
    pub elr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub vbar_el1: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub tpidr_el1: u64,
    pub mpidr_el1: u64,
    pub mdscr_el1: u64,
    pub contextidr_el1: u64,
    pub par_el1: u64,
    pub cntkctl_el1: u64,
    pub cntv_ctl_el0: u64,
    pub cntv_cval_el0: u64,

    // VTimer
    pub vtimer_offset: u64,
    pub vtimer_mask: u64, // 0 or 1; widened from u8 to avoid repr(C) padding

    /// Physical counter (CNTPCT) value at snapshot time.
    /// Used to adjust vtimer_offset on restore so the guest virtual counter
    /// appears continuous (no time jump).
    pub saved_cntpct: u64,

    // GIC ICC (CPU Interface) registers.
    // These are separate from system registers and require the dedicated
    // hv_gic_{get,set}_icc_reg API.  Without restoring them, the GIC CPU
    // interface stays in its default state (ICC_PMR=0, IGRPEN=0) after
    // vCPU creation, effectively disabling all interrupt delivery.
    pub icc_pmr_el1: u64,
    pub icc_bpr0_el1: u64,
    pub icc_bpr1_el1: u64,
    pub icc_ctlr_el1: u64,
    pub icc_sre_el1: u64,
    pub icc_igrpen0_el1: u64,
    pub icc_igrpen1_el1: u64,
    pub icc_ap0r0_el1: u64,
    pub icc_ap1r0_el1: u64,
}

/// Serialized virtio queue state.
#[derive(Clone, Debug, Default)]
pub struct VirtqSnapshot {
    pub num_max: u32,
    pub num: u32,
    pub ready: u8,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
    pub last_avail_idx: u16,
}

/// Virtio device MMIO state (shared by all device types).
#[derive(Clone, Debug, Default)]
pub struct VirtioMmioSnapshot {
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub status: u32,
    pub interrupt_status: u32,
    pub config_generation: u32,
    pub queues: Vec<VirtqSnapshot>,
}

/// All device state needed for restore.
#[derive(Clone, Debug)]
pub struct DeviceState {
    pub network_enabled: bool,
    pub net_mmio: Option<VirtioMmioSnapshot>,
    pub rng_mmio: Option<VirtioMmioSnapshot>,
    pub blk_mmio: Option<VirtioMmioSnapshot>,
    pub use_virtio_blk: bool,
    pub fs_mmio: Vec<VirtioMmioSnapshot>, // virtiofs device MMIO state (one per --share)
    pub gic_state: Option<Vec<u8>>,       // Opaque GIC state blob (macOS 15+)
    pub data_blk_mmio: Option<VirtioMmioSnapshot>, // Overlay data disk (--disk-size)
    pub console_mmio: Option<VirtioMmioSnapshot>, // Virtio-console MMIO state
}

// ── Save ──────────────────────────────────────────────────────────────

/// Check if a memory page is all zeros using u128 word comparisons.
/// ~16x fewer loop iterations than byte-by-byte (`page.iter().all()`).
#[inline]
fn is_zero_page(page: &[u8]) -> bool {
    page.chunks_exact(16)
        .all(|c| u128::from_ne_bytes(c.try_into().unwrap()) == 0)
}

/// Save the complete VM state to a snapshot file directly from memory.
/// Used in forked child processes where memory is accessed via COW.
pub fn save_snapshot(
    path: &Path,
    memory: &[u8],
    cpu_state: &CpuState,
    device_state: &DeviceState,
    fingerprint: u64,
) -> Result<()> {
    let cpu_bytes = cpu_state_as_bytes(cpu_state);
    let device_bytes = serialize_device_state(device_state);

    let memory_size = memory.len() as u64;
    let cpu_state_offset = mem::size_of::<SnapshotHeader>() as u64;
    let device_state_offset = cpu_state_offset + cpu_bytes.len() as u64;
    let memory_offset = device_state_offset + device_bytes.len() as u64;
    let memory_offset = (memory_offset + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);

    let header = SnapshotHeader {
        magic: SNAPSHOT_MAGIC,
        version: SNAPSHOT_VERSION,
        memory_size,
        fingerprint,
        cpu_state_offset,
        cpu_state_size: cpu_bytes.len() as u64,
        device_state_offset,
        device_state_size: device_bytes.len() as u64,
        memory_offset,
    };

    let tmp_path = path.with_extension("tmp");
    let file = File::create(&tmp_path).context("Failed to create snapshot file")?;

    // Write header
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            mem::size_of::<SnapshotHeader>(),
        )
    };
    file.write_all_at(header_bytes, 0)?;
    file.write_all_at(cpu_bytes, cpu_state_offset)?;
    file.write_all_at(&device_bytes, device_state_offset)?;

    // Write memory (sparse: skip zero pages, batch contiguous non-zero runs).
    // We scan the entire memory region because the kernel's buddy allocator
    // can place page tables and other critical structures anywhere in RAM.
    // Zero pages are skipped (not written), keeping the file sparse.
    let scan_bytes = memory.len();
    let num_pages = scan_bytes / PAGE_SIZE;
    let mut written_pages = 0u64;
    let mut run_start: Option<usize> = None;

    for page_idx in 0..=num_pages {
        let is_nonzero = if page_idx < num_pages {
            let offset = page_idx * PAGE_SIZE;
            !is_zero_page(&memory[offset..offset + PAGE_SIZE])
        } else {
            false
        };

        if is_nonzero {
            written_pages += 1;
            if run_start.is_none() {
                run_start = Some(page_idx);
            }
        } else if let Some(start) = run_start {
            let byte_start = start * PAGE_SIZE;
            let byte_end = page_idx * PAGE_SIZE;
            file.write_all_at(
                &memory[byte_start..byte_end],
                memory_offset + byte_start as u64,
            )?;
            run_start = None;
        }
    }

    file.set_len(memory_offset + memory_size)?;
    drop(file);
    fs::rename(&tmp_path, path)?;

    debug!(
        "Snapshot saved: {} pages written ({} MB of {} MB), file size = {} MB",
        written_pages,
        written_pages * PAGE_SIZE as u64 / (1024 * 1024),
        memory_size / (1024 * 1024),
        (memory_offset + memory_size) / (1024 * 1024),
    );

    Ok(())
}

// ── Restore ───────────────────────────────────────────────────────────

/// Restored snapshot: CPU/device state plus a **COW (MAP_PRIVATE)** mapping
/// of the guest memory region.  The COW mapping avoids copying the entire
/// guest RAM upfront — only pages the guest actually modifies are faulted
/// and copied by the kernel on demand.
pub struct SnapshotRestore {
    /// Copy-on-write mapping of the memory region in the snapshot file.
    /// Writable (MAP_PRIVATE): writes create private pages, file unchanged.
    pub memory: memmap2::MmapMut,
    pub cpu_state: CpuState,
    pub device_state: DeviceState,
    pub memory_size: usize,
}

/// Load a snapshot file for restore.  Returns the parsed state and a
/// COW mmap of the memory region (no memcpy — pages are faulted lazily).
pub fn load_snapshot(path: &Path, expected_fingerprint: u64) -> Result<SnapshotRestore> {
    let file = File::open(path).context("Failed to open snapshot file")?;
    let file_len = file.metadata()?.len() as usize;

    // Read header via pread() — avoids creating a full read-only mmap
    // just to parse ~1KB of metadata (eliminates an mmap+munmap pair
    // and their page-table setup/teardown overhead).
    let header_size = mem::size_of::<SnapshotHeader>();
    if file_len < header_size {
        anyhow::bail!("Snapshot file too small");
    }
    let mut header_buf = [0u8; mem::size_of::<SnapshotHeader>()];
    file.read_at(&mut header_buf, 0)
        .context("Failed to read snapshot header")?;
    let header: SnapshotHeader = unsafe { ptr::read(header_buf.as_ptr() as *const _) };

    if header.magic != SNAPSHOT_MAGIC {
        anyhow::bail!(
            "Invalid snapshot magic: 0x{:08x} (expected 0x{SNAPSHOT_MAGIC:08x})",
            header.magic
        );
    }
    if header.version != SNAPSHOT_VERSION {
        anyhow::bail!(
            "Unsupported snapshot version: {} (expected {SNAPSHOT_VERSION})",
            header.version
        );
    }
    if header.fingerprint != expected_fingerprint {
        anyhow::bail!("Snapshot fingerprint mismatch (stale snapshot)");
    }

    // Read CPU + device state in a single pread() call — they're
    // contiguous in the file and together only ~1KB.
    let state_start = header.cpu_state_offset as usize;
    let state_end = header.device_state_offset as usize + header.device_state_size as usize;
    if state_end > file_len {
        anyhow::bail!("Snapshot state extends past end of file");
    }
    let mut state_buf = vec![0u8; state_end - state_start];
    file.read_at(&mut state_buf, state_start as u64)
        .context("Failed to read snapshot state")?;

    // Parse CPU state from the combined buffer (zero-cost: just a ptr::read)
    let cpu_local_end = header.cpu_state_size as usize;
    let cpu_state = cpu_state_from_bytes(&state_buf[..cpu_local_end])?;

    // Parse device state from the combined buffer
    let dev_local_start = header.device_state_offset as usize - state_start;
    let dev_local_end = dev_local_start + header.device_state_size as usize;
    let device_state = deserialize_device_state(&state_buf[dev_local_start..dev_local_end])?;

    let memory_offset = header.memory_offset as usize;
    let memory_size = header.memory_size as usize;

    if memory_offset + memory_size > file_len {
        anyhow::bail!("Snapshot memory extends past end of file");
    }

    // Create a copy-on-write (MAP_PRIVATE) mapping of just the memory
    // region.  This avoids reading/copying 256 MB upfront — pages are
    // faulted lazily from the file and only truly copied when written.
    let memory = unsafe {
        memmap2::MmapOptions::new()
            .offset(memory_offset as u64)
            .len(memory_size)
            .map_copy(&file)?
    };

    debug!(
        "Snapshot loaded: memory_size={} MB, memory_offset=0x{memory_offset:x} (COW mmap)",
        memory_size / (1024 * 1024),
    );

    Ok(SnapshotRestore {
        memory,
        cpu_state,
        device_state,
        memory_size,
    })
}

/// Restore vCPU register state from a CpuState.
pub fn restore_cpu_state(vcpu: &Vcpu, state: &CpuState) -> Result<()> {
    // GPRs
    for i in 0..31u8 {
        if let Some(reg) = HvReg::from_gpr(i) {
            vcpu.write_register(reg, state.x[i as usize])?;
        }
    }
    vcpu.write_register(HvReg::Pc, state.pc)?;
    vcpu.write_register(HvReg::Cpsr, state.cpsr)?;
    vcpu.write_register(HvReg::Fpcr, state.fpcr)?;
    vcpu.write_register(HvReg::Fpsr, state.fpsr)?;

    // System registers
    vcpu.write_sys_register(HvSysReg::SpEl0, state.sp_el0)?;
    vcpu.write_sys_register(HvSysReg::SpEl1, state.sp_el1)?;
    vcpu.write_sys_register(HvSysReg::SctlrEl1, state.sctlr_el1)?;
    vcpu.write_sys_register(HvSysReg::CpacrEl1, state.cpacr_el1)?;
    vcpu.write_sys_register(HvSysReg::Ttbr0El1, state.ttbr0_el1)?;
    vcpu.write_sys_register(HvSysReg::Ttbr1El1, state.ttbr1_el1)?;
    vcpu.write_sys_register(HvSysReg::TcrEl1, state.tcr_el1)?;
    vcpu.write_sys_register(HvSysReg::MairEl1, state.mair_el1)?;
    vcpu.write_sys_register(HvSysReg::SpsrEl1, state.spsr_el1)?;
    vcpu.write_sys_register(HvSysReg::ElrEl1, state.elr_el1)?;
    vcpu.write_sys_register(HvSysReg::EsrEl1, state.esr_el1)?;
    vcpu.write_sys_register(HvSysReg::FarEl1, state.far_el1)?;
    vcpu.write_sys_register(HvSysReg::VbarEl1, state.vbar_el1)?;
    vcpu.write_sys_register(HvSysReg::TpidrEl0, state.tpidr_el0)?;
    vcpu.write_sys_register(HvSysReg::TpidrroEl0, state.tpidrro_el0)?;
    vcpu.write_sys_register(HvSysReg::TpidrEl1, state.tpidr_el1)?;
    vcpu.write_sys_register(HvSysReg::MpidrEl1, state.mpidr_el1)?;
    vcpu.write_sys_register(HvSysReg::MdscrEl1, state.mdscr_el1)?;
    vcpu.write_sys_register(HvSysReg::ContextidrEl1, state.contextidr_el1)?;
    vcpu.write_sys_register(HvSysReg::ParEl1, state.par_el1)?;
    vcpu.write_sys_register(HvSysReg::CntkctlEl1, state.cntkctl_el1)?;
    vcpu.write_sys_register(HvSysReg::CntvCtlEl0, state.cntv_ctl_el0)?;
    vcpu.write_sys_register(HvSysReg::CntvCvalEl0, state.cntv_cval_el0)?;

    // VTimer: adjust the offset so the guest virtual counter appears
    // continuous — as if no time passed while the VM was suspended.
    //
    // The virtual counter = physical_counter - vtimer_offset.  By
    // increasing the offset by the elapsed physical time since the
    // snapshot was taken, the virtual counter resumes from the same
    // value it had at snapshot time.  This keeps CNTV_CVAL in the
    // future (relative to the virtual counter), preventing the vtimer
    // from firing immediately on restore.
    //
    // Without this adjustment the virtual counter jumps forward by the
    // wall-clock time elapsed, all pending timers appear past-due, and
    // the vtimer fires immediately — potentially causing a storm of
    // spurious timer interrupts that degrades performance or hangs
    // the guest.
    let current_cntpct = unsafe { mach_absolute_time() };
    let adjusted_offset = if state.saved_cntpct != 0 {
        // new_offset = old_offset + (current_phys - saved_phys)
        // This makes: virt_counter_now = phys_now - new_offset
        //           = phys_now - old_offset - (phys_now - phys_saved)
        //           = phys_saved - old_offset
        //           = virt_counter_at_snapshot
        state
            .vtimer_offset
            .wrapping_add(current_cntpct.wrapping_sub(state.saved_cntpct))
    } else {
        // Fallback for old snapshots without saved_cntpct
        state.vtimer_offset
    };
    vcpu.set_vtimer_offset(adjusted_offset)?;
    vcpu.set_vtimer_mask(state.vtimer_mask != 0)?;
    log::debug!(
        "vtimer: offset={} (adjusted from {}), mask={}, CNTV_CTL=0x{:x}, CNTV_CVAL=0x{:x}",
        adjusted_offset,
        state.vtimer_offset,
        state.vtimer_mask,
        state.cntv_ctl_el0,
        state.cntv_cval_el0,
    );

    // GIC ICC (CPU interface) registers.
    // These must be restored AFTER the GIC distributor/redistributor state
    // (via hv_gic_set_state) because they configure the per-CPU interrupt
    // priority mask (PMR), group enables, and active priorities.  Without
    // these, the CPU interface stays in its default state (all interrupts
    // masked/disabled) and no interrupts can be delivered to the vCPU.
    //
    // Note: we restore these here (before the GIC state blob restore in the
    // main loop) because the GIC state blob restore may not include ICC regs.
    // Restoring ICC regs after the GIC state blob (deferred) would be ideal,
    // but restoring them twice is harmless.
    if state.icc_pmr_el1 != 0 || state.icc_igrpen1_el1 != 0 {
        vcpu.set_icc_reg(HvGicIccReg::SreEl1, state.icc_sre_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::PmrEl1, state.icc_pmr_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Bpr0El1, state.icc_bpr0_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Bpr1El1, state.icc_bpr1_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::CtlrEl1, state.icc_ctlr_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Ap0r0El1, state.icc_ap0r0_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Ap1r0El1, state.icc_ap1r0_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Igrpen0El1, state.icc_igrpen0_el1)?;
        vcpu.set_icc_reg(HvGicIccReg::Igrpen1El1, state.icc_igrpen1_el1)?;
        log::debug!(
            "ICC regs restored: PMR=0x{:x}, IGRPEN0=0x{:x}, IGRPEN1=0x{:x}, SRE=0x{:x}",
            state.icc_pmr_el1,
            state.icc_igrpen0_el1,
            state.icc_igrpen1_el1,
            state.icc_sre_el1,
        );
    }

    // Trap debug exceptions (same as normal boot)
    vcpu.set_trap_debug_exceptions(true)?;

    Ok(())
}

// ── Fingerprinting ────────────────────────────────────────────────────

/// Hash file content for fingerprinting: size + first 4KB + last 4KB.
/// Fast, stable, and deterministic.  Only reads 8KB from disk regardless
/// of file size.
pub fn hash_file_content(path: &Path) -> u64 {
    let mut hasher = DefaultHasher::new();

    let Ok(mut file) = File::open(path) else {
        return 0;
    };
    let Ok(meta) = file.metadata() else {
        return 0;
    };
    let len = meta.len() as usize;
    len.hash(&mut hasher);

    // Read first 4KB
    let head_len = len.min(4096);
    let mut head = vec![0u8; head_len];
    if file.read_exact(&mut head).is_ok() {
        head.hash(&mut hasher);
    }

    // Read last 4KB (if file > 4KB)
    if len > 4096 {
        let tail_start = len - 4096;
        let mut tail = vec![0u8; 4096];
        if file.seek(SeekFrom::Start(tail_start as u64)).is_ok()
            && file.read_exact(&mut tail).is_ok()
        {
            tail.hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// Hash in-memory bytes for fingerprinting (same approach: size + first/last 4KB).
/// Used for the built-in rootfs which is already in memory.
pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.len().hash(&mut hasher);

    let head_len = data.len().min(4096);
    data[..head_len].hash(&mut hasher);

    if data.len() > 4096 {
        data[data.len() - 4096..].hash(&mut hasher);
    }

    hasher.finish()
}

/// Compute a fingerprint from kernel/rootfs content hashes, memory size,
/// and network config.  Changes to any of these invalidate the snapshot.
///
/// Shared directories (`--share`) and `--disk-size` are NOT included:
/// the device tree always reserves all virtiofs and data block slots,
/// and the overlay disk is ephemeral (fresh on every run), so the same
/// snapshot works regardless of those arguments.
///
/// Both `kernel_fingerprint` and `rootfs_fingerprint` should be produced
/// by [`hash_file_content`].
pub fn compute_fingerprint(
    kernel_fingerprint: u64,
    rootfs_fingerprint: u64,
    memory_mb: usize,
    network_enabled: bool,
) -> u64 {
    let mut hasher = DefaultHasher::new();

    SNAPSHOT_VERSION.hash(&mut hasher);
    kernel_fingerprint.hash(&mut hasher);
    rootfs_fingerprint.hash(&mut hasher);

    memory_mb.hash(&mut hasher);
    network_enabled.hash(&mut hasher);

    hasher.finish()
}

/// Get the snapshot cache directory, creating it if needed.
pub fn snapshot_cache_dir() -> Result<PathBuf> {
    let dir = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("sandal")
        .join("snapshots");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Get the snapshot file path for a given fingerprint.
pub fn snapshot_path(fingerprint: u64) -> Result<PathBuf> {
    let dir = snapshot_cache_dir()?;
    Ok(dir.join(format!("snap-{fingerprint:016x}.bin")))
}

/// Get the disk image path for a given fingerprint (virtio-blk snapshots).
pub fn disk_image_path(fingerprint: u64) -> Result<PathBuf> {
    let dir = snapshot_cache_dir()?;
    Ok(dir.join(format!("snap-{fingerprint:016x}.disk")))
}

/// Remove all snapshot files in the cache directory whose fingerprint
/// does not match `keep_fingerprint`.  This cleans up stale snapshots
/// left behind when the cache version or inputs change.
pub fn gc_stale_snapshots(keep_fingerprint: u64) {
    let dir = match snapshot_cache_dir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let keep_suffix = format!("{keep_fingerprint:016x}");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("snap-") && !name.contains(&keep_suffix) {
            debug!("Removing stale snapshot: {}", entry.path().display());
            let _ = fs::remove_file(entry.path());
        }
    }
}

// ── Binary reader / writer helpers ────────────────────────────────────

/// A lightweight cursor over a byte slice for deserializing fixed-width
/// integers.  Replaces the closure-based approach with monomorphized
/// method calls (no dyn dispatch).
struct SnapReader<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> SnapReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, off: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.off >= self.data.len() {
            anyhow::bail!("snapshot data truncated at offset {}", self.off);
        }
        let v = self.data[self.off];
        self.off += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.off + 2 > self.data.len() {
            anyhow::bail!("snapshot data truncated at offset {}", self.off);
        }
        let v = u16::from_le_bytes(self.data[self.off..self.off + 2].try_into().unwrap());
        self.off += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.off + 4 > self.data.len() {
            anyhow::bail!("snapshot data truncated at offset {}", self.off);
        }
        let v = u32::from_le_bytes(self.data[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.off + 8 > self.data.len() {
            anyhow::bail!("snapshot data truncated at offset {}", self.off);
        }
        let v = u64::from_le_bytes(self.data[self.off..self.off + 8].try_into().unwrap());
        self.off += 8;
        Ok(v)
    }

    fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.off + n > self.data.len() {
            anyhow::bail!("snapshot data truncated at offset {}", self.off);
        }
        let slice = &self.data[self.off..self.off + n];
        self.off += n;
        Ok(slice)
    }
}

/// A lightweight wrapper over `Vec<u8>` for serializing fixed-width
/// integers.  Replaces scattered `extend_from_slice(&val.to_le_bytes())`
/// calls.
struct SnapWriter {
    buf: Vec<u8>,
}

impl SnapWriter {
    fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

// ── Internal serialization ────────────────────────────────────────────

pub fn read_cpu_state(vcpu: &Vcpu) -> Result<CpuState> {
    let mut state = CpuState::default();

    // GPRs
    for i in 0..31u8 {
        if let Some(reg) = HvReg::from_gpr(i) {
            state.x[i as usize] = vcpu.read_register(reg)?;
        }
    }
    state.pc = vcpu.read_register(HvReg::Pc)?;
    state.cpsr = vcpu.read_register(HvReg::Cpsr)?;
    state.fpcr = vcpu.read_register(HvReg::Fpcr)?;
    state.fpsr = vcpu.read_register(HvReg::Fpsr)?;

    // System registers
    state.sp_el0 = vcpu.read_sys_register(HvSysReg::SpEl0)?;
    state.sp_el1 = vcpu.read_sys_register(HvSysReg::SpEl1)?;
    state.sctlr_el1 = vcpu.read_sys_register(HvSysReg::SctlrEl1)?;
    state.cpacr_el1 = vcpu.read_sys_register(HvSysReg::CpacrEl1)?;
    state.ttbr0_el1 = vcpu.read_sys_register(HvSysReg::Ttbr0El1)?;
    state.ttbr1_el1 = vcpu.read_sys_register(HvSysReg::Ttbr1El1)?;
    state.tcr_el1 = vcpu.read_sys_register(HvSysReg::TcrEl1)?;
    state.mair_el1 = vcpu.read_sys_register(HvSysReg::MairEl1)?;
    state.spsr_el1 = vcpu.read_sys_register(HvSysReg::SpsrEl1)?;
    state.elr_el1 = vcpu.read_sys_register(HvSysReg::ElrEl1)?;
    state.esr_el1 = vcpu.read_sys_register(HvSysReg::EsrEl1)?;
    state.far_el1 = vcpu.read_sys_register(HvSysReg::FarEl1)?;
    state.vbar_el1 = vcpu.read_sys_register(HvSysReg::VbarEl1)?;
    state.tpidr_el0 = vcpu.read_sys_register(HvSysReg::TpidrEl0)?;
    state.tpidrro_el0 = vcpu.read_sys_register(HvSysReg::TpidrroEl0)?;
    state.tpidr_el1 = vcpu.read_sys_register(HvSysReg::TpidrEl1)?;
    state.mpidr_el1 = vcpu.read_sys_register(HvSysReg::MpidrEl1)?;
    state.mdscr_el1 = vcpu.read_sys_register(HvSysReg::MdscrEl1)?;
    state.contextidr_el1 = vcpu.read_sys_register(HvSysReg::ContextidrEl1)?;
    state.par_el1 = vcpu.read_sys_register(HvSysReg::ParEl1)?;
    state.cntkctl_el1 = vcpu.read_sys_register(HvSysReg::CntkctlEl1)?;
    state.cntv_ctl_el0 = vcpu.read_sys_register(HvSysReg::CntvCtlEl0)?;
    state.cntv_cval_el0 = vcpu.read_sys_register(HvSysReg::CntvCvalEl0)?;

    // VTimer
    state.vtimer_offset = vcpu.get_vtimer_offset()?;
    state.vtimer_mask = if vcpu.get_vtimer_mask()? { 1 } else { 0 };

    // Save the physical counter so we can adjust the vtimer offset on restore.
    state.saved_cntpct = unsafe { mach_absolute_time() };

    // GIC ICC (CPU interface) registers
    state.icc_pmr_el1 = vcpu.get_icc_reg(HvGicIccReg::PmrEl1)?;
    state.icc_bpr0_el1 = vcpu.get_icc_reg(HvGicIccReg::Bpr0El1)?;
    state.icc_bpr1_el1 = vcpu.get_icc_reg(HvGicIccReg::Bpr1El1)?;
    state.icc_ctlr_el1 = vcpu.get_icc_reg(HvGicIccReg::CtlrEl1)?;
    state.icc_sre_el1 = vcpu.get_icc_reg(HvGicIccReg::SreEl1)?;
    state.icc_igrpen0_el1 = vcpu.get_icc_reg(HvGicIccReg::Igrpen0El1)?;
    state.icc_igrpen1_el1 = vcpu.get_icc_reg(HvGicIccReg::Igrpen1El1)?;
    state.icc_ap0r0_el1 = vcpu.get_icc_reg(HvGicIccReg::Ap0r0El1)?;
    state.icc_ap1r0_el1 = vcpu.get_icc_reg(HvGicIccReg::Ap1r0El1)?;

    Ok(state)
}

/// Reinterpret CpuState as a raw byte slice.  CpuState is `#[repr(C)]`
/// with all-u64 fields, so this is a zero-cost cast (no field-by-field
/// serialization).
fn cpu_state_as_bytes(state: &CpuState) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(state as *const _ as *const u8, mem::size_of::<CpuState>())
    }
}

/// Deserialize CpuState from raw bytes via `ptr::read`.  Inverse of
/// `cpu_state_as_bytes`.
fn cpu_state_from_bytes(data: &[u8]) -> Result<CpuState> {
    let expected = mem::size_of::<CpuState>();
    if data.len() < expected {
        anyhow::bail!(
            "CPU state too small: {} bytes (expected {})",
            data.len(),
            expected
        );
    }
    Ok(unsafe { ptr::read(data.as_ptr() as *const CpuState) })
}

fn serialize_device_state(state: &DeviceState) -> Vec<u8> {
    let mut w = SnapWriter::with_capacity(256);

    w.write_bool(state.network_enabled);

    // Net MMIO
    w.write_bool(state.net_mmio.is_some());
    if let Some(ref mmio) = state.net_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    // RNG MMIO
    w.write_bool(state.rng_mmio.is_some());
    if let Some(ref mmio) = state.rng_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    // Blk MMIO + use_virtio_blk flag
    w.write_bool(state.use_virtio_blk);
    w.write_bool(state.blk_mmio.is_some());
    if let Some(ref mmio) = state.blk_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    // Virtiofs MMIO state (one entry per --share device)
    w.write_u32(state.fs_mmio.len() as u32);
    for mmio in &state.fs_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    // GIC state
    if let Some(ref gic) = state.gic_state {
        w.write_u32(gic.len() as u32);
        w.write_bytes(gic);
    } else {
        w.write_u32(0);
    }

    // Data block MMIO (overlay disk) — appended after GIC for backward compat
    w.write_bool(state.data_blk_mmio.is_some());
    if let Some(ref mmio) = state.data_blk_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    // Virtio-console MMIO — appended after data_blk for backward compat
    w.write_bool(state.console_mmio.is_some());
    if let Some(ref mmio) = state.console_mmio {
        write_virtio_mmio(&mut w, mmio);
    }

    w.into_vec()
}

fn write_virtio_mmio(w: &mut SnapWriter, mmio: &VirtioMmioSnapshot) {
    w.write_u32(mmio.device_features_sel);
    w.write_u64(mmio.driver_features);
    w.write_u32(mmio.driver_features_sel);
    w.write_u32(mmio.queue_sel);
    w.write_u32(mmio.status);
    w.write_u32(mmio.interrupt_status);
    w.write_u32(mmio.config_generation);
    w.write_u32(mmio.queues.len() as u32);
    for q in &mmio.queues {
        w.write_u32(q.num_max);
        w.write_u32(q.num);
        w.write_u8(q.ready);
        w.write_u64(q.desc_addr);
        w.write_u64(q.avail_addr);
        w.write_u64(q.used_addr);
        w.write_u16(q.last_avail_idx);
    }
}

fn deserialize_device_state(data: &[u8]) -> Result<DeviceState> {
    let mut r = SnapReader::new(data);

    let network_enabled = r.read_bool()?;

    let net_mmio = if r.read_bool()? {
        Some(read_virtio_mmio(&mut r)?)
    } else {
        None
    };

    let rng_mmio = if r.read_bool()? {
        Some(read_virtio_mmio(&mut r)?)
    } else {
        None
    };

    // Blk MMIO + use_virtio_blk flag
    let use_virtio_blk = r.read_bool()?;
    let blk_mmio = if r.read_bool()? {
        Some(read_virtio_mmio(&mut r)?)
    } else {
        None
    };

    // Virtiofs MMIO state
    let num_fs = r.read_u32()? as usize;
    let mut fs_mmio = Vec::with_capacity(num_fs);
    for _ in 0..num_fs {
        fs_mmio.push(read_virtio_mmio(&mut r)?);
    }

    // GIC state
    let gic_len = r.read_u32()? as usize;
    let gic_state = if gic_len > 0 {
        Some(r.read_bytes(gic_len)?.to_vec())
    } else {
        None
    };

    // Data block MMIO (overlay disk)
    let data_blk_mmio = if r.read_bool()? {
        Some(read_virtio_mmio(&mut r)?)
    } else {
        None
    };

    // Virtio-console MMIO
    let console_mmio = if r.read_bool()? {
        Some(read_virtio_mmio(&mut r)?)
    } else {
        None
    };

    Ok(DeviceState {
        network_enabled,
        net_mmio,
        rng_mmio,
        blk_mmio,
        use_virtio_blk,
        fs_mmio,
        gic_state,
        data_blk_mmio,
        console_mmio,
    })
}

fn read_virtio_mmio(r: &mut SnapReader) -> Result<VirtioMmioSnapshot> {
    let device_features_sel = r.read_u32()?;
    let driver_features = r.read_u64()?;
    let driver_features_sel = r.read_u32()?;
    let queue_sel = r.read_u32()?;
    let status = r.read_u32()?;
    let interrupt_status = r.read_u32()?;
    let config_generation = r.read_u32()?;
    let num_queues = r.read_u32()? as usize;

    let mut queues = Vec::with_capacity(num_queues);
    for _ in 0..num_queues {
        queues.push(VirtqSnapshot {
            num_max: r.read_u32()?,
            num: r.read_u32()?,
            ready: r.read_u8()?,
            desc_addr: r.read_u64()?,
            avail_addr: r.read_u64()?,
            used_addr: r.read_u64()?,
            last_avail_idx: r.read_u16()?,
        });
    }

    Ok(VirtioMmioSnapshot {
        device_features_sel,
        driver_features,
        driver_features_sel,
        queue_sel,
        status,
        interrupt_status,
        config_generation,
        queues,
    })
}

// ── Snapshot helpers for VirtioNetDevice / VirtioRngDevice ─────────────

impl VirtioMmioSnapshot {
    pub fn from_net(dev: &VirtioNetDevice) -> Self {
        VirtioMmioSnapshot {
            device_features_sel: dev.device_features_sel,
            driver_features: dev.driver_features,
            driver_features_sel: dev.driver_features_sel,
            queue_sel: dev.queue_sel,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            config_generation: dev.config_generation,
            queues: dev
                .queues
                .iter()
                .map(|q| VirtqSnapshot {
                    num_max: q.num_max,
                    num: q.num,
                    ready: if q.ready { 1 } else { 0 },
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                    last_avail_idx: q.last_avail_idx,
                })
                .collect(),
        }
    }

    pub fn from_blk(dev: &VirtioBlkDevice) -> Self {
        VirtioMmioSnapshot {
            device_features_sel: dev.device_features_sel,
            driver_features: dev.driver_features,
            driver_features_sel: dev.driver_features_sel,
            queue_sel: dev.queue_sel,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            config_generation: dev.config_generation,
            queues: dev
                .queues
                .iter()
                .map(|q| VirtqSnapshot {
                    num_max: q.num_max,
                    num: q.num,
                    ready: if q.ready { 1 } else { 0 },
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                    last_avail_idx: q.last_avail_idx,
                })
                .collect(),
        }
    }

    pub fn from_rng(dev: &VirtioRngDevice) -> Self {
        VirtioMmioSnapshot {
            device_features_sel: dev.device_features_sel,
            driver_features: dev.driver_features,
            driver_features_sel: dev.driver_features_sel,
            queue_sel: dev.queue_sel,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            config_generation: 0, // RNG device doesn't have config_generation
            queues: dev
                .queues
                .iter()
                .map(|q| VirtqSnapshot {
                    num_max: q.num_max,
                    num: q.num,
                    ready: if q.ready { 1 } else { 0 },
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                    last_avail_idx: q.last_avail_idx,
                })
                .collect(),
        }
    }

    pub fn from_fs(dev: &VirtioFsDevice) -> Self {
        VirtioMmioSnapshot {
            device_features_sel: dev.device_features_sel,
            driver_features: dev.driver_features,
            driver_features_sel: dev.driver_features_sel,
            queue_sel: dev.queue_sel,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            config_generation: dev.config_generation,
            queues: dev
                .queues
                .iter()
                .map(|q| VirtqSnapshot {
                    num_max: q.num_max,
                    num: q.num,
                    ready: if q.ready { 1 } else { 0 },
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                    last_avail_idx: q.last_avail_idx,
                })
                .collect(),
        }
    }

    pub fn from_console(dev: &VirtioConsoleDevice) -> Self {
        VirtioMmioSnapshot {
            device_features_sel: dev.device_features_sel,
            driver_features: dev.driver_features,
            driver_features_sel: dev.driver_features_sel,
            queue_sel: dev.queue_sel,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            config_generation: 0,
            queues: dev
                .queues
                .iter()
                .map(|q| VirtqSnapshot {
                    num_max: q.num_max,
                    num: q.num,
                    ready: if q.ready { 1 } else { 0 },
                    desc_addr: q.desc_addr,
                    avail_addr: q.avail_addr,
                    used_addr: q.used_addr,
                    last_avail_idx: q.last_avail_idx,
                })
                .collect(),
        }
    }
}
