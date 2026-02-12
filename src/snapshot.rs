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
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::hypervisor::{HvGicIccReg, HvReg, HvSysReg, Vcpu};
use crate::virtio::blk::VirtioBlkDevice;
use crate::virtio::fs::VirtioFsDevice;
use crate::virtio::net::VirtioNetDevice;
use crate::virtio::rng::VirtioRngDevice;

// ── Snapshot file format ──────────────────────────────────────────────

const SNAPSHOT_MAGIC: u32 = 0x534E4150; // "SNAP"
const SNAPSHOT_VERSION: u32 = 1;
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
#[derive(Clone, Debug, Default)]
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
    pub vtimer_mask: u8,

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
    pub uart_is_8250: bool,
    pub uart_8250_ier: u8, // 8250 IER register value (interrupt enables)
    pub pl011_imsc: u32,
    pub network_enabled: bool,
    pub net_mmio: Option<VirtioMmioSnapshot>,
    pub rng_mmio: Option<VirtioMmioSnapshot>,
    pub blk_mmio: Option<VirtioMmioSnapshot>,
    pub use_virtio_blk: bool,
    pub fs_mmio: Vec<VirtioMmioSnapshot>, // virtiofs device MMIO state (one per --share)
    pub gic_state: Option<Vec<u8>>,       // Opaque GIC state blob (macOS 15+)
}

// ── Save ──────────────────────────────────────────────────────────────

/// Save the complete VM state to a snapshot file.
pub fn save_snapshot(
    path: &Path,
    memory: &[u8],
    vcpu: &Vcpu,
    device_state: &DeviceState,
    fingerprint: u64,
) -> Result<()> {
    let cpu_state = read_cpu_state(vcpu)?;
    let cpu_bytes = serialize_cpu_state(&cpu_state);
    let device_bytes = serialize_device_state(device_state);

    let memory_size = memory.len() as u64;
    let cpu_state_offset = std::mem::size_of::<SnapshotHeader>() as u64;
    let device_state_offset = cpu_state_offset + cpu_bytes.len() as u64;
    let memory_offset = device_state_offset + device_bytes.len() as u64;
    // Align memory_offset to page boundary for efficient mmap
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

    // Write to a temp file, then rename for atomicity
    let tmp_path = path.with_extension("tmp");
    let mut file = File::create(&tmp_path).context("Failed to create snapshot file")?;

    // Write header
    let header_bytes = unsafe {
        std::slice::from_raw_parts(
            &header as *const _ as *const u8,
            std::mem::size_of::<SnapshotHeader>(),
        )
    };
    file.write_all(header_bytes)?;

    // Write CPU state
    file.seek(SeekFrom::Start(cpu_state_offset))?;
    file.write_all(&cpu_bytes)?;

    // Write device state
    file.seek(SeekFrom::Start(device_state_offset))?;
    file.write_all(&device_bytes)?;

    // Write memory (sparse: skip zero pages)
    let num_pages = memory.len() / PAGE_SIZE;
    let mut written_pages = 0u64;
    for page_idx in 0..num_pages {
        let offset = page_idx * PAGE_SIZE;
        let page = &memory[offset..offset + PAGE_SIZE];
        if page.iter().all(|&b| b == 0) {
            continue; // sparse hole
        }
        file.seek(SeekFrom::Start(memory_offset + offset as u64))?;
        file.write_all(page)?;
        written_pages += 1;
    }

    // Ensure file is the full size (so mmap works)
    file.set_len(memory_offset + memory_size)?;
    file.sync_all()?;
    drop(file);

    // Atomic rename
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
    use std::os::unix::fs::FileExt;

    let file = File::open(path).context("Failed to open snapshot file")?;
    let file_len = file.metadata()?.len() as usize;

    // Read header via pread() — avoids creating a full read-only mmap
    // just to parse ~1KB of metadata (eliminates an mmap+munmap pair
    // and their page-table setup/teardown overhead).
    let header_size = std::mem::size_of::<SnapshotHeader>();
    if file_len < header_size {
        anyhow::bail!("Snapshot file too small");
    }
    let mut header_buf = [0u8; std::mem::size_of::<SnapshotHeader>()];
    file.read_at(&mut header_buf, 0)
        .context("Failed to read snapshot header")?;
    let header: SnapshotHeader = unsafe { std::ptr::read(header_buf.as_ptr() as *const _) };

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

    // Parse CPU state from the combined buffer
    let cpu_local_end = header.cpu_state_size as usize;
    let cpu_state = deserialize_cpu_state(&state_buf[..cpu_local_end])?;

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
    // the vtimer fires immediately.  Because the snapshot is taken
    // inside spin_lock_irqsave (IRQs disabled), the timer interrupt
    // cannot be delivered, causing an infinite vtimer-fire-mask-unmask
    // loop that hangs the VM.
    extern "C" {
        fn mach_absolute_time() -> u64;
    }
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::io::{Read, Seek, SeekFrom};

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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

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
/// Shared directories (`--share`) are NOT included: the device tree
/// always reserves all MAX_FS_DEVICES virtiofs slots, and mount commands
/// are injected via UART at runtime, so the same snapshot works for any
/// combination of `--share` arguments.
///
/// Both `kernel_fingerprint` and `rootfs_fingerprint` should be produced
/// by [`hash_file_content`].
pub fn compute_fingerprint(
    kernel_fingerprint: u64,
    rootfs_fingerprint: u64,
    memory_mb: usize,
    network_enabled: bool,
) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

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

// ── Internal serialization ────────────────────────────────────────────

fn read_cpu_state(vcpu: &Vcpu) -> Result<CpuState> {
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
    extern "C" {
        fn mach_absolute_time() -> u64;
    }
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

// Simple binary serialization for CpuState (fixed layout)
fn serialize_cpu_state(state: &CpuState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    // GPRs
    for &v in &state.x {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf.extend_from_slice(&state.pc.to_le_bytes());
    buf.extend_from_slice(&state.cpsr.to_le_bytes());
    buf.extend_from_slice(&state.fpcr.to_le_bytes());
    buf.extend_from_slice(&state.fpsr.to_le_bytes());
    // Sys regs
    for v in [
        state.sp_el0,
        state.sp_el1,
        state.sctlr_el1,
        state.cpacr_el1,
        state.ttbr0_el1,
        state.ttbr1_el1,
        state.tcr_el1,
        state.mair_el1,
        state.spsr_el1,
        state.elr_el1,
        state.esr_el1,
        state.far_el1,
        state.vbar_el1,
        state.tpidr_el0,
        state.tpidrro_el0,
        state.tpidr_el1,
        state.mpidr_el1,
        state.mdscr_el1,
        state.contextidr_el1,
        state.par_el1,
        state.cntkctl_el1,
        state.cntv_ctl_el0,
        state.cntv_cval_el0,
    ] {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf.extend_from_slice(&state.vtimer_offset.to_le_bytes());
    buf.push(state.vtimer_mask);
    buf.extend_from_slice(&state.saved_cntpct.to_le_bytes());
    // ICC registers
    for v in [
        state.icc_pmr_el1,
        state.icc_bpr0_el1,
        state.icc_bpr1_el1,
        state.icc_ctlr_el1,
        state.icc_sre_el1,
        state.icc_igrpen0_el1,
        state.icc_igrpen1_el1,
        state.icc_ap0r0_el1,
        state.icc_ap1r0_el1,
    ] {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf
}

fn deserialize_cpu_state(data: &[u8]) -> Result<CpuState> {
    let mut state = CpuState::default();
    let mut off = 0usize;

    let read_u64 = |data: &[u8], off: &mut usize| -> Result<u64> {
        if *off + 8 > data.len() {
            anyhow::bail!("CPU state truncated at offset {}", *off);
        }
        let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
        *off += 8;
        Ok(v)
    };

    for i in 0..31 {
        state.x[i] = read_u64(data, &mut off)?;
    }
    state.pc = read_u64(data, &mut off)?;
    state.cpsr = read_u64(data, &mut off)?;
    state.fpcr = read_u64(data, &mut off)?;
    state.fpsr = read_u64(data, &mut off)?;

    state.sp_el0 = read_u64(data, &mut off)?;
    state.sp_el1 = read_u64(data, &mut off)?;
    state.sctlr_el1 = read_u64(data, &mut off)?;
    state.cpacr_el1 = read_u64(data, &mut off)?;
    state.ttbr0_el1 = read_u64(data, &mut off)?;
    state.ttbr1_el1 = read_u64(data, &mut off)?;
    state.tcr_el1 = read_u64(data, &mut off)?;
    state.mair_el1 = read_u64(data, &mut off)?;
    state.spsr_el1 = read_u64(data, &mut off)?;
    state.elr_el1 = read_u64(data, &mut off)?;
    state.esr_el1 = read_u64(data, &mut off)?;
    state.far_el1 = read_u64(data, &mut off)?;
    state.vbar_el1 = read_u64(data, &mut off)?;
    state.tpidr_el0 = read_u64(data, &mut off)?;
    state.tpidrro_el0 = read_u64(data, &mut off)?;
    state.tpidr_el1 = read_u64(data, &mut off)?;
    state.mpidr_el1 = read_u64(data, &mut off)?;
    state.mdscr_el1 = read_u64(data, &mut off)?;
    state.contextidr_el1 = read_u64(data, &mut off)?;
    state.par_el1 = read_u64(data, &mut off)?;
    state.cntkctl_el1 = read_u64(data, &mut off)?;
    state.cntv_ctl_el0 = read_u64(data, &mut off)?;
    state.cntv_cval_el0 = read_u64(data, &mut off)?;
    state.vtimer_offset = read_u64(data, &mut off)?;

    if off >= data.len() {
        anyhow::bail!("CPU state truncated (missing vtimer_mask)");
    }
    state.vtimer_mask = data[off];
    off += 1;

    // saved_cntpct (added later; may be absent in old snapshots)
    if off + 8 <= data.len() {
        state.saved_cntpct = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        off += 8;
    }

    // ICC registers (added later; may be absent in old snapshots)
    if off + 9 * 8 <= data.len() {
        state.icc_pmr_el1 = read_u64(data, &mut off)?;
        state.icc_bpr0_el1 = read_u64(data, &mut off)?;
        state.icc_bpr1_el1 = read_u64(data, &mut off)?;
        state.icc_ctlr_el1 = read_u64(data, &mut off)?;
        state.icc_sre_el1 = read_u64(data, &mut off)?;
        state.icc_igrpen0_el1 = read_u64(data, &mut off)?;
        state.icc_igrpen1_el1 = read_u64(data, &mut off)?;
        state.icc_ap0r0_el1 = read_u64(data, &mut off)?;
        state.icc_ap1r0_el1 = read_u64(data, &mut off)?;
    }

    Ok(state)
}

fn serialize_device_state(state: &DeviceState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.push(if state.uart_is_8250 { 1 } else { 0 });
    buf.push(state.uart_8250_ier);
    buf.extend_from_slice(&state.pl011_imsc.to_le_bytes());
    buf.push(if state.network_enabled { 1 } else { 0 });

    // Net MMIO
    buf.push(if state.net_mmio.is_some() { 1 } else { 0 });
    if let Some(ref mmio) = state.net_mmio {
        serialize_virtio_mmio(&mut buf, mmio);
    }

    // RNG MMIO
    buf.push(if state.rng_mmio.is_some() { 1 } else { 0 });
    if let Some(ref mmio) = state.rng_mmio {
        serialize_virtio_mmio(&mut buf, mmio);
    }

    // Blk MMIO + use_virtio_blk flag
    buf.push(if state.use_virtio_blk { 1 } else { 0 });
    buf.push(if state.blk_mmio.is_some() { 1 } else { 0 });
    if let Some(ref mmio) = state.blk_mmio {
        serialize_virtio_mmio(&mut buf, mmio);
    }

    // Virtiofs MMIO state (one entry per --share device)
    buf.extend_from_slice(&(state.fs_mmio.len() as u32).to_le_bytes());
    for mmio in &state.fs_mmio {
        serialize_virtio_mmio(&mut buf, mmio);
    }

    // GIC state
    if let Some(ref gic) = state.gic_state {
        buf.extend_from_slice(&(gic.len() as u32).to_le_bytes());
        buf.extend_from_slice(gic);
    } else {
        buf.extend_from_slice(&0u32.to_le_bytes());
    }

    buf
}

fn serialize_virtio_mmio(buf: &mut Vec<u8>, mmio: &VirtioMmioSnapshot) {
    buf.extend_from_slice(&mmio.device_features_sel.to_le_bytes());
    buf.extend_from_slice(&mmio.driver_features.to_le_bytes());
    buf.extend_from_slice(&mmio.driver_features_sel.to_le_bytes());
    buf.extend_from_slice(&mmio.queue_sel.to_le_bytes());
    buf.extend_from_slice(&mmio.status.to_le_bytes());
    buf.extend_from_slice(&mmio.interrupt_status.to_le_bytes());
    buf.extend_from_slice(&mmio.config_generation.to_le_bytes());
    buf.extend_from_slice(&(mmio.queues.len() as u32).to_le_bytes());
    for q in &mmio.queues {
        buf.extend_from_slice(&q.num_max.to_le_bytes());
        buf.extend_from_slice(&q.num.to_le_bytes());
        buf.push(q.ready);
        buf.extend_from_slice(&q.desc_addr.to_le_bytes());
        buf.extend_from_slice(&q.avail_addr.to_le_bytes());
        buf.extend_from_slice(&q.used_addr.to_le_bytes());
        buf.extend_from_slice(&q.last_avail_idx.to_le_bytes());
    }
}

fn deserialize_device_state(data: &[u8]) -> Result<DeviceState> {
    let mut off = 0usize;

    let read_u8 = |data: &[u8], off: &mut usize| -> Result<u8> {
        if *off >= data.len() {
            anyhow::bail!("Device state truncated");
        }
        let v = data[*off];
        *off += 1;
        Ok(v)
    };
    let read_u16 = |data: &[u8], off: &mut usize| -> Result<u16> {
        if *off + 2 > data.len() {
            anyhow::bail!("Device state truncated");
        }
        let v = u16::from_le_bytes(data[*off..*off + 2].try_into().unwrap());
        *off += 2;
        Ok(v)
    };
    let read_u32 = |data: &[u8], off: &mut usize| -> Result<u32> {
        if *off + 4 > data.len() {
            anyhow::bail!("Device state truncated");
        }
        let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
        *off += 4;
        Ok(v)
    };
    let read_u64 = |data: &[u8], off: &mut usize| -> Result<u64> {
        if *off + 8 > data.len() {
            anyhow::bail!("Device state truncated");
        }
        let v = u64::from_le_bytes(data[*off..*off + 8].try_into().unwrap());
        *off += 8;
        Ok(v)
    };

    let uart_is_8250 = read_u8(data, &mut off)? != 0;
    let uart_8250_ier = read_u8(data, &mut off)?;
    let pl011_imsc = read_u32(data, &mut off)?;
    let network_enabled = read_u8(data, &mut off)? != 0;

    let has_net = read_u8(data, &mut off)? != 0;
    let net_mmio = if has_net {
        Some(deserialize_virtio_mmio(
            data, &mut off, &read_u8, &read_u16, &read_u32, &read_u64,
        )?)
    } else {
        None
    };

    let has_rng = read_u8(data, &mut off)? != 0;
    let rng_mmio = if has_rng {
        Some(deserialize_virtio_mmio(
            data, &mut off, &read_u8, &read_u16, &read_u32, &read_u64,
        )?)
    } else {
        None
    };

    // Blk MMIO + use_virtio_blk flag (added later; may be absent in old snapshots)
    let (use_virtio_blk, blk_mmio) = if off < data.len() {
        let use_blk = read_u8(data, &mut off)? != 0;
        let has_blk = read_u8(data, &mut off)? != 0;
        let blk = if has_blk {
            Some(deserialize_virtio_mmio(
                data, &mut off, &read_u8, &read_u16, &read_u32, &read_u64,
            )?)
        } else {
            None
        };
        (use_blk, blk)
    } else {
        (false, None)
    };

    // Virtiofs MMIO state (added later; may be absent in old snapshots)
    let fs_mmio = if off + 4 <= data.len() {
        let num_fs = read_u32(data, &mut off)? as usize;
        let mut fs = Vec::with_capacity(num_fs);
        for _ in 0..num_fs {
            fs.push(deserialize_virtio_mmio(
                data, &mut off, &read_u8, &read_u16, &read_u32, &read_u64,
            )?);
        }
        fs
    } else {
        Vec::new()
    };

    // GIC state
    let gic_len = read_u32(data, &mut off)? as usize;
    let gic_state = if gic_len > 0 {
        if off + gic_len > data.len() {
            anyhow::bail!("Device state truncated (GIC state)");
        }
        let gic = data[off..off + gic_len].to_vec();
        off += gic_len;
        Some(gic)
    } else {
        None
    };
    let _ = off; // suppress unused warning

    Ok(DeviceState {
        uart_is_8250,
        uart_8250_ier,
        pl011_imsc,
        network_enabled,
        net_mmio,
        rng_mmio,
        blk_mmio,
        use_virtio_blk,
        fs_mmio,
        gic_state,
    })
}

fn deserialize_virtio_mmio(
    data: &[u8],
    off: &mut usize,
    read_u8: &dyn Fn(&[u8], &mut usize) -> Result<u8>,
    read_u16: &dyn Fn(&[u8], &mut usize) -> Result<u16>,
    read_u32: &dyn Fn(&[u8], &mut usize) -> Result<u32>,
    read_u64: &dyn Fn(&[u8], &mut usize) -> Result<u64>,
) -> Result<VirtioMmioSnapshot> {
    let device_features_sel = read_u32(data, off)?;
    let driver_features = read_u64(data, off)?;
    let driver_features_sel = read_u32(data, off)?;
    let queue_sel = read_u32(data, off)?;
    let status = read_u32(data, off)?;
    let interrupt_status = read_u32(data, off)?;
    let config_generation = read_u32(data, off)?;
    let num_queues = read_u32(data, off)? as usize;

    let mut queues = Vec::with_capacity(num_queues);
    for _ in 0..num_queues {
        queues.push(VirtqSnapshot {
            num_max: read_u32(data, off)?,
            num: read_u32(data, off)?,
            ready: read_u8(data, off)?,
            desc_addr: read_u64(data, off)?,
            avail_addr: read_u64(data, off)?,
            used_addr: read_u64(data, off)?,
            last_avail_idx: read_u16(data, off)?,
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
}
