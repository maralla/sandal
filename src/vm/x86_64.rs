//! x86_64 guest specifics: physical memory map, PVH direct boot (no
//! firmware), the I/O-port hypercall protocol, the COM1 earlycon stub, and
//! the legacy ISA IRQ pool.

use super::{
    resolve_data_path, Args, Vmm, DATA_BLK_BASE, MMIO_BASE, VIRTIOFS_BASE_START, VIRTIOFS_SIZE,
    VIRTIO_BLK_BASE, VIRTIO_CONSOLE_BASE, VIRTIO_NET_BASE, VIRTIO_RNG_BASE,
};
use anyhow::{anyhow, Result};
use std::fs;

// ── Guest physical memory map ───────────────────────────────────────────
pub(crate) const RAM_BASE: u64 = 0x0;

pub(super) const KERNEL_ARTIFACT: &str = "vmlinux-sandal-x86";
pub(crate) const MAX_FS_DEVICES: usize = 5;

/// Legacy ISA IRQs usable for virtio-mmio devices (skips the timer,
/// keyboard, cascade, RTC and FPU lines). Device slot i takes POOL[i];
/// the slot index matches the `virtio_mmio.device=` cmdline order.
pub(super) const ISA_IRQ_POOL: [u32; 10] = [3, 5, 6, 7, 9, 10, 11, 12, 14, 15];

/// COM1 (earlycon) base port.
pub(super) const SERIAL_BASE: u16 = 0x3f8;

/// PVH boot placement (well below the kernel's 16 MB load address).
const PVH_CMDLINE_ADDR: u64 = 0x20000;
const PVH_START_INFO_ADDR: u64 = 0x30000;
const PVH_MEMMAP_ADDR: u64 = 0x31000;

/// Hypercall page: the guest maps this physical page via /dev/mem and
/// performs MMIO writes to signal the VMM (export resize/done). MMIO works
/// from userspace without I/O-port privileges (which nested KVM denies).
pub(super) const HYPERCALL_PAGE: u64 = MMIO_BASE + 0xe00;

/// (page-aligned base, in-page offset) of the hypercall page — used by the
/// guest helpers that mmap /dev/mem.
pub fn x86_hypercall_page_off() -> (u64, u64) {
    (HYPERCALL_PAGE & !0xfff, HYPERCALL_PAGE & 0xfff)
}

/// Page-aligned base for /dev/mem mmap guests.
/// Config blob injected into the rootfs as /etc/sandal.conf (replaces the
/// arm64 INIT_CONFIG BRK hypercall: a plain file read needs no privileges).
pub(super) const CONFIG_PATH: &str = "etc/sandal.conf";

impl Vmm {
    #[cfg(target_arch = "x86_64")]
    pub(super) fn boot_kernel_x86(&mut self, args: &Args) -> Result<()> {
        const PT_LOAD: u32 = 1;
        const PT_NOTE: u32 = 4;
        const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;
        const E820_RAM: u32 = 1;
        const E820_RESERVED: u32 = 2;

        let kernel_path = args
            .kernel
            .clone()
            .or_else(|| resolve_data_path(KERNEL_ARTIFACT))
            .ok_or_else(|| anyhow!("kernel image not found"))?;
        let elf = fs::read(&kernel_path)?;
        if elf.len() < 64 || &elf[..4] != b"\x7fELF" {
            anyhow::bail!("kernel is not an ELF image");
        }
        let e_phoff = u64::from_le_bytes(elf[32..40].try_into()?) as usize;
        let e_phentsize = u16::from_le_bytes(elf[54..56].try_into()?) as usize;
        let e_phnum = u16::from_le_bytes(elf[56..58].try_into()?) as usize;

        let mut pvh_entry: Option<u64> = None;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            let p_type = u32::from_le_bytes(elf[ph..ph + 4].try_into()?);
            let p_offset = u64::from_le_bytes(elf[ph + 8..ph + 16].try_into()?) as usize;
            let p_paddr = u64::from_le_bytes(elf[ph + 24..ph + 32].try_into()?);
            let p_filesz = u64::from_le_bytes(elf[ph + 32..ph + 40].try_into()?) as usize;
            let p_memsz = u64::from_le_bytes(elf[ph + 40..ph + 48].try_into()?) as usize;

            match p_type {
                PT_LOAD => {
                    let start = (p_paddr - RAM_BASE) as usize;
                    if start + p_memsz > self.memory.len() {
                        anyhow::bail!("kernel segment does not fit in RAM");
                    }
                    let mem = self.memory.as_shared_slice();
                    mem[start..start + p_filesz]
                        .copy_from_slice(&elf[p_offset..p_offset + p_filesz]);
                    // p_memsz > p_filesz (bss) is already zeroed.
                }
                PT_NOTE => {
                    // Walk the note section for the PVH entry point.
                    let mut off = p_offset;
                    let end = p_offset + p_filesz;
                    while off + 12 <= end {
                        let namesz = u32::from_le_bytes(elf[off..off + 4].try_into()?) as usize;
                        let descsz = u32::from_le_bytes(elf[off + 4..off + 8].try_into()?) as usize;
                        let ntype = u32::from_le_bytes(elf[off + 8..off + 12].try_into()?);
                        let name_off = off + 12;
                        let desc_off = name_off + namesz.div_ceil(4) * 4;
                        if ntype == XEN_ELFNOTE_PHYS32_ENTRY && descsz >= 4 {
                            pvh_entry =
                                Some(u32::from_le_bytes(elf[desc_off..desc_off + 4].try_into()?)
                                    as u64);
                        }
                        off = desc_off + descsz.div_ceil(4) * 4;
                    }
                }
                _ => {}
            }
        }
        let entry = pvh_entry.ok_or_else(|| anyhow!("kernel has no PVH entry note"))?;

        // ── Kernel command line: console + virtio-mmio devices ─────────
        // loglevel=3: the pane is the user's console, not a kernel log —
        // probe noise (i8042, WMI, ...) stays in dmesg, not on screen.
        // (err-level and below are hidden; emerg/alert/crit still show.)
        let mut cmdline = String::from(
            "console=hvc0 earlycon=uart8250,io,0x3f8 root=/dev/vda rw init=/init loglevel=7 random.trust_cpu=on nohz=off highres=off nokaslr",
        );
        let mut devices: Vec<(u64, u32)> = vec![
            (VIRTIO_NET_BASE, ISA_IRQ_POOL[0]),
            (VIRTIO_CONSOLE_BASE, ISA_IRQ_POOL[1]),
            (VIRTIO_BLK_BASE, ISA_IRQ_POOL[2]),
            (DATA_BLK_BASE, ISA_IRQ_POOL[3]),
            (VIRTIO_RNG_BASE, ISA_IRQ_POOL[4]),
        ];
        if self.net.is_none() {
            // Keep the mmio layout (and thus the cmdline) stable whether or
            // not networking is enabled: the device region stays reserved but
            // must not be described to the kernel.
        }
        for i in 0..self.virtiofs.len() {
            let slot = 5 + i;
            let irq = *ISA_IRQ_POOL.get(slot).ok_or_else(|| {
                anyhow!(
                    "too many --share directories for x86 (max {})",
                    MAX_FS_DEVICES
                )
            })?;
            devices.push((VIRTIOFS_BASE_START + i as u64 * VIRTIOFS_SIZE, irq));
        }
        // When networking is disabled the net region is still first in the
        // mmio table — describe only real devices, keeping index order.
        let mut described: Vec<(u64, u32)> = Vec::new();
        for (idx, (base, irq)) in devices.iter().enumerate() {
            let present = match idx {
                0 => self.net.is_some(),
                1 => true,                          // console always present
                2 => self.blk.is_some(),            // root blk
                3 => self.data_blk.is_some(),       // data blk
                4 => self.rng.is_some(),            // rng
                _ => idx - 5 < self.virtiofs.len(), // virtiofs
            };
            if present {
                described.push((*base, *irq));
            }
        }
        for (base, irq) in &described {
            cmdline.push_str(&format!(" virtio_mmio.device=512@0x{base:x}:{irq}"));
        }

        // ── hvm_start_info + e820 + cmdline (low memory) ───────────────
        let write_guest = |mem: &mut [u8], addr: u64, data: &[u8]| -> Result<()> {
            let start = (addr - RAM_BASE) as usize;
            if start + data.len() > mem.len() {
                anyhow::bail!("PVH boot structures do not fit in RAM");
            }
            mem[start..start + data.len()].copy_from_slice(data);
            Ok(())
        };

        let cmdline_bytes = cmdline.as_bytes();
        write_guest(
            self.memory.as_shared_slice(),
            PVH_CMDLINE_ADDR,
            cmdline_bytes,
        )?;
        write_guest(
            self.memory.as_shared_slice(),
            PVH_CMDLINE_ADDR + cmdline_bytes.len() as u64,
            &[0],
        )?;

        // e820-style memory map: low RAM, the legacy hole, extended RAM.
        let mem_size = self.memory.len() as u64;
        let mut memmap: Vec<u8> = Vec::new();
        let push_entry = |memmap: &mut Vec<u8>, addr: u64, size: u64, typ: u32| {
            memmap.extend_from_slice(&addr.to_le_bytes());
            memmap.extend_from_slice(&size.to_le_bytes());
            memmap.extend_from_slice(&typ.to_le_bytes());
            memmap.extend_from_slice(&0u32.to_le_bytes());
        };
        let low_ram_end = 0x9_FC00u64.min(mem_size);
        if low_ram_end > 0 {
            push_entry(&mut memmap, 0x0, low_ram_end, E820_RAM);
        }
        if mem_size > 0x100_000 {
            push_entry(&mut memmap, 0x9_FC00, 0x10_0000 - 0x9_FC00, E820_RESERVED);
            push_entry(&mut memmap, 0x10_0000, mem_size - 0x10_0000, E820_RAM);
        }
        write_guest(self.memory.as_shared_slice(), PVH_MEMMAP_ADDR, &memmap)?;

        // struct hvm_start_info (version 1, with the memory map). Field
        // order per include/xen/interface/hvm/start_info.h: magic, version,
        // flags, nr_modules (u32), modlist_paddr (u64), cmdline_paddr (u64),
        // rsdp_paddr (u64), memmap_paddr (u64), memmap_entries (u32),
        // reserved (u32) — 56 bytes total.
        let mut start_info = Vec::new();
        start_info.extend_from_slice(&0x336e_c578u32.to_le_bytes()); // magic
        start_info.extend_from_slice(&1u32.to_le_bytes()); // version
        start_info.extend_from_slice(&0u32.to_le_bytes()); // flags
        start_info.extend_from_slice(&0u32.to_le_bytes()); // nr_modules
        start_info.extend_from_slice(&0u64.to_le_bytes()); // modlist_paddr
        start_info.extend_from_slice(&PVH_CMDLINE_ADDR.to_le_bytes());
        start_info.extend_from_slice(&0u64.to_le_bytes()); // rsdp_paddr
        start_info.extend_from_slice(&PVH_MEMMAP_ADDR.to_le_bytes());
        start_info.extend_from_slice(&((memmap.len() / 24) as u32).to_le_bytes());
        start_info.extend_from_slice(&0u32.to_le_bytes()); // reserved
        write_guest(
            self.memory.as_shared_slice(),
            PVH_START_INFO_ADDR,
            &start_info,
        )?;

        // ── Initial vCPU state ─────────────────────────────────────────
        self.vcpu.set_supported_cpuid()?;
        self.vcpu.init_pvh(entry, PVH_START_INFO_ADDR)?;
        if std::env::var_os("SANDAL_X86_TRACE").is_some() {
            self.vcpu.set_guest_debug_singlestep()?;
        }
        Ok(())
    }
}

/// Handle one KVM exit on x86_64.
#[cfg(target_os = "linux")]
impl Vmm {
    pub(super) fn handle_kvm_exit(&mut self, exit: crate::hypervisor::KvmExit) -> Result<()> {
        use crate::hypervisor::KvmExit;
        match exit {
            KvmExit::Mmio {
                addr,
                len,
                is_write,
                data,
            } => {
                if is_write {
                    let mut val = 0u64;
                    for (i, b) in data.iter().take(len).enumerate() {
                        val |= (*b as u64) << (8 * i);
                    }
                    self.mmio_write(addr, len, val);
                } else {
                    // sas == log2(len); KVM handles sign-extension.
                    let sas = len.trailing_zeros().min(3) as u8;
                    let val = self.mmio_read(addr, len, sas);
                    self.vcpu.fill_mmio_read(&val.to_le_bytes()[..len]);
                }
            }
            KvmExit::Io {
                port,
                len,
                is_write,
                value,
            } => {
                self.handle_pio(port, len, is_write, value);
            }

            KvmExit::Hlt => {
                // The in-kernel PIC wakes a halted vCPU on injected IRQs;
                // a bare HLT exit is spurious — just re-enter.
            }
            KvmExit::SystemEvent(_) => {
                self.guest_shutdown = true;
            }
            KvmExit::FailEntry(reason) => {
                anyhow::bail!(
                    "KVM failed to enter the guest (hardware_entry_failure_reason=0x{reason:x})"
                );
            }
            KvmExit::InternalError(sub) => {
                anyhow::bail!("KVM internal error (suberror {sub})");
            }
            KvmExit::Unknown(r) => {
                log::warn!("unexpected KVM exit reason {r}");
            }
            KvmExit::DebugX86 { exception, pc, dr6 } => {
                use std::sync::atomic::{AtomicU64, Ordering};
                static LAST_PC: AtomicU64 = AtomicU64::new(0);
                let last = LAST_PC.swap(pc, Ordering::Relaxed);
                if last != pc {
                    eprintln!("trace: exc={exception} pc=0x{pc:x} dr6=0x{dr6:x}");
                }
            }
        }
        Ok(())
    }
}

impl Vmm {
    #[cfg(target_arch = "x86_64")]
    pub(super) fn handle_pio(&mut self, port: u16, len: usize, is_write: bool, value: u64) {
        if (SERIAL_BASE..SERIAL_BASE + 8).contains(&port) {
            if is_write {
                // THR: absorb (verbose mode mirrors the HVF PL011 stub).
                if port == SERIAL_BASE && self.verbose_uart {
                    eprint!("{}", (value & 0xff) as u8 as char);
                }
            } else {
                // IN: LSR reads report TX ready; everything else reads 0.
                let val: u64 = if port == SERIAL_BASE + 5 { 0x60 } else { 0 };
                self.vcpu.fill_io_read(self.vcpu.io_data_offset(), len, val);
            }
            return;
        }
        // Rate-limit: some probes (PCI conf, i8042, RTC) poll repeatedly.
        // These accesses are expected on a PVH guest without ACPI — the
        // kernel simply probes legacy hardware and we ignore it — so they
        // are debug-level; `-v` shows a sampled trace.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEEN: AtomicU64 = AtomicU64::new(0);
        let n = SEEN.fetch_add(1, Ordering::Relaxed);
        if n < 8 || n.is_power_of_two() {
            log::debug!(
                "unhandled PIO {} port 0x{port:x} (x{n})",
                if is_write { "write" } else { "read" }
            );
        }
    }
}

/// Legacy ISA GSI for a device slot (matches the cmdline IRQ assignment).
pub(super) fn x86_irq_for_slot(slot: usize) -> u32 {
    ISA_IRQ_POOL[slot]
}
