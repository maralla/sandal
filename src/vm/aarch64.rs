//! ARM64 guest specifics: physical memory map, `Image` + DTB boot, the
//! `BRK #imm` hypercall protocol, and the PL011 earlycon stub.
//!
//! Applies to both macOS (HVF) and Linux (KVM): the guest kernel artifact and
//! boot flow are identical; only the hypervisor differs (see [`super::macos`]
//! and the KVM setup in [`super::Vmm::new`]).

use super::{
    resolve_data_path, Args, Vmm, DATA_BLK_BASE, SPI_BLK, SPI_DATA_BLK, SPI_FS_START, SPI_NET,
    SPI_RNG, SPI_VSOCK, VIRTIOFS_BASE_START, VIRTIOFS_SIZE, VIRTIO_BLK_BASE, VIRTIO_NET_BASE,
    VIRTIO_RNG_BASE, VIRTIO_VSOCK_BASE,
};
use crate::devicetree::DeviceTree;
use crate::hypervisor::Reg;
use crate::initramfs;
use anyhow::Result;
use std::fs;

// ── Guest physical memory map (must match src/devicetree.rs) ────────────
pub(crate) const RAM_BASE: u64 = 0x4000_0000;
const KERNEL_LOAD_ADDR: u64 = 0x4020_0000; // 2 MB aligned
const DTB_ADDR: u64 = 0x4800_0000; // 128 MB offset, well past the kernel image

pub(super) const GICD_BASE: u64 = 0x0800_0000;
pub(super) const GICD_SIZE: u64 = 0x1_0000;
pub(super) const GICR_BASE: u64 = 0x080A_0000;
pub(super) const GICR_SIZE: u64 = 0x2_0000; // 2 × 64 KB frames for 1 CPU

pub(super) const UART_BASE: u64 = 0x0900_0000;

pub(super) const KERNEL_ARTIFACT: &str = "vmlinux-sandal-aarch64";

/// The kernel embedded in release builds (`make dist`): zstd-compressed,
/// decompressed at boot like the built-in rootfs payload. Dev builds
/// compile to `None` and keep the data-path lookup.
#[cfg(sandal_embed_kernel)]
fn embedded_kernel() -> Option<Vec<u8>> {
    const BUILTIN_KERNEL_ZST: &[u8] = include_bytes!("../kernel-aarch64.zst");
    Some(zstd::decode_all(BUILTIN_KERNEL_ZST).expect("failed to decompress embedded kernel"))
}

#[cfg(not(sandal_embed_kernel))]
fn embedded_kernel() -> Option<Vec<u8>> {
    None
}
pub(crate) const MAX_FS_DEVICES: usize = 8;

impl Vmm {
    #[cfg(target_arch = "aarch64")]
    pub(super) fn boot_kernel_arm64(&mut self, args: &Args) -> Result<()> {
        // ── Load the kernel Image ──────────────────────────────────────
        let kernel: Vec<u8> = if let Some(path) = &args.kernel {
            fs::read(path)?
        } else if let Some(image) = embedded_kernel() {
            image
        } else if let Some(path) = resolve_data_path(KERNEL_ARTIFACT) {
            fs::read(path)?
        } else {
            anyhow::bail!("kernel image not found")
        };
        if kernel.len() < 64 {
            anyhow::bail!("kernel image too small");
        }
        // Linux arm64 Image header: text_offset at 0x08, image_size at 0x10.
        let text_offset = u64::from_le_bytes(kernel[0x08..0x10].try_into()?);
        let image_size = u64::from_le_bytes(kernel[0x10..0x18].try_into()?);
        let load = KERNEL_LOAD_ADDR + text_offset;
        let size = image_size as usize;
        if load + size as u64 > RAM_BASE + self.memory.len() as u64 {
            anyhow::bail!("kernel image does not fit in RAM");
        }
        let mem = self.memory.as_shared_slice();
        mem[(load - RAM_BASE) as usize..(load - RAM_BASE) as usize + kernel.len()]
            .copy_from_slice(&kernel);

        // ── Build the DTB ──────────────────────────────────────────────
        let virtiofs_dt: Vec<(u64, u32)> = (0..self.virtiofs.len())
            .map(|i| {
                (
                    VIRTIOFS_BASE_START + i as u64 * VIRTIOFS_SIZE,
                    SPI_FS_START + i as u32,
                )
            })
            .collect();
        let dtb = DeviceTree::build(
            self.memory.len() as u64,
            UART_BASE,
            GICD_BASE,
            GICD_SIZE as usize,
            GICR_BASE,
            GICR_SIZE as usize,
            self.net
                .lock()
                .unwrap()
                .as_ref()
                .map(|_| (VIRTIO_NET_BASE, SPI_NET)),
            Some((VIRTIO_BLK_BASE, SPI_BLK)), // vda (root)
            self.data_blk
                .as_ref()
                .map(|_| (DATA_BLK_BASE, SPI_DATA_BLK)), // vdb (overlay upper)
            self.rng.as_ref().map(|_| (VIRTIO_RNG_BASE, SPI_RNG)),
            &virtiofs_dt,
            self.vsock.as_ref().map(|_| (VIRTIO_VSOCK_BASE, SPI_VSOCK)),
            args.verbose,
            None,             // overlay bootarg handled by the guest init from the config
            Some(&[0u8; 64]), // rng-seed so CRNG never blocks at boot
        )?;
        let dtb_start = DTB_ADDR - RAM_BASE;
        if dtb_start as usize + dtb.len() > self.memory.len() {
            anyhow::bail!("DTB does not fit in RAM");
        }
        let mem = self.memory.as_shared_slice();
        mem[dtb_start as usize..dtb_start as usize + dtb.len()].copy_from_slice(&dtb);

        // ── Set the initial vCPU state (Linux arm64 boot protocol) ────
        // Enter at EL1h, all interrupts masked, MMU off (reset SCTLR).
        self.vcpu.write_register(Reg::Pc, load)?;
        self.vcpu.write_register(Reg::X0, DTB_ADDR)?;
        self.vcpu.write_register(Reg::X1, 0)?;
        self.vcpu.write_register(Reg::X2, 0)?;
        self.vcpu.write_register(Reg::X3, 0)?;
        self.vcpu.write_register(Reg::Cpsr, 0x3c5)?; // EL1h, DAIF=1111
        Ok(())
    }
}

/// Handle one KVM exit on arm64.
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
            KvmExit::Debug { hsr } => {
                let ec = (hsr >> 26) & 0x3f;
                if ec == EC_BRK {
                    // The vCPU PC still points at the BRK instruction;
                    // handle_brk decodes the immediate and advances it.
                    self.handle_brk((hsr & 0xffff) as u64)?;
                } else {
                    // Only BRK traps are enabled (KVM_GUESTDBG_USE_SW_BP);
                    // anything else would be a bug — skip the instruction.
                    log::warn!("unexpected debug exception ESR=0x{hsr:08x}");
                    let pc = self.vcpu.read_register(Reg::Pc)?;
                    self.vcpu.write_register(Reg::Pc, pc + 4)?;
                }
            }
            KvmExit::SystemEvent(_) => {
                // PSCI SYSTEM_OFF / SYSTEM_RESET (handled in-kernel).
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
            KvmExit::Io { .. } | KvmExit::Hlt => unreachable!("x86-only exits on arm64"),
        }
        Ok(())
    }
}

impl Vmm {
    pub(super) fn handle_brk(&mut self, syndrome: u64) -> Result<()> {
        let imm = (syndrome & 0xffff) as u32;
        let pc = self.vcpu.read_register(Reg::Pc)?;
        self.vcpu.write_register(Reg::Pc, pc + 4)?;
        match imm {
            initramfs::EXPORT_RESIZE_IMM => self.handle_export_resize(),
            initramfs::EXPORT_DONE_IMM => self.handle_export_done(),
            // The exit protocol: the code rides x15 (marker-free — the old
            // fixed `SANDAL_EXIT:<code>` stdout marker is gone).
            initramfs::EXIT_IMM => {
                let code = self.vcpu.read_register(Reg::X15)? as u32 as i32;
                self.guest_exit_code = Some(code);
                self.guest_shutdown = true;
            }
            // The command execution line's readiness: vsockd's listener is
            // bound — connect every parked front end now (the event-driven
            // connect; the x86_64 hypercall store's BRK analog).
            initramfs::VSOCKD_READY_IMM => {
                log::info!("vsockd: the READY brk landed");
                if let Some(vsock) = self.vsock.as_ref() {
                    vsock.device.lock().unwrap().set_guest_listening();
                }
            }
            // Unknown BRKs are resumed; the protocol has no other
            // immediate values.
            _ => {}
        }
        Ok(())
    }

    /// Minimal PL011 for earlycon: absorb writes, report TX empty / RX empty.
    pub(super) fn uart_read(&self, off: u64) -> u64 {
        match off {
            0x018 => 0x10, // FR: RXFE=1 (empty), TXFF=0 (ready)
            _ => 0,
        }
    }

    pub(super) fn uart_write(&mut self, off: u64, val: u64) {
        if off == 0x000 && self.verbose_uart {
            eprint!("{}", (val & 0xff) as u8 as char);
        }
        let _ = val;
    }
}

/// Exception class (EC field, bits 31..26 of the syndrome): BRK.
#[cfg_attr(target_os = "macos", allow(dead_code))]
const EC_BRK: u32 = 0x3c;
