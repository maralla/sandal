//! Shared interrupt assignments (GIC INTIDs).
//!
//! SPIs: INTID = 32 + spi_num. These numbers are baked into the device tree
//! (`src/devicetree.rs`) and shared by both hypervisor backends:
//!
//! - macOS/HVF: driven through the software GIC
//!   (`src/hypervisor/hvf/gic.rs`).
//! - Linux/KVM: driven as level-triggered SPIs via `KVM_IRQ_LINE`.

/// Virtual timer PPI (GIC INTID 27). Only used by the HVF backend's software
/// GIC; under KVM the vtimer is fully in-kernel.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub const IRQ_VTIMER: u32 = 27;

pub const SPI_NET: u32 = 16;
pub const SPI_CONSOLE: u32 = 17;
pub const SPI_BLK: u32 = 18;
pub const SPI_DATA_BLK: u32 = 19;
pub const SPI_RNG: u32 = 20;
pub const SPI_FS_START: u32 = 21; // virtiofs devices take SPI_FS_START + i
