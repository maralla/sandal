#![allow(dead_code)]

use super::ffi::*;
use anyhow::Result;
use std::ffi::c_void;

pub struct Vm {
    _marker: std::marker::PhantomData<()>,
}

impl Vm {
    /// Create a new VM instance
    pub fn new() -> Result<Self> {
        let ret = unsafe { hv_vm_create_wrapper(0) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to create VM: error code {ret}");
        }

        // Set up GIC for interrupt handling (required for timer, UART, etc.)
        #[cfg(target_arch = "aarch64")]
        {
            Self::setup_gic()?;
        }

        Ok(Vm {
            _marker: std::marker::PhantomData,
        })
    }

    /// Setup GIC (Generic Interrupt Controller) for ARM64
    #[cfg(target_arch = "aarch64")]
    fn setup_gic() -> Result<()> {
        use super::ffi::*;

        // GIC setup (silent unless error)

        // Query GIC parameters first
        let mut dist_size: usize = 0;
        let mut dist_align: usize = 0;
        let mut redist_region_size: usize = 0;
        let mut redist_per_cpu_size: usize = 0;
        let mut redist_align: usize = 0;

        unsafe {
            hv_gic_get_distributor_size_wrapper(&mut dist_size);
            hv_gic_get_distributor_base_alignment_wrapper(&mut dist_align);
            hv_gic_get_redistributor_region_size_wrapper(&mut redist_region_size);
            hv_gic_get_redistributor_size_wrapper(&mut redist_per_cpu_size);
            hv_gic_get_redistributor_base_alignment_wrapper(&mut redist_align);
        }

        // GIC addresses, aligned to HVF requirements
        let gic_dist_base: u64 = 0x08000000;
        // Align redistributor base to HVF's required alignment
        let redist_base_unaligned = gic_dist_base + dist_size as u64;
        let gic_redist_base = if redist_align > 0 {
            (redist_base_unaligned + redist_align as u64 - 1) & !(redist_align as u64 - 1)
        } else {
            redist_base_unaligned
        };

        let config = unsafe { hv_gic_config_create_wrapper() };
        if config.is_null() {
            anyhow::bail!("Failed to create GIC config");
        }

        let ret = unsafe {
            let mut r = hv_gic_config_set_distributor_base_wrapper(config, gic_dist_base);
            if r != HV_SUCCESS {
                hv_gic_config_release_wrapper(config);
                return Err(anyhow::anyhow!(
                    "Failed to set GIC distributor base: error code {r}"
                ));
            }

            r = hv_gic_config_set_redistributor_base_wrapper(config, gic_redist_base);
            if r != HV_SUCCESS {
                hv_gic_config_release_wrapper(config);
                return Err(anyhow::anyhow!(
                    "Failed to set GIC redistributor base: error code {r}"
                ));
            }

            r = hv_gic_create_wrapper(config);
            hv_gic_config_release_wrapper(config);
            r
        };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to create GIC: error code {ret}");
        }

        // Query SPI range
        let mut spi_base: u32 = 0;
        let mut spi_count: u32 = 0;
        unsafe {
            hv_gic_get_spi_interrupt_range_wrapper(&mut spi_base, &mut spi_count);
        }

        Ok(())
    }

    /// Query GIC redistributor and distributor sizes for device tree
    #[cfg(target_arch = "aarch64")]
    pub fn query_gic_params() -> (u64, usize, u64, usize) {
        use super::ffi::*;

        let mut dist_size: usize = 0;
        let mut dist_align: usize = 0;
        let mut redist_per_cpu: usize = 0;
        let mut redist_align: usize = 0;

        unsafe {
            hv_gic_get_distributor_size_wrapper(&mut dist_size);
            hv_gic_get_distributor_base_alignment_wrapper(&mut dist_align);
            hv_gic_get_redistributor_size_wrapper(&mut redist_per_cpu);
            hv_gic_get_redistributor_base_alignment_wrapper(&mut redist_align);
        }

        let gic_dist_base: u64 = 0x08000000;
        let redist_base_unaligned = gic_dist_base + dist_size as u64;
        let gic_redist_base = if redist_align > 0 {
            (redist_base_unaligned + redist_align as u64 - 1) & !(redist_align as u64 - 1)
        } else {
            redist_base_unaligned
        };

        // Use per-CPU redistributor size × number of CPUs (1 CPU for now)
        // NOT the full region size (which can be 32 MB and overlap with UART!)
        let num_cpus: usize = 1;
        let redist_size = redist_per_cpu * num_cpus;

        (gic_dist_base, dist_size, gic_redist_base, redist_size)
    }

    /// Map host memory into guest physical address space
    pub fn map_memory(
        &self,
        host_addr: *mut c_void,
        guest_addr: u64,
        size: usize,
        flags: u64,
    ) -> Result<()> {
        let ret = unsafe { hv_vm_map_wrapper(host_addr, guest_addr, size, flags) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to map memory at 0x{guest_addr:x}: error code {ret}");
        }

        Ok(())
    }

    /// Set GIC SPI interrupt level
    /// `spi_num` is the SPI number (0-based, as used in the device tree).
    /// The actual GIC interrupt ID is spi_num + 32.
    #[cfg(target_arch = "aarch64")]
    pub fn set_gic_spi(spi_num: u32, level: bool) {
        unsafe {
            let intid = spi_num + 32; // SPIs start at GIC interrupt ID 32
            let ret = hv_gic_set_spi_wrapper(intid, level);
            if ret != HV_SUCCESS {
                log::warn!("hv_gic_set_spi(intid={intid}, level={level}) failed: {ret}");
            }
        }
    }

    /// Save GIC state as an opaque byte blob (macOS 15.0+).
    /// Returns None if GIC state saving is not supported.
    #[cfg(target_arch = "aarch64")]
    pub fn save_gic_state() -> Option<Vec<u8>> {
        use super::ffi::{hv_gic_state_save_wrapper, HV_SUCCESS};

        // First call: get the size
        let mut size: usize = 0;
        let ret = unsafe { hv_gic_state_save_wrapper(std::ptr::null_mut(), &mut size) };
        if ret != HV_SUCCESS || size == 0 {
            return None;
        }

        // Second call: get the data
        let mut data = vec![0u8; size];
        let ret = unsafe { hv_gic_state_save_wrapper(data.as_mut_ptr(), &mut size) };
        if ret != HV_SUCCESS {
            return None;
        }
        data.truncate(size);
        Some(data)
    }

    /// Restore GIC state from an opaque byte blob (macOS 15.0+).
    #[cfg(target_arch = "aarch64")]
    pub fn restore_gic_state(data: &[u8]) -> Result<()> {
        use super::ffi::{hv_gic_state_restore_wrapper, HV_SUCCESS};

        let ret = unsafe { hv_gic_state_restore_wrapper(data.as_ptr(), data.len()) };
        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to restore GIC state: error code {ret}");
        }
        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        unsafe {
            let ret = hv_vm_destroy_wrapper();
            if ret != HV_SUCCESS {
                log::warn!("Failed to destroy VM: error code {ret}");
            }
        }
    }
}
