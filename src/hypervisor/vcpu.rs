use super::ffi::*;
use anyhow::Result;
use std::ptr;

#[cfg(target_arch = "aarch64")]
use super::ffi::{
    hv_vcpu_get_vtimer_mask_wrapper, hv_vcpu_get_vtimer_offset_wrapper,
    hv_vcpu_read_sys_reg_wrapper, hv_vcpu_set_vtimer_mask_wrapper,
    hv_vcpu_set_vtimer_offset_wrapper, hv_vcpu_write_sys_reg_wrapper, HvSysReg,
};

pub struct Vcpu {
    id: HvVcpu,
    exit_info: *mut HvVcpuExit,
}

impl Vcpu {
    /// Create a new virtual CPU
    pub fn new() -> Result<Self> {
        let mut id: HvVcpu = 0;
        let mut exit_info: *mut HvVcpuExit = ptr::null_mut();

        let ret = unsafe { hv_vcpu_create_wrapper(&mut id, &mut exit_info) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to create VCPU: error code {ret}");
        }

        Ok(Vcpu { id, exit_info })
    }

    /// Run the virtual CPU
    pub fn run(&self) -> Result<u32> {
        let ret = unsafe { hv_vcpu_run_wrapper(self.id) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to run VCPU: error code {ret}");
        }

        // Return exit reason
        let reason = unsafe { (*self.exit_info).reason };
        Ok(reason)
    }

    /// Read a CPU register
    pub fn read_register(&self, reg: HvReg) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { hv_vcpu_read_register_wrapper(self.id, reg as u32, &mut value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to read register: error code {ret}");
        }

        Ok(value)
    }

    /// Write a CPU register
    pub fn write_register(&self, reg: HvReg, value: u64) -> Result<()> {
        let ret = unsafe { hv_vcpu_write_register_wrapper(self.id, reg as u32, value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to write register: error code {ret}");
        }

        Ok(())
    }

    /// Get the VCPU ID
    pub fn id(&self) -> HvVcpu {
        self.id
    }

    pub fn read_exception_syndrome(&self) -> Result<u64> {
        if self.exit_info.is_null() {
            anyhow::bail!("Exit info is NULL");
        }

        unsafe { Ok((*self.exit_info).exception.syndrome) }
    }

    pub fn read_fault_address(&self) -> Result<u64> {
        if self.exit_info.is_null() {
            anyhow::bail!("Exit info is NULL");
        }

        unsafe { Ok((*self.exit_info).exception.physical_address) }
    }

    /// Read an ARM64 system register
    #[cfg(target_arch = "aarch64")]
    pub fn read_sys_register(&self, reg: HvSysReg) -> Result<u64> {
        let mut value: u64 = 0;
        let ret = unsafe { hv_vcpu_read_sys_reg_wrapper(self.id, reg as u32, &mut value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to read system register: error code {ret}");
        }

        Ok(value)
    }

    /// Write an ARM64 system register
    #[cfg(target_arch = "aarch64")]
    pub fn write_sys_register(&self, reg: HvSysReg, value: u64) -> Result<()> {
        let ret = unsafe { hv_vcpu_write_sys_reg_wrapper(self.id, reg as u32, value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to write system register: error code {ret}");
        }

        Ok(())
    }

    /// Set the VTimer mask
    #[cfg(target_arch = "aarch64")]
    pub fn set_vtimer_mask(&self, masked: bool) -> Result<()> {
        let ret = unsafe { hv_vcpu_set_vtimer_mask_wrapper(self.id, masked) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to set vtimer mask: error code {ret}");
        }

        Ok(())
    }

    /// Get the VTimer mask
    #[cfg(target_arch = "aarch64")]
    pub fn get_vtimer_mask(&self) -> Result<bool> {
        let mut masked = false;
        let ret = unsafe { hv_vcpu_get_vtimer_mask_wrapper(self.id, &mut masked) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to get vtimer mask: error code {ret}");
        }

        Ok(masked)
    }

    /// Set the VTimer offset
    #[cfg(target_arch = "aarch64")]
    pub fn set_vtimer_offset(&self, offset: u64) -> Result<()> {
        let ret = unsafe { hv_vcpu_set_vtimer_offset_wrapper(self.id, offset) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to set vtimer offset: error code {ret}");
        }

        Ok(())
    }

    /// Get the VTimer offset
    #[cfg(target_arch = "aarch64")]
    pub fn get_vtimer_offset(&self) -> Result<u64> {
        let mut offset = 0;
        let ret = unsafe { hv_vcpu_get_vtimer_offset_wrapper(self.id, &mut offset) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to get vtimer offset: error code {ret}");
        }

        Ok(offset)
    }

    /// Force exit of VCPUs (ARM64 only)
    #[cfg(target_arch = "aarch64")]
    pub fn force_exit(vcpu_ids: &[u64]) -> Result<()> {
        use super::ffi::hv_vcpus_exit_wrapper;

        let ret =
            unsafe { hv_vcpus_exit_wrapper(vcpu_ids.as_ptr() as *mut _, vcpu_ids.len() as u32) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to force vcpu exit: error code {ret}");
        }

        Ok(())
    }

    /// Set a pending interrupt on the VCPU (ARM64 only)
    /// int_type: 0 = IRQ, 1 = FIQ
    #[cfg(target_arch = "aarch64")]
    pub fn set_pending_interrupt(&self, int_type: u32, pending: bool) -> Result<()> {
        use super::ffi::hv_vcpu_set_pending_interrupt_wrapper;

        let ret = unsafe { hv_vcpu_set_pending_interrupt_wrapper(self.id, int_type, pending) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to set pending interrupt: error code {ret}");
        }

        Ok(())
    }

    /// Set trap for debug exceptions (ARM64 only)
    #[cfg(target_arch = "aarch64")]
    pub fn set_trap_debug_exceptions(&self, value: bool) -> Result<()> {
        use super::ffi::hv_vcpu_set_trap_debug_exceptions_wrapper;

        let ret = unsafe { hv_vcpu_set_trap_debug_exceptions_wrapper(self.id, value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to set trap debug exceptions: error code {ret}");
        }

        Ok(())
    }

    /// Read a GIC ICC (CPU interface) register
    #[cfg(target_arch = "aarch64")]
    pub fn get_icc_reg(&self, reg: HvGicIccReg) -> Result<u64> {
        use super::ffi::hv_gic_get_icc_reg_wrapper;

        let mut value: u64 = 0;
        let ret = unsafe { hv_gic_get_icc_reg_wrapper(self.id, reg as u16, &mut value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to read ICC register {:?}: error code {ret}", reg);
        }

        Ok(value)
    }

    /// Write a GIC ICC (CPU interface) register
    #[cfg(target_arch = "aarch64")]
    pub fn set_icc_reg(&self, reg: HvGicIccReg, value: u64) -> Result<()> {
        use super::ffi::hv_gic_set_icc_reg_wrapper;

        let ret = unsafe { hv_gic_set_icc_reg_wrapper(self.id, reg as u16, value) };

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to write ICC register {:?}: error code {ret}", reg);
        }

        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        unsafe {
            let ret = hv_vcpu_destroy_wrapper(self.id);
            if ret != HV_SUCCESS {
                log::warn!("Failed to destroy VCPU: error code {ret}");
            }
        }
    }
}
