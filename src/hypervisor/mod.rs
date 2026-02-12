mod ffi;
pub mod vcpu;
pub mod vm;

use anyhow::Result;

pub use ffi::{HvReg, HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE};
pub use vcpu::Vcpu;
pub use vm::Vm;

#[cfg(target_arch = "aarch64")]
pub use ffi::HvGicIccReg;
#[cfg(target_arch = "aarch64")]
pub use ffi::HvSysReg;

/// Check if Hypervisor framework is available
pub fn check_hypervisor_support() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("Hypervisor framework is only available on macOS")
    }
}

/// Initialize the hypervisor subsystem
pub fn init() -> Result<()> {
    check_hypervisor_support()?;
    Ok(())
}
