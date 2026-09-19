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

        // HVF's native GIC (`hv_gic_create`) is intentionally not used; the
        // software GIC lives in `src/gic.rs` (see docs/vmm-spec.md §1.1/§1.3).
        // The guest's arch timer depends on the documented vtimer mask flow:
        // HVF masks the vtimer on HV_EXIT_REASON_VTIMER_ACTIVATED, and it may
        // only be unmasked once the guest has serviced INTID 27 (unmasking
        // earlier re-fires the still-expired comparator).  Observing that EOI
        // requires the ICC sysregs to trap, which only happens while HVF does
        // not own the GIC.  With the native GIC the vtimer fires once and then
        // stays masked, which is why the previous timer workarounds existed.
        Ok(Vm {
            _marker: std::marker::PhantomData,
        })
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
