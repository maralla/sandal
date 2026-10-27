use super::ffi::*;
use anyhow::Result;
use std::ffi::c_void;

pub struct Vm {
    _marker: std::marker::PhantomData<()>,
}

impl Vm {
    /// Create a new VM instance.
    ///
    /// `hv_vm_create` is RETRIED with backoff: on GitHub's macOS ARM
    /// runners it fails intermittently with an undocumented 0xFAE9400F
    /// (MEASURED: 12 of 14 suite boots failed cold, two mid-run succeeded
    /// — per-call flakiness, not a leak: a dead process's VM is reaped by
    /// the kernel, and the failures started on the first boot of a fresh
    /// runner). Ten attempts ride out a busy host.
    pub fn new() -> Result<Self> {
        let mut ret = HV_SUCCESS;
        for attempt in 0..10 {
            ret = unsafe { hv_vm_create_wrapper(0) };
            if ret == HV_SUCCESS {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250 * (attempt + 1)));
        }

        if ret != HV_SUCCESS {
            anyhow::bail!("Failed to create VM: error code {ret}");
        }

        // HVF's native GIC (`hv_gic_create`) is intentionally not used; the
        // software GIC lives in this module's `gic.rs` (see docs/vmm-spec.md §1.1/§1.3).
        // The guest's arch timer depends on the documented vtimer mask flow:
        // HVF masks the vtimer on HV_EXIT_REASON_VTIMER_ACTIVATED, and it may
        // only be unmasked once the guest has serviced INTID 27 (unmasking
        // earlier re-fires the still-expired comparator).  Observing that EOI
        // requires the ICC sysregs to trap, which only happens while HVF does
        // not own the GIC — with the native GIC the vtimer fires once and
        // then stays masked.
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
