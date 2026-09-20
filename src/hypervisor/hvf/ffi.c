#include <Hypervisor/Hypervisor.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// C wrapper functions for Hypervisor.framework.
// These provide a simpler, stable interface for the Rust FFI in ffi.rs.
// Only the HVF surface used by the software-GIC VMM is wrapped: the native
// GIC (hv_gic_*) is deliberately not created (see docs/vmm-spec.md).

int hv_vm_create_wrapper(uint64_t flags __attribute__((unused))) {
    return hv_vm_create(NULL);
}

int hv_vm_destroy_wrapper(void) {
    return hv_vm_destroy();
}

int hv_vm_map_wrapper(void *addr, uint64_t gpa, size_t size, uint64_t flags) {
    return hv_vm_map(addr, gpa, size, flags);
}

int hv_vcpu_create_wrapper(uint32_t *vcpu, void **exit_info) {
    hv_vcpu_t vcpu_id;

#ifdef __aarch64__
    hv_vcpu_config_t config = hv_vcpu_config_create();
    int ret = hv_vcpu_create(&vcpu_id, (hv_vcpu_exit_t **)exit_info, config);
    if (config) {
        extern void os_release(void *);
        os_release(config);
    }
#else
    int ret = hv_vcpu_create(&vcpu_id, (hv_vcpu_exit_t **)exit_info, NULL);
#endif

    *vcpu = vcpu_id;
    return ret;
}

int hv_vcpu_destroy_wrapper(uint32_t vcpu) {
    return hv_vcpu_destroy((hv_vcpu_t)vcpu);
}

int hv_vcpu_run_wrapper(uint32_t vcpu) {
    return hv_vcpu_run((hv_vcpu_t)vcpu);
}

#ifdef __aarch64__
// ARM64 register access
int hv_vcpu_read_register_wrapper(uint32_t vcpu, uint32_t reg, uint64_t *value) {
    return hv_vcpu_get_reg((hv_vcpu_t)vcpu, (hv_reg_t)reg, value);
}

int hv_vcpu_write_register_wrapper(uint32_t vcpu, uint32_t reg, uint64_t value) {
    return hv_vcpu_set_reg((hv_vcpu_t)vcpu, (hv_reg_t)reg, value);
}

// ARM64 system register access
int hv_vcpu_read_sys_reg_wrapper(uint32_t vcpu, uint32_t reg, uint64_t *value) {
    return hv_vcpu_get_sys_reg((hv_vcpu_t)vcpu, (hv_sys_reg_t)reg, value);
}

int hv_vcpu_write_sys_reg_wrapper(uint32_t vcpu, uint32_t reg, uint64_t value) {
    return hv_vcpu_set_sys_reg((hv_vcpu_t)vcpu, (hv_sys_reg_t)reg, value);
}

// Interrupt delivery: a bare IRQ/FIQ line assert consumed at hv_vcpu_run entry.
int hv_vcpu_set_pending_interrupt_wrapper(uint32_t vcpu, uint32_t type, bool pending) {
    return hv_vcpu_set_pending_interrupt((hv_vcpu_t)vcpu, (hv_interrupt_type_t)type, pending);
}

// VTimer mask: set automatically on HV_EXIT_REASON_VTIMER_ACTIVATED, cleared by
// the VMM when the guest EOIs the vtimer interrupt.
int hv_vcpu_set_vtimer_mask_wrapper(uint32_t vcpu, bool vtimer_is_masked) {
    return hv_vcpu_set_vtimer_mask((hv_vcpu_t)vcpu, vtimer_is_masked);
}

// VTimer offset (CNTVOFF_EL2): set once at VM creation.
int hv_vcpu_set_vtimer_offset_wrapper(uint32_t vcpu, uint64_t vtimer_offset) {
    return hv_vcpu_set_vtimer_offset((hv_vcpu_t)vcpu, vtimer_offset);
}

// Trap debug exceptions (BRK) to EL2 so the guest init's BRK protocol reaches
// the VMM instead of being delivered to the guest as SIGTRAP.
int hv_vcpu_set_trap_debug_exceptions_wrapper(uint32_t vcpu, bool value) {
    return hv_vcpu_set_trap_debug_exceptions((hv_vcpu_t)vcpu, value);
}

// Force one or more vCPUs out of hv_vcpu_run (CANCELED exit).  Used by the
// network poller to wake an idle guest when host sockets become readable.
int hv_vcpus_exit_wrapper(uint64_t *vcpus, uint32_t vcpu_count) {
    return hv_vcpus_exit((hv_vcpu_t *)vcpus, vcpu_count);
}
#else
// x86_64 register access
int hv_vcpu_read_register_wrapper(uint32_t vcpu, uint32_t reg, uint64_t *value) {
    return hv_vcpu_read_register((hv_vcpu_t)vcpu, (hv_x86_reg_t)reg, value);
}

int hv_vcpu_write_register_wrapper(uint32_t vcpu, uint32_t reg, uint64_t value) {
    return hv_vcpu_write_register((hv_vcpu_t)vcpu, (hv_x86_reg_t)reg, value);
}
#endif
