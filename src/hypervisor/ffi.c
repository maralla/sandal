#include <Hypervisor/Hypervisor.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// C wrapper functions for Hypervisor framework
// These provide a simpler interface for Rust FFI

int hv_vm_create_wrapper(uint64_t flags __attribute__((unused))) {
    return hv_vm_create(NULL);
}

int hv_vm_destroy_wrapper(void) {
    return hv_vm_destroy();
}

int hv_vm_map_wrapper(void *addr, uint64_t gpa, size_t size, uint64_t flags) {
    return hv_vm_map(addr, gpa, size, flags);
}

int hv_vm_unmap_wrapper(uint64_t gpa, size_t size) {
    return hv_vm_unmap(gpa, size);
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

// Interrupt functions
int hv_vcpu_set_pending_interrupt_wrapper(uint32_t vcpu, uint32_t type, bool pending) {
    return hv_vcpu_set_pending_interrupt((hv_vcpu_t)vcpu, (hv_interrupt_type_t)type, pending);
}

// VTimer functions
int hv_vcpu_set_vtimer_mask_wrapper(uint32_t vcpu, bool vtimer_is_masked) {
    return hv_vcpu_set_vtimer_mask((hv_vcpu_t)vcpu, vtimer_is_masked);
}

int hv_vcpu_get_vtimer_mask_wrapper(uint32_t vcpu, bool *vtimer_is_masked) {
    return hv_vcpu_get_vtimer_mask((hv_vcpu_t)vcpu, vtimer_is_masked);
}

int hv_vcpu_set_vtimer_offset_wrapper(uint32_t vcpu, uint64_t vtimer_offset) {
    return hv_vcpu_set_vtimer_offset((hv_vcpu_t)vcpu, vtimer_offset);
}

int hv_vcpu_get_vtimer_offset_wrapper(uint32_t vcpu, uint64_t *vtimer_offset) {
    return hv_vcpu_get_vtimer_offset((hv_vcpu_t)vcpu, vtimer_offset);
}

// Force VCPU exit
int hv_vcpus_exit_wrapper(uint32_t *vcpus, uint32_t vcpu_count) {
    return hv_vcpus_exit((hv_vcpu_t *)vcpus, vcpu_count);
}

// Trap configuration
int hv_vcpu_set_trap_debug_exceptions_wrapper(uint32_t vcpu, bool value) {
    return hv_vcpu_set_trap_debug_exceptions((hv_vcpu_t)vcpu, value);
}

// GIC (Generic Interrupt Controller) functions
void* hv_gic_config_create_wrapper(void) {
    return hv_gic_config_create();
}

int hv_gic_config_set_distributor_base_wrapper(void *config, uint64_t addr) {
    return hv_gic_config_set_distributor_base((hv_gic_config_t)config, addr);
}

int hv_gic_config_set_redistributor_base_wrapper(void *config, uint64_t addr) {
    return hv_gic_config_set_redistributor_base((hv_gic_config_t)config, addr);
}

int hv_gic_create_wrapper(void *config) {
    return hv_gic_create((hv_gic_config_t)config);
}

void hv_gic_config_release_wrapper(void *config) {
    if (config) {
        extern void os_release(void *);
        os_release(config);
    }
}

// GIC parameter query functions
int hv_gic_get_distributor_size_wrapper(size_t *size) {
    return hv_gic_get_distributor_size(size);
}

int hv_gic_get_distributor_base_alignment_wrapper(size_t *alignment) {
    return hv_gic_get_distributor_base_alignment(alignment);
}

int hv_gic_get_redistributor_region_size_wrapper(size_t *size) {
    return hv_gic_get_redistributor_region_size(size);
}

int hv_gic_get_redistributor_size_wrapper(size_t *size) {
    return hv_gic_get_redistributor_size(size);
}

int hv_gic_get_redistributor_base_alignment_wrapper(size_t *alignment) {
    return hv_gic_get_redistributor_base_alignment(alignment);
}

int hv_gic_get_redistributor_base_wrapper(uint32_t vcpu, uint64_t *base) {
    return hv_gic_get_redistributor_base((hv_vcpu_t)vcpu, base);
}

int hv_gic_get_spi_interrupt_range_wrapper(uint32_t *base, uint32_t *count) {
    return hv_gic_get_spi_interrupt_range(base, count);
}

int hv_gic_set_spi_wrapper(uint32_t intid, bool level) {
    return hv_gic_set_spi(intid, level);
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
