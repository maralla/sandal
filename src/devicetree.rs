/// Minimal Flattened Device Tree (FDT) builder
/// Creates a device tree blob to pass to the Linux kernel
///
/// FDT format (all big-endian):
/// 1. Header (40 bytes)
/// 2. Memory reservation map (8-byte aligned entries, terminated by {0,0})
/// 3. Structure block (tokens: BEGIN_NODE, END_NODE, PROP, END)
/// 4. Strings block (null-terminated property name strings)
use anyhow::Result;

const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_END: u32 = 0x00000009;

pub struct DeviceTree {
    dt_struct: Vec<u8>,  // Structure block
    dt_strings: Vec<u8>, // Strings block (property names)
}

impl DeviceTree {
    pub fn new() -> Self {
        DeviceTree {
            dt_struct: Vec::new(),
            dt_strings: Vec::new(),
        }
    }

    /// Build a complete device tree for ARM64 virtual machine
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        memory_size: u64,
        uart_base: u64,
        gic_dist_base: u64,
        gic_dist_size: usize,
        gic_redist_base: u64,
        gic_redist_size: usize,
        virtio_net: Option<(u64, u32)>,
        virtio_blk: Option<(u64, u32)>,
        data_blk: Option<(u64, u32)>,
        virtio_rng: Option<(u64, u32)>,
        virtiofs: &[(u64, u32)],
        virtio_console: Option<(u64, u32)>,
        verbose: bool,
        overlay_bootarg: Option<&str>,
        rng_seed: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut dt = Self::new();

        // Root node
        dt.begin_node("");
        dt.prop_u32("#address-cells", 2);
        dt.prop_u32("#size-cells", 2);
        dt.prop_string("compatible", "linux,dummy-virt");
        dt.prop_string("model", "linux,dummy-virt");
        // interrupt-parent must be a root property BEFORE child nodes
        dt.prop_u32("interrupt-parent", 0x8001);

        // Chosen node (boot arguments)
        dt.begin_node("chosen");
        {
            // earlycon=pl011 for early boot / panic messages on the MMIO UART.
            // console=hvc0 makes the virtio-console the primary interactive console.
            // random.trust_bootloader=on: seed CRNG at boot so getrandom() never blocks.
            // random.trust_cpu=on: trust CPU RNG (RNDR on ARMv8.5+) as additional entropy.
            let earlycon = "earlycon=pl011,mmio32,0x9000000 console=hvc0 random.trust_bootloader=on random.trust_cpu=on nohz=off highres=off";
            let rootfs = if virtio_blk.is_some() {
                " root=/dev/vda rw init=/init"
            } else {
                ""
            };
            // "quiet" suppresses kernel console messages above KERN_WARNING,
            // preventing printk from cluttering the interactive terminal.
            // In verbose mode we omit it so all kernel output is visible.
            let quiet = if verbose { "" } else { " quiet" };
            let overlay = overlay_bootarg
                .map(|v| format!(" overlay={v}"))
                .unwrap_or_default();
            dt.prop_string("bootargs", &format!("{earlycon}{rootfs}{quiet}{overlay}"));
        }
        // stdout-path points to the UART node for earlycon
        dt.prop_string("stdout-path", "/pl011@9000000");
        // Seed the kernel CRNG at early boot so userspace never blocks on
        // /dev/urandom — the virtio-rng hwrng kthread on Linux 4.14 has a
        // completion race (reinit_completion vs complete from ISR) that can
        // permanently stall the hwrng feed under NO_HZ.
        if let Some(seed) = rng_seed {
            dt.prop_bytes("rng-seed", seed);
        }
        dt.end_node();

        // Memory node
        dt.begin_node("memory@40000000");
        dt.prop_string("device_type", "memory");
        // reg = <base_hi base_lo size_hi size_lo>
        let mut reg = Vec::new();
        reg.extend_from_slice(&(0x40000000u64).to_be_bytes());
        reg.extend_from_slice(&memory_size.to_be_bytes());
        dt.prop_bytes("reg", &reg);
        dt.end_node();

        // CPUs node
        dt.begin_node("cpus");
        dt.prop_u32("#address-cells", 1);
        dt.prop_u32("#size-cells", 0);

        dt.begin_node("cpu@0");
        dt.prop_string("device_type", "cpu");
        dt.prop_string("compatible", "arm,cortex-a57");
        dt.prop_u32("reg", 0);
        dt.prop_string("enable-method", "psci");
        dt.end_node(); // cpu@0

        dt.end_node(); // cpus

        // GIC v3 interrupt controller node
        // phandle 0x8001 for reference from other nodes
        let gic_node_name = format!("intc@{gic_dist_base:x}");
        dt.begin_node(&gic_node_name);
        dt.prop_string("compatible", "arm,gic-v3");
        dt.prop_u32("#interrupt-cells", 3);
        dt.prop_u32("#address-cells", 2);
        dt.prop_u32("#size-cells", 2);
        dt.prop_empty("ranges");
        dt.prop_empty("interrupt-controller");
        // reg: distributor, redistributor
        let mut gic_reg = Vec::new();
        gic_reg.extend_from_slice(&gic_dist_base.to_be_bytes());
        gic_reg.extend_from_slice(&(gic_dist_size as u64).to_be_bytes());
        gic_reg.extend_from_slice(&gic_redist_base.to_be_bytes());
        gic_reg.extend_from_slice(&(gic_redist_size as u64).to_be_bytes());
        dt.prop_bytes("reg", &gic_reg);
        dt.prop_u32("phandle", 0x8001);
        dt.end_node();

        // PSCI node
        dt.begin_node("psci");
        dt.prop_stringlist("compatible", &["arm,psci-1.0", "arm,psci-0.2", "arm,psci"]);
        dt.prop_string("method", "hvc");
        dt.prop_u32("cpu_suspend", 0xc4000001);
        dt.prop_u32("cpu_off", 0x84000002);
        dt.prop_u32("cpu_on", 0xc4000003);
        dt.prop_u32("migrate", 0xc4000005);
        dt.end_node();

        // Timer node (ARM generic timer) — the arch timer is the guest's
        // clocksource AND clockevent. Its PPIs are delivered by the VMM via
        // the documented HVF vtimer flow (HV_EXIT_REASON_VTIMER_ACTIVATED →
        // pend PPI 27 in the software GIC → unmask on the guest's EOI).
        // Interrupt specifiers: GIC_PPI(1), PPI number, IRQ_TYPE_LEVEL_LOW(8).
        // PPI 13 = secure physical, PPI 14 = non-secure physical,
        // PPI 11 = virtual (GIC INTID 27), PPI 10 = hypervisor.
        dt.begin_node("timer");
        dt.prop_stringlist("compatible", &["arm,armv8-timer", "arm,armv7-timer"]);
        dt.prop_empty("always-on");
        // The arch timer counter runs at the host 24 MHz. Advertising it lets
        // the kernel's arch_timer driver compute correct delay/clockevent
        // targets even if CNTFRQ_EL0 reads as 0 from the vCPU.
        dt.prop_u32("clock-frequency", 24_000_000);
        let mut timer_irqs = Vec::new();
        for ppi in &[13u32, 14, 11, 10] {
            timer_irqs.extend_from_slice(&1u32.to_be_bytes()); // GIC_PPI
            timer_irqs.extend_from_slice(&ppi.to_be_bytes());
            timer_irqs.extend_from_slice(&8u32.to_be_bytes()); // IRQ_TYPE_LEVEL_LOW
        }
        dt.prop_bytes("interrupts", &timer_irqs);
        dt.end_node();

        // UART node — PL011 earlycon-only stub (for early boot & panic messages)
        dt.begin_node("pl011@9000000");
        dt.prop_stringlist("compatible", &["arm,pl011", "arm,primecell"]);
        let mut uart_reg = Vec::new();
        uart_reg.extend_from_slice(&uart_base.to_be_bytes());
        uart_reg.extend_from_slice(&0x1000u64.to_be_bytes());
        dt.prop_bytes("reg", &uart_reg);
        // UART interrupt: SPI 1, level triggered
        let mut uart_irq = Vec::new();
        uart_irq.extend_from_slice(&0u32.to_be_bytes()); // SPI
        uart_irq.extend_from_slice(&1u32.to_be_bytes()); // IRQ 1
        uart_irq.extend_from_slice(&4u32.to_be_bytes()); // level triggered
        dt.prop_bytes("interrupts", &uart_irq);
        dt.prop_stringlist("clock-names", &["uartclk", "apb_pclk"]);
        // Minimal fixed clocks (24MHz)
        let clocks: [u32; 2] = [0x8000, 0x8000]; // phandles to clock nodes
        let mut clk_bytes = Vec::new();
        for c in &clocks {
            clk_bytes.extend_from_slice(&c.to_be_bytes());
        }
        dt.prop_bytes("clocks", &clk_bytes);
        dt.end_node();

        // Virtio-net MMIO node (optional)
        if let Some((base, spi)) = virtio_net {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Virtio-blk MMIO node (root filesystem)
        if let Some((base, spi)) = virtio_blk {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Data block MMIO node (overlay writable disk, --disk-size / --layer)
        if let Some((base, spi)) = data_blk {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Virtio-rng MMIO node (guest entropy)
        if let Some((base, spi)) = virtio_rng {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Virtiofs MMIO nodes (shared directories)
        for &(base, spi) in virtiofs {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Virtio-console MMIO node (interactive terminal I/O — hvc0)
        if let Some((base, spi)) = virtio_console {
            Self::virtio_mmio_node(&mut dt, base, spi);
        }

        // Fixed clock node (needed for PL011 earlycon UART)
        dt.begin_node("apb-pclk");
        dt.prop_string("compatible", "fixed-clock");
        dt.prop_u32("#clock-cells", 0);
        dt.prop_u32("clock-frequency", 24000000); // 24 MHz
        dt.prop_string("clock-output-names", "clk24mhz");
        dt.prop_u32("phandle", 0x8000);
        dt.end_node();

        dt.end_node(); // root

        // Finalize
        dt.finish()
    }

    fn begin_node(&mut self, name: &str) {
        self.struct_write_u32(FDT_BEGIN_NODE);
        self.struct_write_cstring(name);
        self.struct_align4();
    }

    fn end_node(&mut self) {
        self.struct_write_u32(FDT_END_NODE);
    }

    fn prop_u32(&mut self, name: &str, value: u32) {
        self.prop_bytes(name, &value.to_be_bytes());
    }

    /// Emit one `virtio,mmio` device node with its SPI (level-high).
    fn virtio_mmio_node(dt: &mut DeviceTree, base: u64, spi: u32) {
        let node_name = format!("virtio_mmio@{base:x}");
        dt.begin_node(&node_name);
        dt.prop_string("compatible", "virtio,mmio");
        let mut reg = Vec::new();
        reg.extend_from_slice(&base.to_be_bytes());
        reg.extend_from_slice(&0x200u64.to_be_bytes());
        dt.prop_bytes("reg", &reg);
        let mut irq = Vec::new();
        irq.extend_from_slice(&0u32.to_be_bytes()); // SPI
        irq.extend_from_slice(&spi.to_be_bytes());
        irq.extend_from_slice(&4u32.to_be_bytes()); // level-high
        dt.prop_bytes("interrupts", &irq);
        dt.prop_empty("dma-coherent");
        dt.end_node();
    }

    fn prop_string(&mut self, name: &str, value: &str) {
        let mut data = value.as_bytes().to_vec();
        data.push(0); // null terminator
        self.prop_bytes(name, &data);
    }

    fn prop_stringlist(&mut self, name: &str, values: &[&str]) {
        let mut data = Vec::new();
        for s in values {
            data.extend_from_slice(s.as_bytes());
            data.push(0); // null terminator for each string
        }
        self.prop_bytes(name, &data);
    }

    fn prop_empty(&mut self, name: &str) {
        self.prop_bytes(name, &[]);
    }

    fn prop_bytes(&mut self, name: &str, value: &[u8]) {
        let nameoff = self.get_or_add_string(name);
        self.struct_write_u32(FDT_PROP);
        self.struct_write_u32(value.len() as u32);
        self.struct_write_u32(nameoff);
        self.dt_struct.extend_from_slice(value);
        self.struct_align4();
    }

    /// Get or add a property name to the strings block.
    /// Returns the offset of the name in the strings block.
    fn get_or_add_string(&mut self, name: &str) -> u32 {
        // Search for existing string
        let name_bytes = name.as_bytes();

        let mut offset = 0;
        while offset < self.dt_strings.len() {
            // Find the end of the current string
            let end = self.dt_strings[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(self.dt_strings.len());

            let existing = &self.dt_strings[offset..end];
            if existing == name_bytes {
                return offset as u32;
            }

            offset = end + 1; // skip null terminator
        }

        // String not found, append it
        let new_offset = self.dt_strings.len() as u32;
        self.dt_strings.extend_from_slice(name_bytes);
        self.dt_strings.push(0); // null terminator
        new_offset
    }

    fn finish(&mut self) -> Result<Vec<u8>> {
        // Add FDT_END token
        self.struct_write_u32(FDT_END);

        // Build the complete blob:
        // Header (40 bytes) + padding
        // Memory reservation map (16 bytes: one empty entry)
        // Structure block
        // Strings block

        let header_size = 40u32;

        // Memory reservation map starts right after header, aligned to 8
        let mem_rsvmap_off = Self::align_up(header_size, 8);
        let mem_rsvmap_size = 16u32; // one empty entry {0, 0}

        // Structure block follows memory reservation map
        let dt_struct_off = mem_rsvmap_off + mem_rsvmap_size;
        let dt_struct_size = self.dt_struct.len() as u32;

        // Strings block follows structure block
        let dt_strings_off = dt_struct_off + dt_struct_size;
        let dt_strings_size = self.dt_strings.len() as u32;

        let totalsize = dt_strings_off + dt_strings_size;

        let mut blob = Vec::with_capacity(totalsize as usize);

        // Header
        blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        blob.extend_from_slice(&totalsize.to_be_bytes());
        blob.extend_from_slice(&dt_struct_off.to_be_bytes());
        blob.extend_from_slice(&dt_strings_off.to_be_bytes());
        blob.extend_from_slice(&mem_rsvmap_off.to_be_bytes());
        blob.extend_from_slice(&17u32.to_be_bytes()); // version
        blob.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
        blob.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        blob.extend_from_slice(&dt_strings_size.to_be_bytes());
        blob.extend_from_slice(&dt_struct_size.to_be_bytes());

        // Pad to mem_rsvmap_off
        while blob.len() < mem_rsvmap_off as usize {
            blob.push(0);
        }

        // Memory reservation map: one empty entry (terminates the list)
        blob.extend_from_slice(&0u64.to_be_bytes());
        blob.extend_from_slice(&0u64.to_be_bytes());

        // Structure block
        assert_eq!(blob.len(), dt_struct_off as usize);
        blob.extend_from_slice(&self.dt_struct);

        // Strings block
        assert_eq!(blob.len(), dt_strings_off as usize);
        blob.extend_from_slice(&self.dt_strings);

        assert_eq!(blob.len(), totalsize as usize);

        Ok(blob)
    }

    // Structure block helpers
    fn struct_write_u32(&mut self, val: u32) {
        self.dt_struct.extend_from_slice(&val.to_be_bytes());
    }

    fn struct_write_cstring(&mut self, s: &str) {
        self.dt_struct.extend_from_slice(s.as_bytes());
        self.dt_struct.push(0);
    }

    fn struct_align4(&mut self) {
        while !self.dt_struct.len().is_multiple_of(4) {
            self.dt_struct.push(0);
        }
    }

    fn align_up(val: u32, align: u32) -> u32 {
        (val + align - 1) & !(align - 1)
    }
}
