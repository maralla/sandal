//! Windows Hypervisor Platform (WHP) backend — x86_64.
//!
//! WHP exposes partition/vCPU primitives only: no in-kernel PIC, no PIT, no
//! in-kernel device emulation. This backend therefore supplies the two legacy
//! devices the guest kernel relies on:
//!
//! - **the i8259 PIC pair** (master + cascade slave) in userspace: the
//!   virtio devices' IRQ lines are delivered as edge interrupts through
//!   `WHvRequestInterrupt`, vector-mapped through the ICW2 bases the guest
//!   programs (the kernel runs in "PIC mode" — the minimal guest config has
//!   no ACPI/MPS tables, so the LAPIC is never discovered);
//! - **an i8254 PIT tick**: a host thread raises IRQ 0 at the guest-
//!   programmed rate (default 250 Hz) and wakes a halted vCPU.
//!
//! Device MMIO: the virtio-mmio window sits above guest RAM and is left
//! unmapped in the GPA space. Accesses surface as
//! `WHvRunVpExitReasonMemoryAccess` exits, which this backend completes by
//! decoding the faulting instruction (a focused x64 load/store decoder
//! covering the access forms the Linux virtio-mmio driver emits —
//! `readl`/`writel`-style MOVs), performing the access against the device
//! model, setting the destination register via
//! `WHvSetVirtualProcessorRegisters` and advancing RIP.
//!
//! The WHV_REGISTER_NAME / exit-context constant values follow the Windows
//! SDK `whv.h` layout; they are gathered in one place (this module) so any
//! SDK-version drift is a one-block fix.

use crate::hypervisor::KvmExit;
use anyhow::{anyhow, bail, Result};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// WHV constants
// ─────────────────────────────────────────────────────────────────────────────

// Map flags (WHV_MAP_GPA_RANGE_FLAGS).
const WHV_MAP_GPA_RANGE_READ: u32 = 1 << 0;
const WHV_MAP_GPA_RANGE_WRITE: u32 = 1 << 1;
const WHV_MAP_GPA_RANGE_EXECUTE: u32 = 1 << 2;

// Exit reasons (WHV_RUN_VP_EXIT_REASON).
const WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS: u32 = 1;
const WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS: u32 = 2;
const WHV_RUN_VP_EXIT_REASON_X64_HALT: u32 = 3;
const WHV_RUN_VP_EXIT_REASON_EXCEPTION: u32 = 5;
const WHV_RUN_VP_EXIT_REASON_CANCELED: u32 = 8192;

// Interrupt type (WHV_INTERRUPT_TYPE) — edge, matching the i8259 model.
const WHV_INTERRUPT_TYPE_EDGE: u32 = 1;

// Register names (WHV_REGISTER_NAME). The encoding is
// (WHV_REGISTER_TYPE << 16) | index; general-purpose registers Rax..R15 are
// 0x00080000-0x0008000F in x86 encoding order.
const WHV_X64_REGISTER_RAX: u32 = 0x0008_0000;
const WHV_X64_REGISTER_RCX: u32 = 0x0008_0001;
const WHV_X64_REGISTER_RDX: u32 = 0x0008_0002;
const WHV_X64_REGISTER_RBX: u32 = 0x0008_0003;
const WHV_X64_REGISTER_RSP: u32 = 0x0008_0004;
const WHV_X64_REGISTER_RBP: u32 = 0x0008_0005;
const WHV_X64_REGISTER_RSI: u32 = 0x0008_0006;
const WHV_X64_REGISTER_RDI: u32 = 0x0008_0007;
const WHV_X64_REGISTER_R8: u32 = 0x0008_0008;
const WHV_X64_REGISTER_R9: u32 = 0x0008_0009;
const WHV_X64_REGISTER_R10: u32 = 0x0008_000A;
const WHV_X64_REGISTER_R11: u32 = 0x0008_000B;
const WHV_X64_REGISTER_R12: u32 = 0x0008_000C;
const WHV_X64_REGISTER_R13: u32 = 0x0008_000D;
const WHV_X64_REGISTER_R14: u32 = 0x0008_000E;
const WHV_X64_REGISTER_R15: u32 = 0x0008_000F;
const WHV_X64_REGISTER_RIP: u32 = 0x0008_0100;

// Segment names (WHvX64RegisterCs..Ss = 0x00090000-0x00090005) and control
// registers (WHvX64RegisterCr0 = 0x00090010).
const WHV_X64_REGISTER_CS: u32 = 0x0009_0000;
const WHV_X64_REGISTER_DS: u32 = 0x0009_0001;
const WHV_X64_REGISTER_ES: u32 = 0x0009_0002;
const WHV_X64_REGISTER_FS: u32 = 0x0009_0003;
const WHV_X64_REGISTER_GS: u32 = 0x0009_0004;
const WHV_X64_REGISTER_SS: u32 = 0x0009_0005;
const WHV_X64_REGISTER_CR0: u32 = 0x0009_0010;

// Exit-context field offsets (bytes) inside WHV_RUN_VP_EXIT_CONTEXT.
const EXIT_REASON_OFF: usize = 0; // u32
const VP_CTX_OFF: usize = 8; // WHV_VP_EXIT_CONTEXT
const VP_RIP_OFF: usize = VP_CTX_OFF; // u64
const VP_CTX_SIZE: usize = 288; // 18 GPRs + 6 segments + tables + exception
const UNION_OFF: usize = VP_CTX_OFF + VP_CTX_SIZE;
// WHV_MEMORY_ACCESS_CONTEXT: AccessInfo(u32), AccessSize(u8), Rsvd[3], Gpa, Gva.
const MEMACC_INFO_OFF: usize = UNION_OFF;
const MEMACC_SIZE_OFF: usize = UNION_OFF + 4;
const MEMACC_GPA_OFF: usize = UNION_OFF + 8;
// WHV_X64_IO_PORT_ACCESS_CONTEXT: PortNumber(u16), AccessSize(u16), Rsvd[4],
// Rax(u64), ...
const IOPORT_PORT_OFF: usize = UNION_OFF;
const IOPORT_SIZE_OFF: usize = UNION_OFF + 2;
const IOPORT_RAX_OFF: usize = UNION_OFF + 8;

const EXIT_CTX_SIZE: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// FFI: the WHv entry points are resolved dynamically from
// WindowsHypervisorPlatform.dll (no import library needed at build time).
// ─────────────────────────────────────────────────────────────────────────────

type Handle = isize;

#[repr(C)]
#[derive(Clone, Copy)]
struct WhvInterruptContext {
    r#type: u32,
    vector: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WhvX64SegmentRegister {
    base: u64,
    limit: u32,
    selector: u16,
    attributes: u16,
}

type FnCreatePartition = unsafe extern "system" fn(partition: *mut Handle) -> i32;
type FnSetupPartition = unsafe extern "system" fn(partition: Handle) -> i32;
type FnCreateVirtualProcessor =
    unsafe extern "system" fn(partition: Handle, vp_index: u32, flags: u32) -> i32;
type FnMapGpaRange = unsafe extern "system" fn(
    partition: Handle,
    source: *mut u8,
    guest_address: u64,
    size: u64,
    flags: u32,
) -> i32;
type FnRunVirtualProcessor =
    unsafe extern "system" fn(partition: Handle, vp: u32, ctx: *mut u8, size: u32) -> i32;
type FnRequestInterrupt = unsafe extern "system" fn(
    partition: Handle,
    interrupt: *const WhvInterruptContext,
    size: u32,
) -> i32;
type FnGetVpRegisters = unsafe extern "system" fn(
    partition: Handle,
    vp: u32,
    names: *const u32,
    count: u32,
    values: *mut u8,
) -> i32;
type FnSetVpRegisters = unsafe extern "system" fn(
    partition: Handle,
    vp: u32,
    names: *const u32,
    count: u32,
    values: *const u8,
) -> i32;

#[derive(Clone, Copy)]
pub(crate) struct WhvApi {
    create_partition: FnCreatePartition,
    setup_partition: FnSetupPartition,
    create_virtual_processor: FnCreateVirtualProcessor,
    map_gpa_range: FnMapGpaRange,
    run_virtual_processor: FnRunVirtualProcessor,
    request_interrupt: FnRequestInterrupt,
    get_vp_registers: FnGetVpRegisters,
    set_vp_registers: FnSetVpRegisters,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetProcAddress(lib: Handle, name: *const u8) -> *mut c_void;
}

/// Resolve and cache the WHv entry points. Returned by value (the struct is
/// a set of Copy function pointers).
fn whv_api() -> Result<WhvApi> {
    static API: Mutex<Option<WhvApi>> = Mutex::new(None);
    let mut cached = API.lock().unwrap();
    if cached.is_some() {
        return Ok((*cached).unwrap());
    }
    let loaded = (|| unsafe {
        let lib_name: Vec<u16> = "WindowsHypervisorPlatform.dll\0".encode_utf16().collect();
        let lib = LoadLibraryW(lib_name.as_ptr());
        if lib == 0 {
            return Err(anyhow!(
                "WindowsHypervisorPlatform.dll not loaded — enable the \
                 'Virtual Machine Platform' or 'Windows Hypervisor Platform' \
                 Windows feature and reboot"
            ));
        }
        let sym = |name: &str| -> *mut c_void {
            let c = std::ffi::CString::new(name).unwrap();
            GetProcAddress(lib, c.as_ptr() as *const u8)
        };
        let get = |name: &str| -> Result<*mut c_void> {
            let p = sym(name);
            if p.is_null() {
                bail!("WindowsHypervisorPlatform.dll missing export {name}");
            }
            Ok(p)
        };
        Ok(WhvApi {
            create_partition: std::mem::transmute::<*mut c_void, FnCreatePartition>(get(
                "WHvCreatePartition",
            )?),
            setup_partition: std::mem::transmute::<*mut c_void, FnSetupPartition>(get(
                "WHvSetupPartition",
            )?),
            create_virtual_processor: std::mem::transmute::<*mut c_void, FnCreateVirtualProcessor>(
                get("WHvCreateVirtualProcessor")?,
            ),
            map_gpa_range: std::mem::transmute::<*mut c_void, FnMapGpaRange>(get(
                "WHvMapGpaRange",
            )?),
            run_virtual_processor: std::mem::transmute::<*mut c_void, FnRunVirtualProcessor>(get(
                "WHvRunVirtualProcessor",
            )?),
            request_interrupt: std::mem::transmute::<*mut c_void, FnRequestInterrupt>(get(
                "WHvRequestInterrupt",
            )?),
            get_vp_registers: std::mem::transmute::<*mut c_void, FnGetVpRegisters>(get(
                "WHvGetVirtualProcessorRegisters",
            )?),
            set_vp_registers: std::mem::transmute::<*mut c_void, FnSetVpRegisters>(get(
                "WHvSetVirtualProcessorRegisters",
            )?),
        })
    })();
    let api = loaded?;
    *cached = Some(api);
    Ok(api)
}

/// Check an HRESULT (negative = failure) and map it to an anyhow error.
fn wh(hr: i32, what: &str) -> Result<()> {
    if hr < 0 {
        return Err(anyhow!("{what} failed: HRESULT 0x{:08X}", hr as u32));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Userspace i8259 PIC pair (master + cascade slave)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct PicChip {
    vector_base: u8,
    imr: u8,
    irr: u8,
    isr: u8,
    /// What an IN on the command port returns: 0x0A = IRR, 0x0B = ISR.
    read_isr: bool,
    /// ICW sequence state: 0 = idle, 1..4 = expecting ICW1..4.
    icw_step: u8,
}

const MASTER: usize = 0;
const SLAVE: usize = 1;

/// The dual-i8259 emulation delivering guest interrupts through
/// `WHvRequestInterrupt`. Edge-triggered (matches the virtio device model:
/// raise on new work, the guest EOI acknowledges, the device re-raises if
/// work remains).
pub struct Pic {
    partition: Handle,
    api: WhvApi,
    chips: [PicChip; 2],
}

impl Pic {
    fn new(partition: Handle, api: WhvApi) -> Self {
        Pic {
            partition,
            api,
            chips: [PicChip::default(), PicChip::default()],
        }
    }

    /// The vector for an ISA IRQ line (the guest programs ICW2 bases 0x08 and
    /// 0x70; before programming, deliver the conventional bases).
    fn vector(&self, irq: u32) -> u8 {
        if irq < 8 {
            self.chips[MASTER].vector_base.wrapping_add(irq as u8)
        } else {
            self.chips[SLAVE].vector_base.wrapping_add(irq as u8 - 8)
        }
    }

    /// Assert an IRQ line (level). Delivers if the chip can take it.
    pub fn raise(&mut self, irq: u32) {
        if irq < 8 {
            self.chips[MASTER].irr |= 1 << irq;
        } else {
            self.chips[SLAVE].irr |= 1 << (irq - 8);
            // The cascade line asserts on the master too.
            self.chips[MASTER].irr |= 1 << 2;
        }
        self.deliver_pending();
    }

    /// Deliver pending, unmasked, not-in-service interrupts (master first —
    /// the cascade line must be in service before the slave's vectors).
    fn deliver_pending(&mut self) {
        for (idx, chip) in self.chips.iter_mut().enumerate() {
            let pending = chip.irr & !chip.imr & !chip.isr;
            if pending == 0 {
                continue;
            }
            let irq = pending.trailing_zeros() as u8;
            let vector = chip.vector_base.wrapping_add(irq);
            let int_ctx = WhvInterruptContext {
                r#type: WHV_INTERRUPT_TYPE_EDGE,
                vector: vector as u32,
            };
            let hr = unsafe {
                (self.api.request_interrupt)(
                    self.partition,
                    &int_ctx,
                    std::mem::size_of::<WhvInterruptContext>() as u32,
                )
            };
            if hr < 0 {
                // A failed delivery would wedge the guest silently — surface it.
                eprintln!(
                    "whp: WHvRequestInterrupt(vector {vector:#x}) failed: 0x{:08X}",
                    hr as u32
                );
                continue;
            }
            chip.irr &= !(1 << irq);
            chip.isr |= 1 << irq;
            let _ = idx;
        }
    }

    /// Host timer tick: edge-assert IRQ 0 (the PIT channel 0 line).
    pub fn tick(&mut self) {
        self.raise(0);
    }

    /// OCW2 nonspecific EOI: release the highest-priority in-service
    /// interrupt, then deliver the next pending one.
    fn eoi(&mut self, chip_idx: usize) {
        let chip = &mut self.chips[chip_idx];
        if chip.isr != 0 {
            // Clear the lowest set bit = the lowest-priority in-service
            // interrupt in a full cascade EOI; the kernel EOIs both chips,
            // so clearing everything in-service for this chip is safe.
            chip.isr = 0;
        }
        self.deliver_pending();
    }

    /// The register file interface for the PIO exits on ports 0x20/0x21/0xA0/0xA1.
    fn port_read(&mut self, port: u16) -> u8 {
        match port {
            0x20 => {
                let c = &self.chips[MASTER];
                if c.read_isr {
                    c.isr
                } else {
                    c.irr
                }
            }
            0x21 => self.chips[MASTER].imr,
            0xA0 => {
                let c = &self.chips[SLAVE];
                if c.read_isr {
                    c.isr
                } else {
                    c.irr
                }
            }
            0xA1 => self.chips[SLAVE].imr,
            _ => 0,
        }
    }

    fn port_write(&mut self, port: u16, val: u8) {
        let chip_idx = if port == 0x20 || port == 0x21 {
            MASTER
        } else {
            SLAVE
        };
        match port {
            0x20 | 0xA0 => {
                if val & 0x10 != 0 {
                    // ICW1: begin the initialization sequence.
                    self.chips[chip_idx] = PicChip {
                        icw_step: 2,
                        // Conventional bases; the guest overwrites via ICW2.
                        vector_base: if chip_idx == MASTER { 0x08 } else { 0x70 },
                        ..Default::default()
                    };
                } else if val & 0x08 != 0 {
                    // OCW3: read selection.
                    self.chips[chip_idx].read_isr = val & 0x01 != 0;
                } else if val & 0x20 != 0 {
                    // OCW2 nonspecific EOI.
                    self.eoi(chip_idx);
                }
            }
            0x21 | 0xA1 => {
                let chip = &mut self.chips[chip_idx];
                if chip.icw_step == 2 {
                    // ICW2: the interrupt vector base.
                    chip.vector_base = val & 0xF8;
                    chip.icw_step = 3;
                } else if chip.icw_step == 3 {
                    // ICW3 (cascade wiring) — accepted, not modeled.
                    chip.icw_step = 4;
                } else if chip.icw_step == 4 {
                    // ICW4 (mode) — end of the sequence.
                    chip.icw_step = 0;
                    chip.imr = 0xFF;
                } else {
                    // OCW1: the interrupt mask.
                    chip.imr = val;
                }
            }
            _ => {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// x64 MMIO access decoder
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DecodedMmio {
    pub is_write: bool,
    pub size: u32,
    /// The load destination / store source GPR (x86 encoding order, 0-15).
    gpr: Option<u8>,
    /// The immediate for `MOV r/m, imm`.
    imm: u64,
    len: usize,
}

/// Decode the faulting instruction for the MMIO access forms the Linux
/// virtio-mmio driver emits (readl/writel/readw/writew/readb/writeb compile
/// to plain MOV load/stores, optionally zero/sign-extended). Returns None
/// for anything else — the caller bails with the instruction bytes, and the
/// device model grows the supported set if a new form appears.
fn decode_x64_mmio(code: &[u8]) -> Option<DecodedMmio> {
    let mut i = 0usize;
    let mut operand16 = false;
    let mut rex_w = false;
    let mut rex_r = false;
    let mut rex_seen = false;

    // Prefixes.
    loop {
        match code.get(i) {
            Some(0x66) => {
                operand16 = true;
                i += 1;
            }
            Some(0x67) | Some(0x2E) | Some(0x36) | Some(0x3E) | Some(0x26) | Some(0x64)
            | Some(0x65) => i += 1,
            Some(0xF2) | Some(0xF3) => i += 1,
            Some(&b) if (0x40..=0x4F).contains(&b) => {
                rex_w = b & 0x08 != 0;
                rex_r = b & 0x04 != 0;
                rex_seen = true;
                i += 1;
            }
            _ => break,
        }
    }

    let size = if rex_w {
        8
    } else if operand16 {
        2
    } else {
        4
    };

    let opcode = *code.get(i)?;
    i += 1;

    // Two-byte opcodes: zero/sign extension loads.
    let (mnemonic_load, size): (bool, u32) = match opcode {
        0x8A => (true, 1),
        0x8B => (true, size),
        0x88 => (false, 1),
        0x89 => (false, size),
        0xC6 => (false, 1),
        0xC7 => (false, if operand16 { 2 } else { 4 }),
        0x0F => {
            let op2 = *code.get(i)?;
            i += 1;
            match op2 {
                0xB6 => (true, 1),
                0xB7 => (true, 2),
                0xBE => (true, 1),
                0xBF => (true, 2),
                _ => return None,
            }
        }
        _ => return None,
    };

    // ModRM.
    let modrm = *code.get(i)?;
    i += 1;
    let mode = modrm >> 6;
    let reg = (modrm >> 3) & 7;
    let rm = modrm & 7;
    if mode == 3 {
        // Register-to-register: not an MMIO access.
        return None;
    }

    let mut gpr = reg;
    if rex_r {
        gpr += 8;
    }

    // Displacement / SIB consumption.
    let mut disp_len = 0usize;
    if rm == 4 {
        // SIB byte.
        let sib = *code.get(i)?;
        i += 1;
        let base = sib & 7;
        if base == 5 && mode == 0 {
            disp_len = 4;
        }
    } else if rm == 5 && mode == 0 {
        disp_len = 4; // RIP-relative (the address is in the exit anyway)
    }
    disp_len = match mode {
        1 => 1,
        2 => 4,
        _ => disp_len,
    };
    i += disp_len;

    let mut imm = 0u64;
    let mut len = i;
    if opcode == 0xC6 || opcode == 0xC7 {
        let imm_size = if opcode == 0xC6 { 1 } else { size };
        for k in 0..imm_size {
            imm |= ((*code.get(len)?) as u64) << (8 * k);
            len += 1;
        }
    }

    let _ = rex_seen;
    Some(DecodedMmio {
        is_write: !mnemonic_load,
        size,
        gpr: if mnemonic_load { Some(gpr) } else { None },
        imm,
        len,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// VM (partition)
// ─────────────────────────────────────────────────────────────────────────────

pub struct Vm {
    partition: Handle,
    api: WhvApi,
    pub(crate) pic: Arc<Mutex<Pic>>,
    /// The mapped guest RAM (host pointer + size) — set by `map_memory`;
    /// shared with the vCPUs (which fetch guest instruction bytes for the
    /// MMIO decoder). Created before any vCPU, so the Arc hand-off is safe.
    ram: Arc<Mutex<Option<(*mut u8, usize)>>>,
}

impl Vm {
    pub fn new() -> Result<Self> {
        let api = whv_api()?;
        let mut partition: Handle = 0;
        let hr = unsafe { (api.create_partition)(&mut partition) };
        wh(hr, "WHvCreatePartition")?;
        let hr = unsafe { (api.setup_partition)(partition) };
        wh(hr, "WHvSetupPartition")?;

        Ok(Vm {
            partition,
            api,
            pic: Arc::new(Mutex::new(Pic::new(partition, api))),
            // The raw mapping pointer never crosses threads (the WHP run
            // loop owns it); the PIC does (its tick thread) and carries
            // its own unsafe impl Send/Sync.
            #[allow(clippy::arc_with_non_send_sync)]
            ram: Arc::new(Mutex::new(None)),
        })
    }

    /// Map host memory into the guest physical address space. The `flags`
    /// parameter is ignored (the WHP mapping is read/write/execute).
    pub fn map_memory(
        &self,
        host_addr: *mut c_void,
        guest_addr: u64,
        size: usize,
        _flags: u64,
    ) -> Result<()> {
        let hr = unsafe {
            (self.api.map_gpa_range)(
                self.partition,
                host_addr as *mut u8,
                guest_addr,
                size as u64,
                WHV_MAP_GPA_RANGE_READ | WHV_MAP_GPA_RANGE_WRITE | WHV_MAP_GPA_RANGE_EXECUTE,
            )
        };
        wh(hr, "WHvMapGpaRange")?;
        // Record the RAM mapping for the guest-code fetches (the decode
        // path). The Arc is shared with the vCPUs, which are created before
        // this call but only fetch code once the guest runs.
        *self.ram.lock().unwrap() = Some((host_addr as *mut u8, size));
        Ok(())
    }

    /// The interrupt controller is the userspace PIC pair (see the module
    /// docs). Kept under the KVM-era name so the shared boot path reads the
    /// same across backends.
    pub fn create_irqchip(&self) -> Result<()> {
        Ok(())
    }

    /// The PIC handle for the device threads (timer tick, console input).
    pub fn pic_handle(&self) -> Arc<Mutex<Pic>> {
        Arc::clone(&self.pic)
    }

    /// Guest instruction bytes at a physical address (for the MMIO access
    /// decoder). Returns up to `max` bytes; reads outside RAM return zeros.
    pub fn guest_code_at(&self, gpa: u64, max: usize) -> [u8; 15] {
        let mut out = [0u8; 15];
        let guard = self.ram.lock().unwrap();
        if let Some((ptr, len)) = *guard {
            let n = max.min(15).min(len.saturating_sub(gpa as usize));
            unsafe {
                std::ptr::copy_nonoverlapping(ptr.add(gpa as usize), out.as_mut_ptr(), n);
            }
        }
        out
    }

    /// Deliver an edge interrupt for an asserted device IRQ line (the ISA
    /// IRQ number, matching the `virtio_mmio.device=` cmdline order).
    pub fn raise_irq(&self, irq: u32) -> Result<()> {
        self.pic.lock().unwrap().raise(irq);
        Ok(())
    }

    pub(crate) fn partition(&self) -> Handle {
        self.partition
    }

    pub(crate) fn api(&self) -> WhvApi {
        self.api
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// vCPU
// ─────────────────────────────────────────────────────────────────────────────

pub struct Vcpu {
    partition: Handle,
    api: WhvApi,
    vp_index: u32,
    /// The mapped guest RAM (for fetching instruction bytes at RIP) — the
    /// same cell the Vm's `map_memory` fills.
    ram: Arc<Mutex<Option<(*mut u8, usize)>>>,
    /// The register the last decoded MMIO load targets (for `fill_mmio_read`).
    last_mmio_gpr: Mutex<Option<u8>>,
}

// The partition/vCPU handles and the API pointers are process-global
// resources shared with the device threads (the PIC tick) — Send/Sync.
unsafe impl Send for Vcpu {}
unsafe impl Sync for Vcpu {}

impl Vcpu {
    pub fn new(vm: &Vm) -> Result<Self> {
        let hr = unsafe { (vm.api.create_virtual_processor)(vm.partition, 0, 0) };
        wh(hr, "WHvCreateVirtualProcessor")?;
        Ok(Vcpu {
            partition: vm.partition,
            api: vm.api,
            vp_index: 0,
            ram: Arc::clone(&vm.ram),
            last_mmio_gpr: Mutex::new(None),
        })
    }

    /// WHP passes the physical CPUID through by default (including the LM
    /// feature bits the 64-bit guest needs). Deliberately not overridden:
    /// the guest runs in PIC mode with the bare-hardware paravirt path.
    pub fn set_supported_cpuid(&self) -> Result<()> {
        Ok(())
    }

    /// The PVH entry state: 32-bit protected mode with paging *enabled* is
    /// what KVM sets; the Linux PVH entry (`xen_prepare_pvh`) switches to
    /// long mode itself, so the vCPU starts in 32-bit protected mode with
    /// flat segments — mirroring the KVM `init_pvh`.
    pub fn init_pvh(&self, entry: u64, start_info: u64) -> Result<()> {
        let set_reg = |name: u32, value: u64| -> Result<()> {
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&value.to_le_bytes());
            let hr = unsafe {
                (self.api.set_vp_registers)(self.partition, self.vp_index, &name, 1, buf.as_ptr())
            };
            wh(hr, "WHvSetVirtualProcessorRegisters")
        };

        // Flat code segment: base 0, limit 4 GB, readable/executable.
        let mut cs = [0u8; 16];
        cs[..8].copy_from_slice(&0u64.to_le_bytes()); // base
        cs[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // limit
        cs[12..14].copy_from_slice(&8u16.to_le_bytes()); // selector
                                                         // attributes: Accessible | Executable | Long?? — 32-bit entry: no Long.
        cs[14..16].copy_from_slice(&0x009Bu16.to_le_bytes());
        let hr = unsafe {
            (self.api.set_vp_registers)(
                self.partition,
                self.vp_index,
                &WHV_X64_REGISTER_CS,
                1,
                cs.as_ptr(),
            )
        };
        wh(hr, "set CS")?;

        // Flat data segments.
        let mut ds = [0u8; 16];
        ds[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        ds[12..14].copy_from_slice(&0x10u16.to_le_bytes());
        ds[14..16].copy_from_slice(&0x0093u16.to_le_bytes());
        for name in [
            WHV_X64_REGISTER_DS,
            WHV_X64_REGISTER_ES,
            WHV_X64_REGISTER_FS,
            WHV_X64_REGISTER_GS,
            WHV_X64_REGISTER_SS,
        ] {
            let hr = unsafe {
                (self.api.set_vp_registers)(self.partition, self.vp_index, &name, 1, ds.as_ptr())
            };
            wh(hr, "set data segment")?;
        }

        // CR0: PE | ET (paging comes later, from the kernel itself).
        set_reg(WHV_X64_REGISTER_CR0, 0x11)?;
        set_reg(WHV_X64_REGISTER_RIP, entry)?;
        set_reg(WHV_X64_REGISTER_RBX, start_info)?;
        set_reg(WHV_X64_REGISTER_RSP, 0x8000)?;
        set_reg(WHV_X64_REGISTER_RAX, 0)?;
        Ok(())
    }

    /// Run the vCPU until the next userspace exit, translating the WHP exit
    /// context into the shared [`KvmExit`] vocabulary.
    pub fn run(&mut self) -> Result<KvmExit> {
        let api = self.api;
        let mut ctx = [0u8; EXIT_CTX_SIZE];
        let hr = unsafe {
            (api.run_virtual_processor)(
                self.partition,
                self.vp_index,
                ctx.as_mut_ptr(),
                EXIT_CTX_SIZE as u32,
            )
        };
        if hr < 0 {
            return Err(anyhow!(
                "WHvRunVirtualProcessor failed: 0x{:08X}",
                hr as u32
            ));
        }

        let reason = u32::from_le_bytes(ctx[EXIT_REASON_OFF..EXIT_REASON_OFF + 4].try_into()?);
        match reason {
            WHV_RUN_VP_EXIT_REASON_X64_IO_PORT_ACCESS => {
                let port =
                    u16::from_le_bytes(ctx[IOPORT_PORT_OFF..IOPORT_PORT_OFF + 2].try_into()?);
                let size = u16::from_le_bytes(ctx[IOPORT_SIZE_OFF..IOPORT_SIZE_OFF + 2].try_into()?)
                    as usize;
                let value = u64::from_le_bytes(ctx[IOPORT_RAX_OFF..IOPORT_RAX_OFF + 8].try_into()?);
                Ok(KvmExit::Io {
                    port,
                    len: size,
                    is_write: true,
                    value,
                })
            }
            WHV_RUN_VP_EXIT_REASON_MEMORY_ACCESS => {
                let gpa = u64::from_le_bytes(ctx[MEMACC_GPA_OFF..MEMACC_GPA_OFF + 8].try_into()?);
                let access_info =
                    u32::from_le_bytes(ctx[MEMACC_INFO_OFF..MEMACC_INFO_OFF + 4].try_into()?);
                let is_write = access_info & 0x2 != 0; // WHvMemoryAccessWrite

                // Decode the faulting instruction: read up to 15 bytes of
                // guest code at RIP through the mapped RAM.
                let rip = u64::from_le_bytes(ctx[VP_RIP_OFF..VP_RIP_OFF + 8].try_into()?);
                let code: [u8; 15] = self.guest_code_at(rip, 15);
                let Some(decoded) = decode_x64_mmio(&code) else {
                    bail!(
                        "whp: unsupported MMIO instruction at rip 0x{rip:x}: \
                         {:02x?} (gpa 0x{gpa:x})",
                        &code[..code.len().min(8)]
                    );
                };

                if is_write {
                    let mut data = [0u8; 8];
                    if let Some(gpr) = decoded.gpr {
                        // The store source register holds the value.
                        let reg_name = WHV_X64_REGISTER_RAX + gpr as u32;
                        let mut buf = [0u8; 16];
                        let hr = unsafe {
                            (api.get_vp_registers)(
                                self.partition,
                                self.vp_index,
                                &reg_name,
                                1,
                                buf.as_mut_ptr(),
                            )
                        };
                        wh(hr, "get store-source register")?;
                        data[..decoded.size as usize]
                            .copy_from_slice(&buf[..decoded.size as usize]);
                    } else {
                        data[..decoded.size as usize]
                            .copy_from_slice(&decoded.imm.to_le_bytes()[..decoded.size as usize]);
                    }
                    // Advance RIP past the emulated store.
                    self.set_rip(rip + decoded.len as u64)?;
                    Ok(KvmExit::Mmio {
                        addr: gpa,
                        len: decoded.size as usize,
                        is_write: true,
                        data,
                    })
                } else {
                    // Read: stash the destination register; `fill_mmio_read`
                    // applies the value and the run loop advances nothing
                    // (the RIP advance happens here too).
                    *self.last_mmio_gpr.lock().unwrap() = decoded.gpr;
                    self.set_rip(rip + decoded.len as u64)?;
                    Ok(KvmExit::Mmio {
                        addr: gpa,
                        len: decoded.size as usize,
                        is_write: false,
                        data: [0; 8],
                    })
                }
            }
            WHV_RUN_VP_EXIT_REASON_X64_HALT => Ok(KvmExit::Hlt),
            WHV_RUN_VP_EXIT_REASON_EXCEPTION => {
                let exc = u32::from_le_bytes(ctx[UNION_OFF..UNION_OFF + 4].try_into()?);
                Ok(KvmExit::DebugX86 {
                    exception: exc,
                    pc: u64::from_le_bytes(ctx[VP_RIP_OFF..VP_RIP_OFF + 8].try_into()?),
                    dr6: 0,
                })
            }
            WHV_RUN_VP_EXIT_REASON_CANCELED => Ok(KvmExit::Unknown(u32::MAX)),
            other => Ok(KvmExit::Unknown(other)),
        }
    }

    /// Guest instruction bytes at a physical address (through the recorded
    /// RAM mapping; outside RAM returns zeros).
    fn guest_code_at(&self, gpa: u64, max: usize) -> [u8; 15] {
        let mut out = [0u8; 15];
        let guard = self.ram.lock().unwrap();
        if let Some((ptr, len)) = *guard {
            let n = max.min(15).min(len.saturating_sub(gpa as usize));
            unsafe {
                std::ptr::copy_nonoverlapping(ptr.add(gpa as usize), out.as_mut_ptr(), n);
            }
        }
        out
    }

    fn set_rip(&self, rip: u64) -> Result<()> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&rip.to_le_bytes());
        let hr = unsafe {
            (self.api.set_vp_registers)(
                self.partition,
                self.vp_index,
                &WHV_X64_REGISTER_RIP,
                1,
                buf.as_ptr(),
            )
        };
        wh(hr, "WHvSetVirtualProcessorRegisters(RIP)")
    }

    /// IN port read completion: the value lands in EAX (the WHP IN exit
    /// leaves RAX to the VMM).
    pub fn fill_io_read(&self, _offset: usize, _len: usize, value: u64) {
        let _ = self.set_reg_nothrow(WHV_X64_REGISTER_RAX, value);
    }

    /// The KVM-side data-offset concept does not exist on WHP.
    pub fn io_data_offset(&self) -> usize {
        0
    }

    /// MMIO read completion: the decoded destination register receives the
    /// value (already sign/zero-extended to 64 bits by the caller).
    pub fn fill_mmio_read(&self, data: &[u8]) {
        let gpr = *self.last_mmio_gpr.lock().unwrap();
        if let Some(gpr) = gpr {
            let mut value = 0u64;
            for (i, b) in data.iter().enumerate().take(8) {
                value |= (*b as u64) << (8 * i);
            }
            let _ = self.set_reg_nothrow(WHV_X64_REGISTER_RAX + gpr as u32, value);
        }
    }

    fn set_reg_nothrow(&self, name: u32, value: u64) -> Result<()> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&value.to_le_bytes());
        // WHV_REGISTER_VALUE is a 16-byte union; the integer variants read
        // the low 8 bytes.
        let hr = unsafe {
            (self.api.set_vp_registers)(self.partition, self.vp_index, &name, 1, buf.as_ptr())
        };
        wh(hr, "WHvSetVirtualProcessorRegisters")
    }

    /// Guest debug single-step is not wired on WHP (diagnostics use the
    /// trace file instead).
    pub fn set_guest_debug_singlestep(&self) -> Result<()> {
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Halt wake + the device IRQ plumbing used by the Windows run loop
// ─────────────────────────────────────────────────────────────────────────────

/// Shared halt state: the run loop parks on `cvar` when the guest executes
/// HLT; the timer tick / console input threads notify on any event that
/// should resume the guest.
#[derive(Default)]
pub struct HaltWaker {
    pending: AtomicBool,
    gate: Mutex<()>,
    cvar: Condvar,
}

impl HaltWaker {
    pub fn notify(&self) {
        self.pending.store(true, Ordering::Relaxed);
        self.cvar.notify_all();
    }

    pub fn wait_timeout(&self, ms: u64) {
        let _g = self.gate.lock().unwrap();
        if self.pending.swap(false, Ordering::Relaxed) {
            return; // an event arrived before the wait
        }
        let _ = self
            .cvar
            .wait_timeout(_g, std::time::Duration::from_millis(ms));
    }
}

// The raw Windows handle crosses threads (the PIC tick) — shareable.
unsafe impl Send for Pic {}
unsafe impl Sync for Pic {}
