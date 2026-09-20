# VMM Specification — sandal on Apple Hypervisor.framework

**Purpose.** Single source of truth for the HVF backend (`src/vm.rs`
`run_loop_hvf`, and the HVF backend under `src/hypervisor/hvf/`). It is derived
from authoritative sources — Apple's Hypervisor.framework API/headers, the ARM
Architecture Reference Manual (generic timer, GICv3, WFI), and Linux arm64
boot/driver requirements — and documents the design that is actually
implemented.

The Linux/KVM backend (`src/hypervisor/kvm/`, `run_loop_kvm`) follows a
different contract: the GICv3 (VGIC) and the virtual timer are emulated
in-kernel, device interrupts are level lines driven via `KVM_IRQ_LINE`, WFI
blocks inside `KVM_RUN`, the BRK protocol arrives as `KVM_EXIT_DEBUG`, and
PSCI shutdown as `KVM_EXIT_SYSTEM_EVENT`. See the module documentation in
`src/hypervisor/kvm/mod.rs` for the full model.

---

## 1. Apple Hypervisor.framework contract

Sources: [Apple Hypervisor documentation](https://developer.apple.com/documentation/hypervisor)
and the local SDK headers under `Hypervisor.framework/Headers/`.

### 1.1 The virtual timer (vtimer)

The guest's ARM **virtual** generic timer is delivered through a documented
exit-reason flow:

1. The guest programs `CNTV_CTL_EL0` (enable, mask, ISTATUS) and `CNTV_CVAL_EL0`.
2. When the comparator expires, `hv_vcpu_run()` returns exit reason
   **`HV_EXIT_REASON_VTIMER_ACTIVATED`**.
3. At that point HVF **masks the vtimer automatically**. It will not fire again
   until the VMM clears the mask with **`hv_vcpu_set_vtimer_mask(false)`** —
   even if `hv_vcpu_run` is called again with the timer interrupt still pending.
4. Apple's doc for [`hv_vcpu_set_vtimer_mask`](https://developer.apple.com/documentation/hypervisor/hv_vcpu_set_vtimer_mask(_:_:)):
   *"The hypervisor caller must make the vTimer interrupt pending in the guest's
   virtual interrupt controller … and detect when the guest has serviced the
   interrupt. The mask function should be called … when deactivating an
   interrupt whose ID matches that of the vTimer."*
5. The vtimer interrupt is **PPI 11 in the FDT convention = GIC INTID 27**.

**Consequence (decisive):** the mask can only be cleared when the guest
*deactivates* the timer interrupt, so the VMM must **observe the guest's
`ICC_EOIR1_EL1` / `ICC_DIR_EL1` for INTID 27**. Those sysregs only trap when the
GIC is **not** owned by HVF (`hv_gic_create` not called). Therefore **the GIC is
emulated in software by the VMM**.

### 1.2 `hv_vcpu_set_pending_interrupt` — the delivery primitive

- Signature: `hv_vcpu_set_pending_interrupt(hv_vcpu_t, hv_interrupt_type_t, bool)`.
- `hv_interrupt_type_t`: **`HV_INTERRUPT_TYPE_IRQ = 0`,
  `HV_INTERRUPT_TYPE_FIQ = 1`** (local SDK `hv_vcpu_types.h`). This is a **bare
  IRQ/FIQ line assert**, not a GIC INTID.
- The line must **mirror the software GIC state**: assert it when an enabled
  interrupt passes PMR, and **de-assert it** when nothing is deliverable. A line
  that stays asserted after the guest has taken the interrupt livelocks Linux in
  a spurious-IRQ storm (IAR returns 1023 forever).
- The pending bit is consumed at `hv_vcpu_run` entry, so a deliverable
  interrupt is re-asserted before **every** run (Apple: *"The pending
  interrupts automatically cleared after hv_vcpu_run returns"*).  A redundant
  `false` write when the line is already low (idle iterations) is skipped; the
  VMM tracks the last written state.
- `Gic::deliverable()` has a fast path for "no pending bits at all", so idle
  loops do not rescan all 128 INTIDs.
- When asserted, the guest's `ICC_IAR1_EL1` trap returns the highest-priority
  pending, enabled INTID selected by the software GIC.

### 1.3 GIC ownership

- **Software GIC (chosen):** `hv_gic_create` is **not** called. GICD/GICR are
  left unmapped in the VM so guest accesses produce MMIO exits; ICC sysreg
  accesses trap. All pending/active/enable/priority state lives in the VMM.
- **Native GIC (rejected):** `hv_gic_create` + `hv_gic_set_spi`/distributor
  pokes. Rejected because the VMM cannot observe the guest's ICC EOI, so the
  vtimer auto-mask is never cleared and the timer fires once and stops.
  (HVF's native `hv_gic_set_spi` also does not reliably create pending state.)

### 1.4 Memory

- `hv_vm_map` maps the guest RAM buffer once at VM creation. Unmapped guest
  physical accesses produce data-abort exits that the VMM decodes as MMIO.
- Field drop order matters: the vCPU must be destroyed before the VM (Rust drops
  struct fields in declaration order).

---

## 2. ARM architecture (ARMv8-A / ARMv9-A)

### 2.1 Generic timer (D11)

- `CNTVCT_EL0 = CNTPCT_EL0 − CNTVOFF_EL2`. The VMM sets `CNTVOFF` once at VM
  creation via `hv_vcpu_set_vtimer_offset(mach_absolute_time())`, so the guest's
  virtual counter starts near zero and advances at the host rate.
- `CNTV_CTL_EL0`: bit0 `ENABLE`, bit1 `IMASK`, bit2 `ISTATUS`.
- `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` are read/written through
  `hv_vcpu_get/set_sys_reg`.
- Host clock: `mach_absolute_time()` counts at 24 MHz on Apple Silicon. The
  guest must be told `CNTFRQ = 24_000_000`; a wrong advertised frequency makes
  every guest `__delay`/timeout run at the wrong rate.
- Trapped counter reads are synthesized (`src/vm.rs::handle_sysreg`):
  `CNTFRQ`, `CNTPCT`/`CNTPCTSS` (host counter), `CNTVCT`/`CNTVCTSS`
  (host − `CNTVOFF`), `CNTV_CTL`/`CNTV_CVAL` (forwarded to HVF), and
  `CNTV_TVAL` (translated: write → `CVAL = CNTVCT + TVAL`, read → `CVAL − CNTVCT`).
  The `CNTV_TVAL` translation is required by the arm64 clockevent path.

### 2.2 GICv3 (software emulation, subset sufficient for Linux)

`src/hypervisor/hvf/gic.rs` implements enough of the GICv3 for Linux's `gic-v3` driver:

- **Distributor (GICD) MMIO:** CTLR, TYPER, IIDR, PIDR0–4; IGROUPR,
  ISENABLER/ICENABLER, ISPENDR/ICPENDR, ISACTIVER/ICACTIVER, IGRPMODR,
  ICFGR, IPRIORITYR. Bitmap registers are 32 INTIDs per 32-bit word
  (word *n* covers INTIDs `32n..32n+31`; *n* = 0 is redistributor-owned and
  reads as zero). ICFGR stores 2 bits per INTID; priorities are byte-wise.
- **Redistributor (GICR) MMIO:** RD frame (CTLR, IIDR, TYPER, WAKER, PIDRs) and
  SGI/PPI frame (`IGROUPR0`, `ISENABLER0`, `ICENABLER0`, `ISPENDR0`,
  `ICPENDR0`, `ISACTIVER0`, `ICACTIVER0`, `ICFGR0/1`, `IGRPMODR0`,
  `IPRIORITYR0..7`). INTIDs 0–31 live here; redistributor writes preserve the
  upper half-word (INTIDs 32–63 are distributor-owned).
- **GICR_TYPER:** bit 4 is `Last`, bits `[63:32]` are the processor affinity
  (0 for CPU0). Linux's `gic_iterate_rdists()` walks frames until `Last` is
  set, so a wrong bit makes it step into the next (unmapped) 128 KiB frame.
- **CPU interface (ICC sysregs, trapped):**
  `ICC_PMR_EL1`, `ICC_IAR1_EL1` (select highest-priority pending+enabled group-1
  INTID passing PMR, mark Active, else 1023), `ICC_EOIR1_EL1`/`ICC_DIR_EL1`
  (clear Active; INTID 27 also unmasks the HVF vtimer), `ICC_BPR1_EL1`,
  `ICC_CTLR_EL1` (read), `ICC_SRE_EL1`, `ICC_IGRPEN0/1_EL1`, `ICC_AP1R0_EL1`,
  `ICC_IAR0_EL1` (spurious).
- **Delivery:** before every `hv_vcpu_run`, the VMM re-pends level-triggered
  device SPIs from the device `interrupt_status` registers and then drives the
  IRQ line from `Gic::deliverable()`.
- **Interrupt map:** vtimer = **PPI 27**; device SPIs use `INTID = 32 + SPI`:
  virtio-net = SPI 16 (INTID 48), virtio-console = SPI 17 (49),
  root virtio-blk = SPI 18 (50), data virtio-blk = SPI 19 (51),
  virtio-rng = SPI 20 (52), virtio-fs devices = SPI 21+*i* (53+*i*, one per
  `--share`).  `src/irqs.rs` owns the SPI constants; the DTB passes the SPI
  number in the second interrupt cell.

### 2.3 WFI

- `WFI` traps to the VMM (`EC_WFX_TRAP`). The VMM advances the PC, and if an
  interrupt is already deliverable it re-enters immediately.
- Otherwise it blocks in `poll(host stdin, deadline)` where the deadline is the
  guest's `CNTV_CVAL` converted through the vtimer offset
  (`cval − (mach_absolute_time() − CNTVOFF)`, clamped to 1..1000 ms). On timeout
  it pends INTID 27; on stdin activity it drains host input into the console
  RX queue. Both paths return to `hv_vcpu_run`.

### 2.4 Exception exit (`HV_EXIT_REASON_EXCEPTION`)

The exit carries a syndrome. The VMM handles:

- `EC_DATA_ABORT` / `EC_DATA_ABORT_LOWER` (0x24/0x25): decode ISV/SAS/SRT and
  dispatch the access to the GIC, virtio devices, or the PL011 stub.
- `EC_SYSTEMREGISTERTRAP` (0x18): ICC registers, counter-timer registers, and
  feature-ID registers (§2.1).
- `EC_WFX_TRAP` (0x01): WFI/WFE (§2.3).
- `EC_AA64_HVC` (0x16): PSCI (SYSTEM_OFF/RESET end the run). `EC_AA64_SMC`
  (0x17) is treated as HVC; the DTB uses `method = "hvc"`.
- `EC_BRK` (0x3c): the guest init's control protocol (`INIT_CONFIG`,
  `EXPORT_RESIZE`, `EXPORT_DONE`). `hv_vcpu_set_trap_debug_exceptions(true)` is
  required so `BRK #imm` from EL0 traps to EL2 instead of being delivered to
  the guest as SIGTRAP.

---

## 3. Linux arm64 requirements

- **Boot protocol:** kernel Image loaded at `KERNEL_LOAD_ADDR + text_offset`;
  DTB passed in `x0`; entered at EL1h with `DAIF` masked and MMU off
  (`CPSR = 0x3c5`).
- **Arch timer:** `arm,armv8-timer` is the clocksource (`arch_sys_counter`,
  CNTVCT) and clockevent (CNTV). The DT lists the timer PPIs and advertises
  `clock-frequency = 24 MHz`. With `nohz=off highres=off` the kernel requests a
  periodic tick, so the software GIC + vtimer flow must keep delivering it.
- **Virtio:** virtio-mmio v2 devices for the console (`hvc0`), root disk
  (`/dev/vda`), overlay data disk (`/dev/vdb`), `virtio-net` (user-space
  backend), `virtio-rng`, and one `virtio-fs` device per `--share`. The PL011
  UART is only a stub for `earlycon` and panic output.
- **Block feature advertisement:** `VIRTIO_BLK_F_SIZE_MAX`/`SEG_MAX`/`FLUSH`.
  `seg_max` must be **`queue_size - 2`** (126 for the 128-descriptor ring):
  the header and status descriptors need two entries, and advertising more
  lets the guest build a request chain that can never fit.  The Linux
  `virtio_blk` driver converts `seg_max` straight into `max_segments`; the
  virtio-blk convention is `queue_size - 2`.
- **Virtio-fs:** served from the host path via FUSE protocol; the backend runs
  in the VMM thread, so a shared directory is a plain synchronous device.
- **User-space networking:** `src/unet.rs` implements the guest-facing TCP/UDP
  stack plus a NAT to host sockets via `connect()`/`sendto()`; a kqueue poller
  thread kicks the vCPU (`hv_vcpus_exit`) when host data arrives, and
  `src/net.rs` enforces the protocol/host allow-list.  Fast path: TCP frames
  are built in a **single allocation** with in-place checksums (no per-packet
  temp buffers), host socket reads are **batched** up to the guest's window
  budget (16 KiB) and split into MSS segments, and the virtio-net TX assembly
  buffer is reused instead of allocated per packet.
- **Console:** the host terminal is switched to raw mode on startup and restored
  on exit, so every keystroke (Tab, CSI replies, partial lines) reaches the
  guest instead of being line-buffered by the host tty.  The user command is
  started with **cwd = the guest home** (`/root`, matching `HOME`), so an
  interactive shell opens in `~` instead of `/`.
- **Guest init protocol:** `/init` uses `BRK #imm` for its config blob and for
  `sandal-export`; `SANDAL_EXIT:` / `SANDAL_EXPORT_PATH:` console markers are
  intercepted by the VMM (detected at any position in the line, with
  marker-prefix bytes held back so mid-line markers are still hidden).  The
  `SANDAL_EXIT:<code>` marker sets the guest exit status and shuts the VM down
  immediately, so the kernel's poweroff print is never forwarded; the code is
  returned as sandal's process exit status.

---

## 4. Verified constants (local SDK `Hypervisor.framework/Headers/hv_vcpu_types.h`)

- Exit reasons (`hv_exit_reason_t`, uint32, sequential):
  **`HV_EXIT_REASON_CANCELED = 0`**, **`HV_EXIT_REASON_EXCEPTION = 1`**,
  **`HV_EXIT_REASON_VTIMER_ACTIVATED = 2`**, `HV_EXIT_REASON_UNKNOWN = 3`.
- Interrupt types: **`HV_INTERRUPT_TYPE_IRQ = 0`**,
  **`HV_INTERRUPT_TYPE_FIQ = 1`**.
- Apple's vtimer exit comment (verbatim): *"ARM Generic VTimer became pending
  since the last hv_vcpu_run() call returned. The caller is expected to make the
  interrupt corresponding to the VTimer pending in the guest's interrupt
  controller. This exit automatically sets the VTimer mask. The VCPU will not
  exit with this status again until after the mask is cleared with
  hv_vcpu_set_vtimer_mask(), which should be called during a trap of the EOI for
  the guest's VTimer interrupt handler."*

---

## 5. Key design decisions

1. **Software GICv3 in the VMM** — required so the VMM observes the guest's EOI
   and can unmask the vtimer (§1.1, §1.3).
2. **Timer:** `HV_EXIT_REASON_VTIMER_ACTIVATED` → pend INTID 27 + assert the IRQ
   line; unmask on EOI/DIR of 27.
3. **Counter/timer sysregs:** set `CNTVOFF` once; synthesize trapped counter
   reads; forward `CNTV_CTL`/`CNTV_CVAL` to HVF and translate `CNTV_TVAL`.
4. **Virtio device parameters are part of the ABI:** every optional feature
   that changes guest request shapes (`SEG_MAX`, queue size) must respect the
   virtqueue geometry, or the guest's block layer can deadlock itself.
5. **Frequency:** advertise 24 MHz in the DTB.
6. **Device IRQs:** level-triggered SPIs in the software GIC; the IRQ line is
   mirrored (asserted *and* de-asserted) before every run.
7. **No host-side timer/IRQ recovery hacks** (no ISTATUS polling, CVAL forcing,
   deferred interrupts, or offset rewrites).

## 6. Implementation notes (hard-won; do not regress)

These were the root causes of the interactive hang; each is covered by tests or
the `make test` gate:

- `GICR_TYPER.Last` is **bit 4**, not bit 24 (boot-time Oops otherwise).
- Distributor bitmap registers start at word *n* = INTIDs `32n..32n+31`; an
  off-by-one silently enables the wrong INTIDs and device IRQs are never
  delivered (the "lost wakeup" symptom).
- The vCPU IRQ line must be **de-asserted** when nothing is deliverable,
  otherwise Linux livelocks in a spurious-IRQ storm.
- WFI must compare `CNTV_CVAL` against the **virtual** counter
  (`host − CNTVOFF`), not the raw host counter, or every WFI re-pends the
  vtimer (400 k IRQ/s storm).
- The host tty must be in raw mode or Tab/CSI input never reaches the guest.
- `hv_vcpu_set_trap_debug_exceptions(true)` is required for the `/init` BRK
  protocol (otherwise init dies with SIGTRAP).
- `CNTV_TVAL` writes must be translated to `CNTV_CVAL` when trapped; the arm64
  clockevent arms the tick through TVAL.
- **Never enable `CONFIG_MAGIC_SYSRQ` in the guest kernel.** The hvc
  (virtio-console) driver implements sysrq as a `^O` (Ctrl-O) toggle followed
  by the next byte as the command (`hvc_console.c`, `#ifdef CONFIG_MAGIC_SYSRQ`).
  A stray Ctrl-O — or the byte after it, which is often a terminal DSR reply —
  is consumed as a sysrq command instead of reaching the shell.  `h`/unknown
  keys print the sysrq help, a digit changes the console loglevel (0 silences
  it), and `b`/`o` reboot/power off; all of these look exactly like a VMM hang.
  The diagnostic kernel therefore keeps the passive options (KALLSYMS,
  STACKTRACE, DEBUG_FS, DETECT_HUNG_TASK) but **not** MAGIC_SYSRQ.
- `seg_max` must leave room for the header and status descriptors
  (`seg_max <= QUEUE_SIZE - 2`).  Advertising `seg_max == 128` on a
  128-descriptor ring let the guest build 128-segment requests (130
  descriptors); `virtqueue_add_sgs()` then returned `-ENOSPC` on every retry,
  the guest stopped its block hardware queue, and no completion could arrive
  to restart it.  Symptom: `Writeback` stuck in `/proc/meminfo`, `ios in
  progress` frozen in `/proc/diskstats`, and a demand-paging task blocked in
  `D` state (uv startup), while device traces show an empty, idle queue.  The
  fix is the correct `seg_max` advertisement (`queue_size - 2`), not a
  retry/workaround in the VMM.
