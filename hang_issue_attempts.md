# Virtio console / interactive hang — cause & gate

**Important**

* We prefer fast iterating on fixing the problem
* There is no need to run too many times, we first let 3 runs can stably success
* Always run the test script with `timeout 60`, there is no need to set a longer timeout, if the command can't finish within 60s, something must be wrong.
* After code changing, use `make` to rebuild the project.
* We are fixing the hang issue, not just let the uv python pass, be focusing on the ROOT CAUSE.
* We can utilize some bisect, vairable control methods for finding the root cause.
* If no clue, add more debugging prints or traces, then investigate what is happening.
* Never ask or shows the user an intermediate result, the user wants the finial fully fixed state, so always keep iterating.

## Goal

Stable interactive shell, Python/`uv`, Tab/readline, and exit/restart paths under **`--no-cache`**. Internal gate driver: **`scripts/repro_python_tab.sh`** (flags and env in the script header). Never **`SANDAL_USE_CACHE=1`** for this gate.

Goal: Remove the real failure mode in sandal (virtio console, synthetic terminal I/O, RNG/MMIO paths, vCPU loop ordering, etc.) so shells, uv, and CPython behave correctly under the same inputs a user would send.

Not the goal: Tweaking expect (extra sleeps, looser patterns, fewer phases, “retry until green”) so CI goes green while the hypervisor still mis-handles console input or device completion.

The repro script’s job is only to stress the same in-project paths (second uv run, readline/CSI, etc.) under timeout 60. Fixes belong in src/vm.rs, src/virtio/console.rs, and related code, with SANDAL_TRACE_CONSOLE_IO (and friends) used to confirm behavior—not to replace a proper fix.

**Trace** (default file **`sandal_trace.log`**, or **`SANDAL_TRACE_FILE`**): **`SANDAL_TRACE_CONSOLE_IO=1`** → **`CONSOLE_IO:`** (**STDIN_POLL**, **GUEST_LINE**, **SYNTH_RX**, **TX_CHUNK**, **WFI** backlog, **`UV_WATCH`** **`region=`**, **`LOW_PROGRESS_KICK`**, **`VTIMER_SAMPLE`** ~2s, virtio-rng **`RNG_NOTIFY_NOOP`**, **`RNG_ORPHAN_IRQ_CLEAR`**, **`RNG_NOOP_FORCE_EXIT`**, **`RNG_INTERRUPT_ACK`**). **`SANDAL_TRACE_CONSOLE_DEEP=1`** adds **CONSOLE_DEEP** (poll phases, WFI, **`BLK_POLL_HIT`**, **`RNG_POLL_HIT`**, **`RNG_INTERRUPT_STATUS_READ`**, **`DATA_BLK_POLL_HIT`**, **`NET_RX_DELIVERED`**, etc.). **`SANDAL_TRACE_GUEST_SHELL=1`** → **GUEST_SHELL_LINE**. Repro **`--trace-console-io`** / **`--trace-console-deep`** may appear **before or after** the subcommand (`scripts/repro_python_tab.sh` strips global flags from any position).

**Note** investigate the hang issue. keep tracing. never stop. use the test script to verify. note for each turn run of the test script you use timeout 60s to limit the time. if it does timeout, it means something must be wrong. don't report intermediate state to user, all the harness is for you not the user. the user only want to see the final stable and complete fixing.

---

## What caused the problem (current understanding)

The failures (timeouts like **no `>>>` after `uv run python`**, or no shell after exit) were **not** one magic kernel bug. On the VMM side they line up with **virtio-console stdin/RX/TX scheduling** and **lost input**:

1. **Lost host stdin**  
   The main loop did `read()` on stdin and called `inject_rx`. If the guest had **no receiveq buffers** yet, injection failed but the bytes were **already consumed** from the host fd. There was no **`rx_backlog`**, so those bytes were gone. Partial lines (e.g. `uv run python\r`) never reached the guest → harness timeouts.

2. **Bad receiveq completions**  
   `inject_rx` could **advance the used ring** (consume a driver buffer) while copying **zero** bytes into the guest when data was still pending. That **wedges** the Linux virtio-console path: the driver thinks a buffer was used but got no payload.

3. **TX bursts starving stdin / RX**  
   Tab completion often produces **many** small transmitq descriptors. Draining the **whole** transmit ring in one go (especially inside a single MMIO trap) meant the VMM thread spent a long time only doing **guest→host** console work. **`poll_stdin` and RX inject** ran **after** that work, so host input and guest RX were **delayed** behind huge TX backlogs — timing-dependent “hangs” under real pacing.

4. **Idle guest + pending stdin**  
   When stdin was queued but the guest had not reposted RX yet, the vCPU could sit in **WFI** with nothing to repost buffers. Without a **kick** (`force_exit`) when backlog is non-empty, progress depends on unrelated interrupts — flaky under load.

5. **Guest-side sensitivity (secondary)**  
   Default CPython + **readline** after heavy Tab / terminal-query traffic can be fragile; the product policy is still to fix the **VMM** (not ship `PYTHON_BASIC_REPL` in init). CSI/query synthesis and pacing matter, but **input loss and TX starvation** are the primary mechanical causes on the hypervisor side.

---

**Note that the methods attempted below are all failed to fix the hang issue**

## Mitigations in the current codebase (summary)

- **`rx_backlog`** + **`push_rx_and_drain` / `drain_rx_backlog`** so failed inject does not drop bytes (host then synth). Every **host** `push_rx_and_drain` pre-drains **`rx_backlog_synth`** via **`drain_rx_backlog_synth_only`** so partial CPR is not completed after the next host chunk.  
- **`inject_rx` → `usize`**, and **do not** post a receiveq used entry with **0** bytes copied while stdin remains.  
- **RX `QUEUE_NOTIFY`**: drain backlog when the guest posts buffers.  
- **TX**: bounded heads per **`process_tx`** call + **pre-`vcpu.run()`** drain when the transmitq still has work.  
- **`poll_stdin`** (and **kick**) on virtio-console MMIO **writes** where wired; **SPI** level follows **`interrupt_status`** after console MMIO.  
- **Virtio `DEVICE_CONFIG` MMIO reads** use ARM64 fault **SAS** (byte/half/word/double) over the 16-byte console config so `readl`/subword probes match Virtio **§5.3.7** layout.  
- **Pre-`vcpu.run()`**: multiple console TX slices (**`TX_HEADS_PER_SLICE`**) each followed by **`poll_stdin`** / kick (bounded slice count) so bursts do not starve RX.  
- **`poll_stdin`** before virtio-blk **`poll_pending`** and again after; console MMIO **reads** poll like writes; extra poll after **`process_tx`** on TX notify before **`process_console_tx`**.  
- **`poll_stdin`** loops **`read()`** until **EAGAIN** (cap **16 KiB**/call) so expect bursts are not split across **`vcpu.run()`** boundaries.  
- **Low forward-progress watchdog**: **`force_exit`** if **≥2 s** wall with fewer than **250** main-loop iterations while interactive (`boot_complete` + `command_injected`) — nudges long **`hv_vcpu_run`** stalls under human-like pacing; **`poll_stdin`** (`low_progress_kick`) runs immediately before that **`force_exit`** so host bursts are not stuck in the pipe across rare-exit windows.  
- **Harness**: **`REPRO_FAIL_FAST=1`** or **`--fail-fast`** lowers expect timeouts so agent/CI runs **fail quickly** on timeout class (still default human pacing unless **`REPRO_FAST_STRESS=1`**).

---

## Status

- **`REPRO_FAST_STRESS=1`**: **`--stress-repeat 4`** (6–12 reps) has been **green** in agent runs after R2-8 stdin draining + EINTR.  
- **Default** pacing (`--stress 4` / `--stress-repeat 4 20`, no `REPRO_FAST_STRESS`): **R2-12** adds a periodic **`force_exit`** when wall time advances with almost no vCPU-loop iterations (paced **no `>>>` after `uv run python`** class). Re-verify with **many** consecutive green **default** runs after any VMM change.
- **Trace correlation**: failures often show **17 bytes** (`uv run python -u\r`) delivered (`rx_backlog=0`) then little guest **TX** before **`>>>`** — distinguish from harness-only timeouts using **`CONSOLE_IO`** / **CONSOLE_DEEP**.  **`region=virtio_rng`** on **`UV_WATCH`** / **`LOW_PROGRESS_KICK`** with **`RNG_NOTIFY_NOOP`** (`avail_idx == last_avail`, **`irq_status=1`**) indicates the vCPU was stuck in virtio-rng MMIO; **`RNG_ORPHAN_IRQ_CLEAR`** logs when the VMM drops a stale used-buffer bit on redundant notify (no avail work).

---

## Change log (this branch — optional)

| Step | Note |
|------|------|
| R2-1 | Backlog + safe `inject_rx` + RX notify drain + SPI level on console MMIO |
| R2-2 | `force_exit` when `rx_backlog` non-empty after `poll_stdin` |
| R2-3 | `poll_stdin` at start of virtio-console MMIO writes |
| R2-4 | Sliced TX + `tx_queue_has_pending` + pre-`vcpu.run()` console drain |
| R2-5 | SAS-aware virtio-console config `mmio_read` |
| R2-6 | Smaller `TX_HEADS_PER_SLICE`; interleaved TX/stdin before `vcpu.run()`; stdin before/after blk poll; console MMIO read + post-TX polls |
| R2-7 | `SANDAL_TRACE_CONSOLE_DEEP` / `SANDAL_TRACE_GUEST_SHELL` + `vmm_trace.rs`; `TX_HEADS_PER_SLICE` 2048 |
| R2-8 | `poll_stdin`: drain reads until EAGAIN (16 KiB cap); **retry on `EINTR`**; trace errno for real read errors |
| R2-9 | Removed `docs/virtio-console-compliance.md`; AGENTS + trace comments point at this file only |
| R2-10 | `poll_stdin` returns whether bytes were delivered to the console; **`force_exit`** on that path (and EOF inject) everywhere we already kick on `rx_backlog` — wake WFI sooner after host typing |
| R2-11 | **`SANDAL_TRACE_CONSOLE_IO`**: `CONSOLE_IO` lines for **STDIN_POLL** (host vs guest RX bytes + preview), **GUEST_LINE**, **SYNTH_RX**, **TX_CHUNK** (≥48 B), **WFI_RX_BACKLOG**; virtio **`drain_rx_backlog` / `push_rx_and_drain`** return **guest byte** counts |
| R2-12 | **Low forward-progress watchdog**: if wall time advances **≥2 s** (was 4 s) while the main loop runs fewer than **250** iterations (tuned from 400), **`force_exit`** the vCPU (same class of nudge as stdin/network pollers) so long `hv_vcpu_run` stretches under paced I/O still see timer/virtio progress |
| R2-13 | **`CONSOLE_IO`**: **`LOW_PROGRESS_KICK`** (watchdog with **fault `region=`** when last exit was MMIO), **`UV_WATCH`** **`region=`**, **`VTIMER_SAMPLE`** (~2s); **`CONSOLE_DEEP`**: **`BLK_POLL_HIT`**, **`DATA_BLK_POLL_HIT`**, **`NET_RX_DELIVERED`** |
| R2-14 | **`poll_stdin`** phase **`low_progress_kick`** immediately before watchdog **`force_exit`** |
| R2-15 | Repro **`REPRO_FAIL_FAST=1`** / **`--fail-fast`**: shorter expect timeouts for quick agent signal; watchdog wall window **2 s** |
| R2-16 | Repro: **`--trace-*` / `--fail-fast`** flags work **after** the subcommand; snapshot restore omits **`virtio_rng`** when the file has no rng MMIO blob |
| R2-17 | Virtio-rng: **`clear_used_irq_if_no_pending_avail`** on redundant **`QueueNotify`** + **`CONSOLE_IO`** **`RNG_ORPHAN_IRQ_CLEAR`** / **`RNG_NOOP_FORCE_EXIT`**; console MMIO **read** path SPI resync |
| R2-18 | Same orphan IRQ clear after **`poll_pending`** on **pre-** and **post-`vcpu.run`** rng paths (`phase=pre_vcpu` / `post_vcpu` in **`RNG_ORPHAN_IRQ_CLEAR`**) |
| R2-19 | **`drain_rx_backlog_synth_only`** + host **`push_rx_and_drain`**: pre-drain stuck **`rx_backlog_synth`** before appending any host bytes (fixes `echo`→`cho` / second-`uv`; keep host-then-synth in **`drain_rx_backlog`**) |
| R2-20 | **`inject_rx`**: removed 1-byte-chain **stall** (was wedging **`last_avail`** vs full RX avail ring: `rx_heads_pending` ≫ 0, second **`uv run`** timeout). Rely on **`stdin_line_defer`** + CPR/host **coalesce** for `echo`→`cho`; reintroduce stall only with a predicate that cannot block **`uv`/merged CSI** |
| R2-21 | **`poll_stdin`**: no CPR/host coalesce on **`uv run`** lines (`harness && !uv_stdin`). **`harness_console_rx_merge_synth_pending`** also refuses merge when synth **> 64 B** (**`HARNESS_RX_SYNTH_COALESCE_SKIP`**) |
| R2-22 | **`synthesize_terminal_query_replies`**: **`MAX_SYNTH_PER_TX_BATCH` 256→64**; cap **`console_synth_rx_pending`** at **384 B** (drop oldest). **`poll_stdin`**: before **`uv run`**, trim pending synth to **128 B**; after delivering **`uv`**, **`drain_rx_backlog`** once to catch newly posted RX buffers |
| R2-23 | Trace showed **`SYNTH_FLUSH_BEFORE_HARNESS_STDIN` pending=128** then **128 B `SYNTH_RX`** immediately before **`uv run python -u\r`** with **`rx_heads_pending=128`**. **`flush_console_synth_rx_pending`**: chunked (**40 B**/step, loop); **`MAX_SYNTH_BEFORE_UV`/`CONSOLE_SYNTH_RX_FLUSH_CHUNK` = 40**; pending total cap **192**; **`MAX_SYNTH_PER_TX_BATCH` 40** |
| R2-24 | **`inject_rx`**: cap receiveq **heads per call** at **`q.num.clamp(1, 64)`** so the used ring is not advanced with a stale single `used_idx` read across **>~queue_size** completions (used-ring wrap / guest wedge). Unit test **`inject_rx_second_call_continues_after_head_cap`** |
| R2-25 | **`poll_stdin`**: **`console_synth_rx_pending.clear()`** when **`stdin_chunk_contains_uv_run`**; **`SYNTH_FLUSH_BEFORE_HARNESS_STDIN`** skipped when chunk contains **`uv run`** (trace showed flush + **`uv`** same poll while **`uv_stdin` false** edge). Device **`rx_backlog_synth`** still pre-drained on host **`push_rx_and_drain`** |
| R2-26 | **`VirtioConsoleDevice::discard_rx_backlog_synth`** before **`push_rx_and_drain`** (**Host**) when stdin chunk contains **`uv run`** — do not inject stuck CPR from **`rx_backlog_synth`** ahead of the **`uv`** line |
| R2-27 | **`repro_python_tab.sh`**: even-phase REPL exit uses **`send_line_exit_python_repl`** (one **`exit()\r`** write after **`^U`**, like **`send_uv_run_python`**) — per-keystroke **`exit()`** interleaved harness **`stty`/`echo`/`uv`** with **`>>>`** readline echo so **`uv`** reached Python; **`wait_ash_prompt` (`/ #`)** was dropped (prompt not reliably visible in expect buffer) |

---

## Exit-cycle GIC starvation hang (WIP, 2026-08)

Reproduces at attempt 4–12 (varies) under both `REPRO_FAST_STRESS` and default pacing.

**Symptom.** After Python `exit()`, the guest enters the idle loop (`do_idle` → `cpu_do_idle`): it reads the cycle counter (`mrs x5, CNTPCTSS_EL0` at `0xffff80008035a00c`) and executes **WFI** (`0xffff80008035a028` = `0xd503207f`), suspending at `PC=0xffff80008035a02c`. Every subsequent exit is `CANCELED` (100 ms poller); no MMIO/sysreg exception ever fires; `consecutive_canceled` climbs past 900. SP804 Timer1 shows `ris=1 mis=1` and SPI 29 is asserted every iteration, but the guest never takes it. Injected console input never wakes it either.

**Confirmed blockers (CONSOLE_IO traces + Hypervisor error codes):**
1. During the hang every GIC/ICC op fails with **`HV_BAD_ARGUMENT` (0xfae94003)** while the vCPU is suspended mid-WFI: `hv_gic_get_icc_reg(IAR)` reads, `hv_gic_set_icc_reg(DIR/EOIR)` writes, `hv_vcpu_write_sys_reg(CNTVCT)` writes, and `hv_gic_state_restore` all fail. So the GIC cannot be inspected or reset once the hang starts (save still returns a blob; restore errors).
2. `hv_vcpu_set_pending_interrupt(0,true)` returns Ok but does **not** wake a WFI-suspended vCPU (no exception exit after injection).
3. Writing `HV_REG_CPSR` to clear PSTATE.I returns Ok and the VMM-side read shows I=0, but the next CANCELED read shows `0x410000c5` (I=1, F=1) again — the guest is inside an exception context (I+F hardware-masked) and re-masks / HVF doesn't persist the write across the run.
4. Arch timer broken on Apple Silicon HVF: CNTVCT/CNTPCT/CNTFRQ read 0 from VMM, vtimer never fires (`exit_reason=2` count 0), CNTV_CTL writes are banked. Counter reads do not trap (0 `CNT_TRAP_RD`), so no synthetic counter.
5. Guest time base is fine (SP804 Timer2 clocksource advances); the hang is purely interrupt delivery.

**Attempted recoveries (all failed):** CPSR.I clear; SPI level pulse; ICC DIR; `set_pending_interrupt`; GIC state save/restore (restore errors mid-hang; firing early corrupts a working GIC); force-enabling CNTP/CNTV (banked); removing arch-timer dtb node (breaks boot).

**Working theory.** Guest is stuck in a WFI inside an exception/idle context with PSTATE.I=1 (F=1 ⇒ hardware-masked). No interrupt can wake it (I=1), no event exists (single vCPU), and HVF blocks VMM-side GIC/state manipulation while the vCPU is suspended. Exact trigger after ~6 exit cycles still open. Suspects: spurious-interrupt-driven `disable_irq`, a stuck-Active SPI blocking delivery, or an HVF GIC state issue after many WFI-cancel cycles. Fix must be preventive (keep timer/console SPI delivery alive before the hang), since in-hang recovery is impossible.

**Correction (later):** The `HV_BAD_ARGUMENT` errors for IAR/EOIR/DIR were NOT evidence of a broken GIC. The Apple `hv_gic_icc_reg` enum (hv_gic_types.h) does **not** expose IAR1_EL1/EOIR1_EL1/DIR_EL1 — those register encodings (0xc660/0xc661/0xc659) are simply invalid, so HVF returns `HV_BAD_ARGUMENT`. The supported registers (PMR, BPR0/1, AP0R0/1, RPR, CTLR, SRE, IGRPEN0/1) read back correct values during the hang (pmr=0xf0, igrpen1=1, ctlr=0x40400). So the GIC CPU-interface config is healthy and SPI delivery via `hv_gic_set_spi` may be working; the real blocker is the guest not taking the interrupt.

Refined picture: the guest is stuck inside an **exception (IRQ) context with PSTATE.I=1, F=1 and SPSR_EL1.I=0** — i.e. an IRQ handler (or IRQ-exit schedule path) entered the idle loop and its WFI cannot wake because I is still masked (hardware masks I/F on exception entry; the handler never returned/ERET'd). Forcing a raw ERET by pointing PC at an ERET instruction in the kernel image crashes the guest (the saved ELR_EL1 is not a valid continuation), so that recovery is off the table. No VMM-side recovery has been able to make this guest take an interrupt once it reaches this state.

**Final state (2026-08):** The hang remains unfixed. Key facts established this session:
- The GIC CPU-interface is healthy during the hang: PMR=0xf0, IGRPEN1=1, CTLR=0x40400, and **AP1R0=AP0R0=0** (no interrupt stuck Active).
- The SP804 timer SPI is asserted (`set_gic_spi` every iteration, device `ris=1`), but the guest never takes it even with PSTATE.I cleared to 0 (confirmed via ERET setup: SPSR_EL1/ELR_EL1/PC writes all return Ok and the subsequent CPSR read shows I=0, yet still no exception exit / MMIO from any ISR). This strongly implies the **timer and console SPIs are disabled in the GIC distributor** (kernel `disable_irq`), which `hv_gic_set_spi` cannot override (level assert on a disabled SPI never becomes pending) and which the VMM cannot re-enable (no distributor access; `hv_gic_state_restore` succeeds but does not restore the distributor enable bits).
- **Panic clue:** forcing `TIF_NEED_RESCHED` on the swapper task makes the guest panic with "Attempted to kill the idle task!" — the idle task's state is being corrupted during the exit cycle, consistent with the shell/python teardown leaving the scheduler in a bad state. This suggests the root trigger is in the exit-cycle task/scheduler handling, not purely the GIC.
- The one working lever is `hv_vcpu_write_sys_reg` for SPSR_EL1/ELR_EL1 (they succeed during the hang), so a correct exception-return could in principle unblock the guest — but with the SPIs disabled there is nothing to wake it even then.

Next promising directions: (a) find and prevent whatever leaves the swapper/scheduler corrupt during Python exit (the panic is a strong lead), (b) determine why the kernel disabled the timer/console IRQs and prevent that, (c) find a way to re-enable GIC distributor SPIs from the VMM.

**Breakthrough + current state (2026-08-02):**
- **Root cause of the interrupt loss found:** HVF's `hv_gic_set_spi` does NOT create pending state — GICD_ISPENDR1 stays 0 even for asserted+enabled SPIs (a known HVF GIC quirk). Verified via the new `hv_gic_set_distributor_reg`/`hv_gic_get_distributor_reg` APIs (GICD_ISENABLER1=0x3ffb0000, timer/console enabled; GICD_ISPENDR1=0 even when asserted).
- **Workaround (in code):** write GICD_ISPENDR1 directly to set the timer (INTID 61=bit29) and console (INTID 60=bit28) pending bits, gated so we only pend an SPI whose device actually has work (pending an idle console SPI makes the ISR read 0 → spurious → the kernel disables the line). Also pend the RNG SPI on RNG work. This moved the hang from attempt ~6 to attempt ~12, and the guest now takes console interrupts regularly (~19 Hz).
- **Remaining blocker:** the guest is still ~50x slow (timer ISR at ~5 Hz vs 250 Hz). It spends most time in an **idle WFI entered with PSTATE.I=1** (the kernel's IRQ-exit path schedules the idle task with I still masked; its WFI never wakes on the pended SPI, and HVF has no API to send the event/WFI-wake or to persist a CPSR.I=0 write). Every VMM-side attempt to clear I (CPSR write doesn't survive the run; forced ERET either corrupts the guest when fired during normal idle or is one-shot and doesn't prevent re-entry into the I=1 idle) has failed. The result is the guest reaches attempt ~12 but each phase takes ~7s, so the 200-phase gate (timeout 60) cannot pass.
- **Real improvement to keep:** the ISPENDR pending-bit workaround (timer + console + rng) is a genuine fix for the "asserted SPI never pends" HVF bug and should stay.

---

## Phase-2 uv block fixed (2026-08-04)

**Symptom.** Under default pacing (`--stress-repeat 4 2`, no `REPRO_FAST_STRESS`), phase 2 (first exit cycle after the Tab/readline phase) reliably failed with `timeout: no >>> after uv run python (attempt 2)`. The second `uv run python -u` was injected (`backlog=0`, echoed), the shell forked uv (task appears, `st=0x2001`), but uv never printed the Python banner and the guest fell into the idle WFI loop with a full console RX ring (`avail=148 used=20 last_avail=20`) — a process blocked reading stdin. Trace of the block: uv's user code takes a data abort (`ESR=0x92000047`, translation fault) during startup and never resolves it.

**Key empirical findings that isolated the cause:**
- Faster wake cadence made it WORSE: 10 ms poll → exit-cycle green 5/5, but 1 ms poll → exit-cycle fails (more force-exits = more preemption).
- The block is a race: 13 s settle + char-by-char `import pl` + Tab reproduces it reliably; single-shot `uv run python` + short settle passes 6/6.
- No kernel oops/panic (KLOG scan of guest RAM finds only rodata format strings). Not caused by vtimer-offset hack, the STUCK_KICK SPI pulse, a stuck-Active interrupt (`AP1R0=0`), disk I/O (no pending blk), or the terminal-query synthesis (that code is not in this tree).

**Root cause.** The VMM force-exited the vCPU on a fixed cadence (stdin poller every 10 ms + `LOW_PROGRESS_KICK` every 5 ms), **regardless of whether the guest was in WFI (safe to wake) or actively computing**. A low iteration delta is ambiguous: it means "the loop is blocked in one `hv_vcpu_run`", which is true both for a long WFI (idle — force_exit is needed) and for a long compute slice (uv startup — force_exit preempts it). Force-exiting active guest code slices a critical section / page-fault handler and, after the heavy Tab/readline interrupt traffic has left the guest's scheduler fragile, the second uv's startup page fault never resolves → uv blocks forever reading stdin.

**Fix (in code).** Make the wake cadence adaptive to whether the vCPU is parked in the idle WFI:
1. New `guest_idle` `Arc<AtomicBool>`, set by the main loop after every exit from the guest PC: idle when `PC ∈ [0xffff80008035a000, 0xffff80008035a200)` (`cpu_do_idle` WFI region).
2. `stdin_poller` uses a 10 ms force-exit cadence when `guest_idle`, 100 ms when the guest is computing — so active code is only sliced once every 100 ms instead of every 10 ms. stdin data still wakes immediately regardless.
3. `LOW_PROGRESS_KICK` only force-exits when `guest_idle` (or `consecutive_canceled > 2000` as a stuck fallback).
4. Removed the STUCK_KICK SPI pulse (low→high on every `cc>=3`) — it was built on the disproven stuck-Active theory and is a spurious-interrupt source; gated `GICD_ISPENDR1` pends handle delivery.

**Result.** Verified under the current tree (branch `continuation`, source = the same `src` as the original checkout):
- `--stress-repeat 4 2` (default pacing): 8/8 green.
- `--stress-repeat 6 2` (default, 12 phases / 6 exit cycles): green.
- `--stress-repeat 4 6` (fast stress, 24 phases / 12 exit cycles): green.
- `--exit-cycle` (fast): green (5/5 + earlier).
- Reproducer (char-by-char `import pl` + Tab + 13 s settle + second uv): 5/5 green (was blocking before the fix).

## 200-phase run: residual block (2026-08-04, WIP)

The full `--stress 200` (fast stress) gate does NOT yet pass: it blocks at attempt ~12 with a 100 ms compute backoff, ~20 with 250 ms. The block: after a phase's `^U + exit()`, the **shell never returns to the prompt** (`warn: no ash / # seen after exit+settle`); `uv` (the `uv run` parent of the exited python) is stuck in `st=0x2001` — its `waitpid` for python never completes. It is a **true deadlock**, not a timeout (the guest keeps ticking, `SP804_WR` continues, but the banner never appears).

**Mechanism (best understanding).** A lost wakeup in the guest's exit path: `uv` sleeps in `waitpid`; the scheduler then never runs python (its child) to exit it, because the guest's scheduler was corrupted by the VMM's abnormal timer delivery over ~10-20 exit cycles. The corruption is the guest's IRQ-exit path scheduling the idle task with `PSTATE.I=1` (`preempt_schedule_irq` runs the idle task with I still masked — a *normal* transient state; HVF's WFI-not-waking bug made it look abnormal). Each timer delivery at a bad point (a force_exit interrupting the wait/wakeup path) is a chance to corrupt; longer idle/exit chains accumulate it.

**Things tested and ruled out as the cause:**
- Increasing RAM 256 MB → 1024 MB (not OOM; still blocks at attempt 20).
- Enabling virtio-rng (guest still blocks; the hwrng kthread deadlocks on the virtio-rng `reinit_completion` vs `complete` race — the device fills a few buffers then stalls, so no entropy flows; even fixing `RNG_KICK_RACE` to write `GICD_ISPENDR1` didn't help). RNG left disabled.
- Removing the idle-WFI `PSTATE.I` clear (the VMM workaround that clears I at `cpu_do_idle`'s WFI) — it's a spurious-interrupt/corruption risk (clearing I lets a timer into the `preempt_schedule_irq` context), but removing it was *neutral* on the 200-run (still attempt 20). It is now removed anyway, because the periodic force_exit wakes the WFI and the armed pending timer is taken at a natural I=0 point after the guest ERETs.
- Increasing the compute backoff 100 → 250 ms reduces the block rate (attempt 12 → 20), confirming preemption-during-compute is a contributor, but no feasible backoff reaches 200 phases (the guest becomes too slow).

**Residual:** a guest-side scheduler/waitqueue lost wakeup after ~10-20 exit cycles. VMM-side recovery (force_exit, TIF_NEED_RESCHED) does not unstick it — the re-check re-sleeps, so the waitqueue state itself is corrupt. Likely needs a preventive fix that keeps the guest's IRQ-exit path from scheduling with I=1 in the first place (e.g., a cleaner timer delivery that HVF wakes naturally), which is the same conclusion the earlier session reached.

**Net state:** the primary gates (`--exit-cycle`, `--stress-repeat 4 2` default pacing, fast stress) are green; the 200-phase marathon still hits a rare deadlock at ~attempt 20.
