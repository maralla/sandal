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
