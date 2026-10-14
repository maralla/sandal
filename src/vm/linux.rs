//! Linux host specifics: the KVM run loop shell, the stdin poller thread,
//! and the device IRQ-line engine that wakes hlt/WFI-blocked vCPUs.
//!
//! Backend model (arm64 and x86_64, see `src/hypervisor/kvm/mod.rs`): the
//! interrupt controller and the guest timer are emulated in-kernel, so device
//! interrupts are lines driven via `KVM_IRQ_LINE` and idle guests block
//! inside `KVM_RUN` without a userspace exit. Console stdin and host-socket
//! data therefore arrive on poller threads that raise the matching IRQ line
//! to kick the vCPU; the main loop delivers the data and re-evaluates the
//! lines after every exit.
//!
//! Synchronization: poller threads raise lines while holding
//! [`KvmHost::irq_lock`], and the main loop drains stdin / polls the net
//! backend / updates all lines in one critical section under the same lock.
//! That makes each thread's "inject data + raise line" pair atomic with
//! respect to the main loop's "drain + recompute lines", so a
//! concurrently-arriving event can never be lowered away.

use super::GuestRam;
use super::{
    host_tty_size, Args, Vmm, HOST_WINCH, MAX_FS_DEVICES, RAM_BASE, SPI_BLK, SPI_CONSOLE,
    SPI_DATA_BLK, SPI_FS_START, SPI_NET, SPI_RNG,
};
use crate::hypervisor::{KvmExit, Vm};
use crate::virtio::console::VirtioConsoleDevice;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::virtio::net::VirtioNetDevice;
use anyhow::{anyhow, Result};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Tracked SPI slots: SPI_NET through SPI_FS_START + MAX_FS_DEVICES - 1.
pub(super) const NUM_TRACKED_SPIS: usize = 32;

/// Linux backend host state: poller threads and SPI line bookkeeping.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // fields document/hold poller state across the run loop
pub(super) struct KvmHost {
    /// Serializes poller threads' IRQ-line raises against the main loop's
    /// line updates and stdin/net draining (see `Vmm::run_loop_kvm`).
    pub(super) irq_lock: Arc<Mutex<()>>,
    /// Write end of the pipe used to stop the stdin poller thread.
    pub(super) stdin_stop_w: RawFd,
    pub(super) stdin_thread: Option<JoinHandle<()>>,
    /// The eventfd that wakes the net kicker's epoll (its stop flag alone
    /// cannot return the 100 ms wait; see spawn_net_kicker).
    pub(super) stop_fd: libc::c_int,
    pub(super) net_thread: Option<JoinHandle<()>>,
    /// Last level issued for each tracked line (index: INTID - 32).
    /// Shared with the poller threads (see [`IrqLevels`]).
    pub(super) irq_levels: IrqLevels,
}

/// Shared tracked level for each IRQ line (index: INTID - 32 on arm64,
/// ISA-pool slot on x86_64). The main loop and the poller threads both
/// drive the same lines; this state must be shared, or a poller's direct
/// pulse desyncs the main loop's view and the next raise becomes an
/// edge-less no-op on the x86 edge-triggered PIC (a silently lost
/// interrupt).
pub(super) type IrqLevels = Arc<[AtomicBool; NUM_TRACKED_SPIS]>;

pub(super) fn new_irq_levels() -> IrqLevels {
    Arc::new(std::array::from_fn(|_| AtomicBool::new(false)))
}

/// Raise/lower a tracked line. `level == tracked` is a no-op for lower and
/// a re-pend for raise: on x86 the edge-triggered PIC needs a fresh
/// high-edge, so an already-high line that re-pends is pulsed
/// (high→low→high); on arm64 the VGIC re-delivers level lines by itself.
pub(super) fn irq_set_level(levels: &IrqLevels, idx: usize, vm: &Vm, line: u32, level: bool) {
    let tracked = levels[idx].load(Ordering::Relaxed);
    if level {
        if tracked {
            // Already high and the device re-pended: create a new edge on
            // x86 (the VGIC needs nothing).
            #[cfg(target_arch = "x86_64")]
            {
                let _ = vm.irq_line(line, false);
                let _ = vm.irq_line(line, true);
            }
        } else {
            let _ = vm.irq_line(line, true);
            levels[idx].store(true, Ordering::Relaxed);
        }
    } else if tracked {
        let _ = vm.irq_line(line, false);
        levels[idx].store(false, Ordering::Relaxed);
    }
}

/// Create a fresh interrupt edge on a line this thread just made pending
/// (data injected or a completion written). The line must be high
/// afterwards; the tracked state records that.
pub(super) fn irq_pulse(levels: &IrqLevels, idx: usize, vm: &Vm, line: u32) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = vm.irq_line(line, false);
        let _ = vm.irq_line(line, true);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = vm.irq_line(line, true);
    }
    levels[idx].store(true, Ordering::Relaxed);
}

impl Vmm {
    #[cfg(target_os = "linux")]
    pub(super) fn run_loop_kvm(&mut self, args: &Args) -> Result<i32> {
        loop {
            // Host terminal resized: re-apply the geometry to the guest
            // console and interrupt it (the virtio console driver feeds the
            // config change to hvc_resize, so the guest tty tracks the host
            // window live). The config path only ever lands when the guest
            // driver's config work runs — on its own schedule — so the
            // resize ALSO rides the port input stream as a record the
            // session agent strips and applies (see portagent.rs's
            // RESIZE_MAGIC): the input path is the one channel that is
            // demonstrably up, and the kernel SIGWINCHs the session when
            // the agent applies the record, so the session re-sizes itself
            // exactly like a real terminal would.
            // Host terminal geometry: the kernel's SIGWINCH, MEASURED
            // (instrumented handler, run in a real tmux pane AND in the
            // test harness after vm_harness.py's _claim_ctty setup):
            // the signal fires wherever the console pty is the VMM's
            // controlling terminal — tmux TIOCSCTTYs its panes (real
            // panes), and the harness setsid + TIOCSCTTYs its pty —
            // and NEVER elsewhere (a launch that inherits no ctty gets
            // no live resize; the boot geometry stands, and host_tty_size
            // falls back to 120x40 off-tty). set_size dedupes against
            // the device's own config: a repeat signal for the same size
            // produces no second record. No poll: a TIOCGWINSZ-per-
            // iteration poll was measured redundant wherever the ctty
            // holds and was removed — the harness now exercises the real
            // signal path instead.
            if HOST_WINCH.swap(false, Ordering::Relaxed) {
                let (cols, rows) = host_tty_size();
                let config_change = self.console.lock().unwrap().set_size(cols, rows);
                if config_change {
                    // The resize record: [u32 "RSZ1"][u16 cols][u16 rows],
                    // little-endian — the resize record's magic
                    // (0x315a5352 LE = the bytes "RSZ1"). Queued for the
                    // port input stream: delivered whole, ahead of the
                    // backlog (see set_resize_record — a split record
                    // leaks its magic into the input stream).
                    let mut record: [u8; 8] = [0; 8];
                    record[0..4].copy_from_slice(&0x315a_5352u32.to_le_bytes());
                    record[4..6].copy_from_slice(&(cols as u16).to_le_bytes());
                    record[6..8].copy_from_slice(&(rows as u16).to_le_bytes());
                    self.console
                        .lock()
                        .unwrap()
                        .set_resize_record(crate::virtio::console::PORT_RX, record);
                    // Deliver it RIGHT HERE, at the poll: a truly idle
                    // session never generates the input pushes or kicks the
                    // later drains ride on, and the resize must not depend
                    // on them (a host zoom while the session sits at a
                    // prompt would otherwise resize nothing, for as long as
                    // the session stays idle — which is exactly when a
                    // user zooms). The pulse below covers the delivery.
                    self.console
                        .lock()
                        .unwrap()
                        .drain_resize_record(
                            self.memory.as_shared_slice(),
                            RAM_BASE,
                            crate::virtio::console::PORT_RX,
                        );
                    let _guard = self.host.irq_lock.lock();
                    irq_pulse(
                        &self.host.irq_levels,
                        (crate::irqs::SPI_CONSOLE - crate::irqs::SPI_NET) as usize,
                        &self.vm,
                        self.irq_line_for_spi(crate::irqs::SPI_CONSOLE),
                    );
                }
            }

            match self.vcpu.run()? {
                // EINTR (e.g. SIGWINCH): just re-enter the guest.
                KvmExit::Unknown(code) if code == u32::MAX => continue,
                exit => {
                    static REPORTED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if std::env::var_os("SANDAL_DEBUG_TIMING").is_some()
                        && !REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Some(t0) = super::BOOT_T0.get() {
                            eprintln!("BOOT_TIMING first_vcpu_exit: {:?}", t0.elapsed());
                        }
                    }
                    self.handle_kvm_exit(exit)?
                }
            }

            // Drain every console stream → host stdout. Each stream goes
            // through its own SHARED filter (the same instances the
            // net-kick thread uses — two independent trackers per stream
            // would tear escape sequences apart at drain boundaries).
            let (pending, _) = drain_console_streams(
                &self.console,
                &self.memory,
                &self.console_tx_filter,
                &self.port_tx_filter,
            );
            // The shutdown/export protocol: whichever drain matched the
            // marker left it set in the shared filter — take it here (the
            // only place with a shutdown path).
            let (exit_code, export_path) = {
                let mut f = self.console_tx_filter.lock().unwrap();
                let mut g = self.port_tx_filter.lock().unwrap();
                (
                    f.exit_code.take().or(g.exit_code.take()),
                    f.export_path.take().or(g.export_path.take()),
                )
            };
            if let Some(code) = exit_code {
                self.guest_exit_code = Some(code);
                self.guest_shutdown = true;
            }
            if let Some(path) = export_path {
                self.export_save_path = Some(path);
            }
            if pending {
                // The control sequence was delivered or a filter answered a
                // terminal query: the reply went into an RX queue. Raise the
                // line under the lock (a fresh edge, not the line update).
                let _guard = self.host.irq_lock.lock();
                irq_pulse(
                    &self.host.irq_levels,
                    (crate::irqs::SPI_CONSOLE - crate::irqs::SPI_NET) as usize,
                    &self.vm,
                    self.irq_line_for_spi(crate::irqs::SPI_CONSOLE),
                );
            }

            // Drain host input and network data into the guest, then mirror
            // the device state onto the SPI lines. Under the irq_lock, per
            // the locking contract: poller threads inject + raise under the
            // same lock, so a raise can never be reordered after this
            // loop's lowering decision (a lost interrupt).
            {
                let irq_lock = self.host.irq_lock.clone();
                let _guard = irq_lock.lock();
                // Drain the stdin handoff queue and retry the device RX
                // backlog every iteration, not only when new input arrived:
                // (Console input is injected and pulsed by the stdin
                // poller's own thread; the net poll and the line mirror
                // are all that run here.)
                if let Some(net) = self.net.lock().unwrap().as_mut() {
                    net.poll_backend();
                    net.process_rx(self.memory.as_shared_slice(), RAM_BASE);
                }
                self.update_irq_lines();
            }

            // If the guest asked the VMM to shut down, exit the loop.
            if self.guest_shutdown {
                break;
            }
        }
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING run_loop_end: {:?} (exit_code={})",
                crate::vm::BOOT_T0.get().map(|t| t.elapsed()).unwrap_or_default(),
                self.guest_exit_code.unwrap_or(0)
            );
        }
        // Stop the helper threads BEFORE anything returns. MEASURED: the
        // stdin poller blocks in poll(stop_pipe, -1) and the net kicker
        // in epoll_wait(100 ms), and exit_group's SIGKILL took ~70 ms to
        // reap one of them — the process was reaped only after the
        // laggard, and that was the whole "teardown" cost past the last
        // userspace byte. The stop byte/flag is each thread's designed
        // exit; joining them here means exit_group has no one to kill.
        self.net_kick_stop.store(true, Ordering::Relaxed);
        let wake = 1u64.to_ne_bytes();
        let _ = unsafe {
            libc::write(self.host.stop_fd, wake.as_ptr().cast(), wake.len())
        };
        if let Some(h) = self.host.net_thread.take() {
            let _ = h.join();
        }
        let wake = [1u8];
        let _ = unsafe {
            libc::write(self.host.stdin_stop_w, wake.as_ptr().cast(), wake.len())
        };
        if let Some(h) = self.host.stdin_thread.take() {
            let _ = h.join();
        }
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING threads_stopped: {:?}",
                crate::vm::BOOT_T0.get().map(|t| t.elapsed()).unwrap_or_default()
            );
        }
        // The session-failure codes get a diagnostic (see
        // diagnose_session_exit): the guest produced no output — a silent
        // exit is indistinguishable from a hang. The code forwards
        // unchanged.
        let code = self.guest_exit_code.unwrap_or(0);
        crate::vm::diagnose_session_exit(code, &args.command);
        Ok(code)
    }

    /// KVM interrupt line for a device SPI:
    /// - arm64: the GIC INTID (32 + SPI), level-triggered in the VGIC.
    /// - x86_64: the legacy ISA GSI from the pool, edge-triggered in the PIC
    ///   (the slot index matches the `virtio_mmio.device=` cmdline order).
    pub(super) fn irq_line_for_spi(&self, spi: u32) -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            32 + spi
        }
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64::x86_irq_for_slot((spi - SPI_NET) as usize)
        }
    }

    #[cfg(target_os = "linux")]
    fn device_irq_level(&self, spi: u32) -> bool {
        match spi {
            SPI_CONSOLE => self.console.lock().unwrap().interrupt_status != 0,
            SPI_BLK => self.blk.as_ref().is_some_and(|d| d.interrupt_status != 0),
            SPI_DATA_BLK => self
                .data_blk
                .as_ref()
                .is_some_and(|d| d.interrupt_status != 0),
            SPI_RNG => self.rng.as_ref().is_some_and(|d| d.interrupt_status != 0),
            SPI_NET => self
                .net
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|d| d.interrupt_status != 0 || d.has_packets()),
            s if s >= SPI_FS_START && s < SPI_FS_START + MAX_FS_DEVICES as u32 => self
                .virtiofs
                .get((s - SPI_FS_START) as usize)
                .is_some_and(|d| d.interrupt_status != 0),
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn update_irq_lines(&mut self) {
        let last_spi = SPI_FS_START + MAX_FS_DEVICES as u32 - 1;
        for spi in SPI_NET..=last_spi {
            let level = self.device_irq_level(spi);
            let idx = (spi - SPI_NET) as usize;
            let line = self.irq_line_for_spi(spi);
            irq_set_level(&self.host.irq_levels, idx, &self.vm, line, level);
        }
    }
}

/// Net kick thread: event-driven net backend pump.
///
/// Blocks in `epoll(7)` on the netstack's host sockets (TCP streams, DNS,
/// wakeup pipe) instead of blindly polling, so an idle guest costs zero
/// CPU and incoming data is noticed within microseconds. On any event it
/// pumps the backend (delivering packets into the guest RX virtqueue) and
/// pulses the net IRQ line; the lock is held across "pump + raise" so a
/// concurrently-arriving packet can never be lowered away by the main
/// loop's line update.
///
/// fd lifecycle: the netstack's wakeup pipe fires whenever a connection is
/// established (and whenever data is stranded in the RX backlog), at which
/// point the watch set is re-synced. Closed sockets are removed from the
/// epoll set by the kernel automatically when their last fd reference is
/// dropped; stale registrations are also pruned on every sync. The thread
/// exits when `stop` is set (bounded by the 100 ms wait timeout).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn spawn_net_kicker(
    vm: Vm,
    net: Arc<Mutex<Option<VirtioNetDevice>>>,
    console: Arc<Mutex<VirtioConsoleDevice>>,
    memory: Arc<GuestRam>,
    filter: Arc<Mutex<super::ConsoleTxFilter>>,
    port_filter: Arc<Mutex<super::ConsoleTxFilter>>,
    irq_lock: Arc<Mutex<()>>,
    irq_levels: IrqLevels,
    stop: Arc<AtomicBool>,
    stop_fd: libc::c_int,
) -> JoinHandle<()> {
    #![allow(clippy::too_many_arguments)] // thread bootstrap; each arg is a distinct handle
    use std::collections::HashSet;

    std::thread::spawn(move || {
        let line = super::x86_64::x86_irq_for_slot(0); // net = ISA pool slot 0
        let console_line = console_irq_line();
        let console_idx = (SPI_CONSOLE - SPI_NET) as usize;

        let epfd = unsafe { libc::epoll_create1(0) };
        if epfd < 0 {
            return; // no net pump this boot; the run loop still polls per exit
        }
        let mut registered: HashSet<RawFd> = HashSet::new();
        // The shutdown wake: the stop flag alone cannot return the
        // epoll_wait below (only its 100 ms timeout or a signal could),
        // so the stop fd is part of the watch set — the shutdown writes
        // one byte and the loop top's flag check exits.
        unsafe {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: stop_fd as u64,
            };
            libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, stop_fd, &mut ev);
        }
        let mut wedged_empty_drains: u32 = 0;
        // Only start counting empty drains after the guest produced console
        // output once: the first TX proves the queue is live, so a subsequent
        // silence is meaningful (apk/curl phases are quiet for many seconds
        // without anything being wedged).
        let mut saw_tx = false;

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            // Pump: deliver anything pending, then sync + wait on the fds.
            {
                // Drain every console stream: a guest writer blocked on a
                // full TX virtqueue (full-screen apps like tmux) cannot
                // generate exits, so the main loop alone would never drain
                // it. Each stream goes through its own shared filter; the
                // control handshake is what keeps the console alive at all.
                let (console_irq_pending, progressed) =
                    drain_console_streams(&console, &memory, &filter, &port_filter);
                if !progressed {
                    // Console wedge detection: every stream looks idle but a
                    // guest console writer may be stuck (e.g. tmux's draw).
                    // Once output has been seen this boot, dump the vring
                    // state parsed straight from guest RAM (the only
                    // guest-side view available when the vCPU is wedged in
                    // the put_chars completion spin), plus any BAD_RING
                    // (`id is not a head`) prints left in the kernel log ring.
                    if saw_tx {
                        wedged_empty_drains += 1;
                    }
                    if wedged_empty_drains >= 50 && (wedged_empty_drains - 50).is_multiple_of(100) {
                        // Re-dump periodically: a later snapshot can catch
                        // drift (e.g. a broken queue after a phantom
                        // completion) that the first one missed.
                        console
                            .lock()
                            .unwrap()
                            .dump_vrings(memory.as_shared_slice(), RAM_BASE);
                        crate::vmm_trace::dump_guest_ram_lines(
                            memory.as_shared_slice(),
                            "is not a head",
                            "BAD_RING",
                            8,
                            120,
                        );
                    }
                } else {
                    saw_tx = true;
                    wedged_empty_drains = 0;
                }
                let _guard = irq_lock.lock();
                // The console completions (drained above) and any query
                // replies pended the console vring interrupt: raise the line
                // here. The main loop is blocked in KVM_RUN when the guest
                // is halted and would never learn of them otherwise — its
                // update_irq_lines only runs after an exit. Without this
                // pulse the guest's vring_interrupt handler (hvc_kick →
                // tty_wakeup) never runs and sleeping tty writers wedge
                // forever (the tmux attached-client hang).
                if console_irq_pending {
                    irq_pulse(&irq_levels, console_idx, &vm, console_line);
                }
                let mut guard = net.lock().unwrap();
                let delivered = match guard.as_mut() {
                    Some(net) => {
                        net.poll_backend();
                        let delivered = net.process_rx(memory.as_shared_slice(), RAM_BASE);
                        net.drain_wakeup();
                        delivered
                    }
                    None => false,
                };
                if delivered {
                    irq_pulse(&irq_levels, 0, &vm, line); // net = tracked idx 0
                }
                // Sync the epoll watch set with the netstack's current fds:
                // add new ones (per connection), drop entries for fds that
                // are gone. Done under the already-held guards — re-locking
                // the irq/net mutexes here would self-deadlock.
                let current: HashSet<RawFd> = guard
                    .as_ref()
                    .map(|n| n.watch_fds())
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                for fd in registered.difference(&current).copied().collect::<Vec<_>>() {
                    unsafe {
                        libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut());
                    }
                    registered.remove(&fd);
                }
                for fd in current {
                    if registered.insert(fd) {
                        let mut ev = libc::epoll_event {
                            events: libc::EPOLLIN as u32,
                            u64: fd as u64,
                        };
                        unsafe {
                            libc::epoll_ctl(
                                epfd,
                                libc::EPOLL_CTL_ADD,
                                fd,
                                &mut ev as *mut libc::epoll_event,
                            );
                        }
                    }
                }
            }

            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
            let n = unsafe {
                libc::epoll_wait(
                    epfd,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    100, // bounds stop-flag latency; also polls new-conn setup
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err != Some(libc::EINTR) {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            // Any readiness (data, wakeup, EOF) is handled by the pump at
            // the top of the next iteration.
        }

        unsafe { libc::close(epfd) };
    })
}


/// Drain every console stream and emit it (shared by the run loop and the
/// net-kick thread — the only two places the console device is pumped on
/// Linux). One filter instance per stream, shared between both callers:
/// two independent escape-sequence trackers would tear sequences apart at
/// drain boundaries and corrupt the protocol-marker state.
///
/// Streams, in pump order:
///   - the control handshake: the port-instantiation sequence, delivered
///     once — without it the guest driver instantiates NO console at all
///     (hvc0 exists only after CONSOLE_PORT), so this is what keeps every
///     console alive;
///   - the console port's stream (the guest init and kernel output):
///     markers + terminal-query answering, with the \n → \r\n translation
///     applied once, here (the host terminal runs with output processing
///     disabled);
///   - the host device port's stream (the interactive session): verbatim
///     (the guest pty already formed those bytes), with terminal-query
///     answering — the replies go back through the port's own RX queue so
///     the guest agent reads them as input;
///   - the control replies: completing the driver's posts (its control path
///     spins until the completion lands, exactly like the console TX); the
///     payload is the driver's own bookkeeping — logged, emitted nowhere.
///
/// Returns `(pending, progressed)`: `pending` means the caller must raise
/// the console interrupt line (the control sequence was delivered, or a
/// filter answered a terminal query into an RX queue); `progressed` means
/// some stream produced bytes (the net-kick thread's wedge detector
/// inverts it).
///
/// The shutdown/export protocol markers are matched by the shared filters
/// but NOT consumed here: the filter instances are shared with the run
/// loop, which is the only place with a shutdown path — whatever this
/// drain matches stays set in the filter until the run loop takes it.
#[cfg(target_os = "linux")]
fn drain_console_streams(
    console: &Arc<Mutex<VirtioConsoleDevice>>,
    memory: &Arc<GuestRam>,
    console_filter: &Arc<Mutex<super::ConsoleTxFilter>>,
    port_filter: &Arc<Mutex<super::ConsoleTxFilter>>,
) -> (bool, bool) {
    use std::io::Write;
    let mut pending = false;
    let mut progressed = false;

    // The console port's stream.
    let console_tx = console.lock().unwrap().process_tx(
        memory.as_shared_slice(),
        RAM_BASE,
        crate::virtio::console::CONSOLE_TX,
    );
    let console_completed = !console_tx.is_empty();
    if !console_tx.is_empty() {
        progressed = true;
        // The \n → \r\n translation, once, for this stream only.
        let tx = crate::virtio::onlcr(console_tx);
        let mut out = Vec::new();
        let replied = {
            let mut f = console_filter.lock().unwrap();
            f.feed(&tx, console, memory, RAM_BASE, &mut out);
            let replied = f.replied;
            f.replied = false;
            replied
        };
        if !out.is_empty() {
            let _ = std::io::stdout().write_all(&out);
            let _ = std::io::stdout().flush();
        }
        // A TX completion landed (a post was captured): the guest driver's
        // vq callback must reclaim it and wake the blocked writer, or the
        // next write parks until an unrelated timer exit — the ~80 ms
        // per post pacer.
        if replied || console_completed {
            pending = true;
        }
    }

    // The host device port's stream: verbatim.
    let port_tx = console.lock().unwrap().process_tx(
        memory.as_shared_slice(),
        RAM_BASE,
        crate::virtio::console::PORT_TX,
    );
    let port_completed = !port_tx.is_empty();
    if !port_tx.is_empty() {
        progressed = true;
        let mut out = Vec::new();
        let replied = {
            let mut f = port_filter.lock().unwrap();
            f.feed(&port_tx, console, memory, RAM_BASE, &mut out);
            let replied = f.replied;
            f.replied = false;
            replied
        };
        if !out.is_empty() {
            let _ = std::io::stdout().write_all(&out);
            let _ = std::io::stdout().flush();
        }
        // Same as the console stream: a landed completion must pulse, or
        // the port's bulk stream paces at the timer's period.
        if replied || port_completed {
            pending = true;
        }
    }

    // The control replies FIRST: complete the driver's pending post — its
    // control path spins until the completion lands, exactly like the
    // console TX. The payload is the driver's own bookkeeping — logged,
    // emitted nowhere.
    let control_tx = console.lock().unwrap().process_tx(
        memory.as_shared_slice(),
        RAM_BASE,
        crate::virtio::console::CONTROL_TX,
    );
    if !control_tx.is_empty() {
        progressed = true;
        crate::vmm_trace::write_console_io(format_args!(
            "CONTROL_TX bytes={} preview=\"{}\"",
            control_tx.len(),
            crate::vmm_trace::bytes_preview(&control_tx, 32)
        ));
    }

    // The control handshake LAST, in the same pump call: the driver reads
    // the control buffer at get_buf time, so message k must be written in
    // the very call that completes the driver's reply for message k-1 —
    // otherwise the buffer holds the LAST message by the time the driver
    // finally runs, and every earlier message is lost.
    let pumped = console
        .lock()
        .unwrap()
        .pump_control_sequence(memory.as_shared_slice(), RAM_BASE);
    // NOTE: pulse only on a NEW event (a delivery or a capture) — pulsing
    // on every call while the sequence is merely DELIVERED is an IRQ
    // storm: the kernel's storm detector disables the line ("nobody
    // cared"), the driver's work never runs again, and the port session
    // parks on an unprocessed host_connected bit forever.
    if pumped {
        pending = true;
        progressed = true;
    }

    (pending, progressed)
}

/// Console interrupt line (the same mapping the main loop uses).
#[cfg(target_os = "linux")]
fn console_irq_line() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        32 + SPI_CONSOLE
    }
    #[cfg(target_arch = "x86_64")]
    {
        super::x86_64::x86_irq_for_slot(1) // console = ISA pool slot 1
    }
}

/// Spawn the KVM stdin poller thread.
///
/// Blocks on poll(2) for host stdin (the interactive pty). On input, injects
/// the bytes directly into the guest console RX virtqueue and requests a
/// console interrupt pulse — the main thread blocks in KVM_RUN and cannot
/// drain a host-side buffer. Exits when a byte arrives on `stop_r` or
/// stdin reaches EOF.
#[cfg(target_os = "linux")]
pub(super) fn spawn_stdin_poller(
    console: Arc<Mutex<VirtioConsoleDevice>>,
    memory: Arc<GuestRam>,
    irq_levels: IrqLevels,
    vm: Vm,
) -> Result<(JoinHandle<()>, RawFd)> {
    let mut pipe_fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err(anyhow!(
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (stop_r, stop_w) = (pipe_fds[0], pipe_fds[1]);

    let handle = std::thread::spawn(move || {
        loop {
            let mut pfds = [
                libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop_r,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let n = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                continue;
            }
            if pfds[1].revents != 0 {
                break; // stop requested
            }

            let mut chunk = [0u8; 4096];
            let n = unsafe { libc::read(0, chunk.as_mut_ptr() as *mut _, chunk.len()) };
            if n > 0 {
                // Inject and raise right here, on this thread: deferring
                // the injection to the main loop paces input at the main
                // loop's own iteration rate — seconds per command. The
                // console lock is held only for the injection (the main
                // loop holds it only briefly for its TX drain), and the
                // pulse needs no lock: the main loop's line update mirrors
                // the device state, so a lock-free pulse is simply the
                // last write and can never be reordered behind a lowering
                // decision.
                let dropped = {
                    let mut console = console.lock().unwrap();
                    // The session target: the console RX queue until the
                    // guest init moves the session onto the host device
                    // port (the SESSION:port marker, parsed by the console
                    // TX filter) — then the port RX queue.
                    let rxq = if console.session_input_on_port {
                        crate::virtio::console::PORT_RX
                    } else {
                        crate::virtio::console::CONSOLE_RX
                    };
                    let (_, dropped) = console.push_rx_and_drain(
                        memory.as_shared_slice(),
                        RAM_BASE,
                        rxq,
                        &chunk[..n as usize],
                    );
                    dropped
                };
                if dropped > 0 {
                    crate::vm::console_eprintln(&format!(
                        "sandal: dropped {dropped} bytes of console input the guest \
                         refused for too long (a full tty or a busy guest): re-send it"
                    ));
                }
                let line = console_irq_line();
                let idx = (SPI_CONSOLE - SPI_NET) as usize;
                irq_pulse(&irq_levels, idx, &vm, line);
                continue;
            }
            if n == 0 {
                // EOF on stdin: no more input will ever arrive. Park until
                // shutdown so we do not spin on a permanently-readable fd.
                let mut pfd = [libc::pollfd {
                    fd: stop_r,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                loop {
                    let n = unsafe { libc::poll(pfd.as_mut_ptr(), 1, -1) };
                    if n > 0 {
                        break;
                    }
                    if n < 0
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        break;
                    }
                }
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        unsafe { libc::close(stop_r) };
    });

    Ok((handle, stop_w))
}
