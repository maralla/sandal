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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::GuestRam;
use super::{
    Args, Vmm, MAX_FS_DEVICES, RAM_BASE, SPI_BLK, SPI_DATA_BLK, SPI_FS_START, SPI_NET, SPI_RNG,
    SPI_VSOCK,
};
use crate::hypervisor::{KvmExit, Vm};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::virtio::net::VirtioNetDevice;
use anyhow::Result;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::io::RawFd;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Linux backend host state: poller threads and SPI line bookkeeping.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // fields document/hold poller state across the run loop
pub(super) struct KvmHost {
    /// Serializes poller threads' IRQ-line raises against the main loop's
    /// line updates and stdin/net draining (see `Vmm::run_loop_kvm`).
    pub(super) irq_lock: Arc<Mutex<()>>,
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
pub(super) use super::vsock_host::{new_irq_levels, IrqLevels};

/// The vsock SPI's IRQ line: the x86_64 ISA-pool GSI / the arm64 GIC
/// INTID. Fixed for the SPI — the bridge thread pulses it directly.
pub(super) fn vsock_irq_line() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        super::x86_64::x86_irq_for_slot((SPI_VSOCK - SPI_NET) as usize)
    }
    #[cfg(target_arch = "aarch64")]
    {
        32 + SPI_VSOCK
    }
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
                // The vsock device: ONE process pass per exit — the
                // guest's kicks land here, the same iteration the exit
                // was handled in — and one pulse on progress. MEASURED:
                // with this site removed the transport cannot work at
                // all; with the pass in a loop instead, the VM wedges
                // on the first real workload (a closed credit window,
                // an exhausted RX ring): the loop holds this irq lock,
                // the bridge blocks on it, and the vCPU never runs
                // again — the re-post/credit event the loop waits for
                // never happens. One pass: the next event (this exit,
                // the bridge's slice, the kernel waking the bridge's
                // poll) advances whatever the pass left pending — and
                // the nested lock the loop used to take here was a
                // plain deadlock whenever the eventfd was unavailable.
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                if let Some(vsock) = self.vsock.as_ref() {
                    let progressed = vsock
                        .device
                        .lock()
                        .unwrap()
                        .process(self.memory.as_shared_slice(), RAM_BASE);
                    if progressed {
                        // The KVM_IRQ_LINE pulse — the same contract as
                        // the console/net line updates (see the bridge's
                        // note).
                        irq_pulse(
                            &self.host.irq_levels,
                            (SPI_VSOCK - SPI_NET) as usize,
                            &self.vm,
                            self.irq_line_for_spi(SPI_VSOCK),
                        );
                    }
                }
                self.update_irq_lines();
            }

            // If the guest asked the VMM to shut down, exit the loop.
            if self.guest_shutdown {
                break;
            }
        }
        if std::env::var_os("SANDAL_DEBUG_RESIDENCY").is_some() {
            self.memory.dump_residency();
        }
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING run_loop_end: {:?} (exit_code={})",
                crate::vm::BOOT_T0
                    .get()
                    .map(|t| t.elapsed())
                    .unwrap_or_default(),
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
        let _ = unsafe { libc::write(self.host.stop_fd, wake.as_ptr().cast(), wake.len()) };
        if let Some(h) = self.host.net_thread.take() {
            let _ = h.join();
        }
        // The vsock listener/bridge (each polls its stop flag on a short
        // slice; the join waits out at most one slice).
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if let Some(vsock) = self.vsock.as_mut() {
            vsock.shutdown();
        }
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING threads_stopped: {:?}",
                crate::vm::BOOT_T0
                    .get()
                    .map(|t| t.elapsed())
                    .unwrap_or_default()
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
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            SPI_VSOCK => self
                .vsock
                .as_ref()
                .is_some_and(|vsock| vsock.device.lock().unwrap().interrupt_status != 0),
            _ => false,
        }
    }

    #[cfg(target_os = "linux")]
    fn update_irq_lines(&mut self) {
        // Through the vsock device (Linux/x86_64); on the other builds
        // the arm is absent and the level reads false, like every other
        // absent device.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let last_spi = SPI_VSOCK;
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
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
    memory: Arc<GuestRam>,
    irq_lock: Arc<Mutex<()>>,
    irq_levels: IrqLevels,
    stop: Arc<AtomicBool>,
    stop_fd: libc::c_int,
) -> JoinHandle<()> {
    #![allow(clippy::too_many_arguments)] // thread bootstrap; each arg is a distinct handle
    use std::collections::HashSet;

    std::thread::spawn(move || {
        let line = super::x86_64::x86_irq_for_slot(0); // net = ISA pool slot 0

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
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            // Pump: deliver anything pending, then sync + wait on the fds.
            {
                let _guard = irq_lock.lock();
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
