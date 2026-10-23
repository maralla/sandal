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
    Args, Vmm, MAX_FS_DEVICES, RAM_BASE, SPI_BLK, SPI_DATA_BLK, SPI_FS_START, SPI_NET, SPI_RNG,
    SPI_VSOCK,
};
use crate::hypervisor::{KvmExit, Vm};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::virtio::net::VirtioNetDevice;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::virtio::vsock::VirtioVsockDevice;
use anyhow::Result;
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

/// The userspace virtio-vsock host machinery (Linux/x86_64 only): the
/// device plus its two threads — the listener (accept → register, the
/// REQUEST synthesized as a control packet) and the bridge (the host
/// sockets ↔ the device's channels, and ONE process pass + IRQ pulse
/// per round under the irq lock, the same locking contract as the net
/// kicker). The device itself is virtio/vsock.rs; this is only the
/// host half.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct VsockHost {
    pub(super) device: Arc<Mutex<VirtioVsockDevice>>,
    /// Set at shutdown so both threads exit; the accepter is woken by
    /// shutting its listener down (below), the bridge by the wake fd
    /// (the bridge parks in poll on it — see spawn).
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    /// The listener's fd (woken at shutdown); None without --port (the
    /// TCP proxy exists only when the operator named it).
    listener_fd: Option<RawFd>,
    /// The bridge's wake eventfd (the device writes it on progress;
    /// shutdown writes it once to end the parked poll immediately).
    wake_fd: RawFd,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl VsockHost {
    /// The bridge core: the device + the exchange loop, ALWAYS (the
    /// command execution line's own front end registers its stream
    /// here); the TCP accepter only when the operator named --port.
    /// One core, two front ends — the exchange loop is stream-agnostic.
    pub(super) fn spawn(
        memory: Arc<GuestRam>,
        vm: Vm,
        irq_lock: Arc<Mutex<()>>,
        irq_levels: IrqLevels,
        listener: Option<std::net::TcpListener>,
        session: Option<super::session::SessionStream>,
    ) -> Result<Self> {
        let device = Arc::new(Mutex::new(VirtioVsockDevice::new()));
        // The bridge's wake eventfd: the device writes it on progress,
        // the bridge's poll (below) watches it, and shutdown writes it
        // once to end the parked poll without waiting out a slice.
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        anyhow::ensure!(
            wake_fd >= 0,
            "vsock: eventfd: {}",
            std::io::Error::last_os_error()
        );
        device.lock().unwrap().set_wake_fd(wake_fd);
        let stop = Arc::new(AtomicBool::new(false));
        // Front end 1: the session handler — the command execution
        // line's own host side (the host stdio as a stream). Registered
        // BEFORE the bridge starts: the bridge's first round takes it.
        if let Some(session) = session {
            device
                .lock()
                .unwrap()
                .register_connection(Box::new(session));
        }
        let mut threads = Vec::new();
        let mut listener_fd = None;
        if let Some(listener) = listener {
            // The listener stays BLOCKING: the dedicated accepter's
            // blocking accept() returns the pending connection the
            // moment it lands (MEASURED: see the accepter's note).
            listener_fd = {
                use std::os::fd::AsRawFd;
                Some(listener.as_raw_fd())
            };
            threads.push(
                std::thread::Builder::new()
                    .name("vsock-accepter".into())
                    .spawn({
                        let device = Arc::clone(&device);
                        let stop = Arc::clone(&stop);
                        move || vsock_accepter(listener, device, stop)
                    })?,
            );
        }
        // The bridge: the live streams only — the I/O and ONE device
        // process pass per round (the front ends register the streams).
        threads.push(
            std::thread::Builder::new()
                .name("vsock-bridge".into())
                .spawn({
                    let device = Arc::clone(&device);
                    let stop = Arc::clone(&stop);
                    move || vsock_bridge(memory, vm, irq_lock, irq_levels, device, stop, wake_fd)
                })?,
        );
        Ok(Self {
            device,
            stop,
            threads,
            listener_fd,
            wake_fd,
        })
    }

    pub(super) fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the accepter: its blocking accept() only returns when a
        // connection pends or the listener is shut down; the shutdown
        // makes it return an error, and the stop flag ends the loop.
        if let Some(fd) = self.listener_fd {
            unsafe {
                let _ = libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
        // Wake the bridge: its parked poll returns now, the round top's
        // stop check ends the loop — the join below waits microseconds,
        // not a slice.
        {
            let one = 1u64.to_ne_bytes();
            unsafe {
                let _ = libc::write(self.wake_fd, one.as_ptr().cast(), one.len());
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for VsockHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The vsock accepter thread: a BLOCKING accept per connection. The
/// kernel wakes the accepter the moment a connection lands — the
/// immediate dequeue the bridge's poll-slice accept loop could not
/// deliver on a cold start (MEASURED: the part-2 probe completed the
/// RST round trip with the unmodified kernel once the dequeue landed).
/// Exits when the listener is shut down (see shutdown) and the stop
/// flag is set.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn vsock_accepter(
    listener: std::net::TcpListener,
    device: Arc<Mutex<VirtioVsockDevice>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(true);
                device.lock().unwrap().register_connection(Box::new(stream));
            }
            Err(error) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                // The shutdown() of the listener makes a blocked
                // accept return; anything else retries.
                log::warn!("vsock: accepter: {error}");
            }
        }
    }
}

/// The vsock bridge thread: the host sockets polled — readable (the
/// command), writable (the command's output), EOF (the agent closed:
/// RST the guest) — then ONE exchange + ONE device process pass + ONE
/// pulse under the irq lock (the locking contract: the main loop
/// updates the lines under the same lock, so a pulse can never be
/// reordered after it and lowered away).
///
/// ONE process pass per round, never a loop. The pass is the whole
/// point: whatever it cannot deliver (a closed credit window, an
/// exhausted RX ring, a full host socket) stays pending for the next
/// EVENT, and the events are real — the kernel waking this poll (the
/// client sent more, or drained enough for the socket to take more
/// output), the guest's own next vCPU exit (the run loop's per-exit
/// pass: the completion-driven rate of the transport's credit chain),
/// or the slice itself. The earlier inner loop (process + pulse until
/// a pass made no progress) instead WEDGED the VM on the first real
/// workload: a stalled pass made every iteration a no-op, the loop held
/// this irq lock, the run loop blocked on it, and the vCPU never ran
/// again — so the re-post/credit event the loop was spinning for never
/// happened (MEASURED: reproduced at will with a stream larger than one
/// posted set; the loop is gone).
///
/// The slice is a fixed 20 ms park: the next event is the kernel's or
/// the guest's own; an idle bridge costs 50 wakeups a second. The
/// poll's events are real — POLLIN always, POLLOUT only for a socket
/// whose outbox failed to drain last round (a nonblocking host
/// socket's EAGAIN; the session front end's stdout is blocking and
/// never arms it) — the kernel wakes the round when it can take more
/// output or when input lands. The timeout is never zero and the
/// events never include an unconditional POLLOUT: the session front
/// end's fd is the host stdin, whose POLLOUT is always ready, so the
/// earlier POLLIN|POLLOUT shape returned from every poll instantly —
/// the 20 ms slice never slept and the bridge spun a core at 100%
/// for the whole VM lifetime (MEASURED), feeding whatever the device
/// did with the extra process passes.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(clippy::too_many_arguments)]
fn vsock_bridge(
    memory: Arc<GuestRam>,
    vm: Vm,
    irq_lock: Arc<Mutex<()>>,
    irq_levels: IrqLevels,
    device: Arc<Mutex<VirtioVsockDevice>>,
    stop: Arc<AtomicBool>,
    wake_fd: RawFd,
) {
    use std::io::{Read, Write};
    let idx = (SPI_VSOCK - SPI_NET) as usize;
    let line = super::x86_64::x86_irq_for_slot(idx);
    // The front ends whose stdin read side hit EOF (eof_is_hangup ==
    // false): their POLLIN arm drops for the rest of the connection.
    let mut read_eof: std::collections::HashSet<u32> = std::collections::HashSet::new();
    while !stop.load(Ordering::Relaxed) {
        // (a) Take the parked sockets and outboxes out of the device.
        let work = device.lock().unwrap().take_bridge_work();
        // (b) The park: one poll over every live socket, on a 20 ms
        // slice (the accepter owns the listener; see vsock_accepter).
        // POLLIN always; POLLOUT only where last round's outbox did
        // not drain. After the poll, the read/write attempts run
        // unconditionally anyway (the revents are the wake hint; a
        // missed revents costs one round of latency, never a stall).
        // The events are PER DIRECTION: POLLIN on the stream's read
        // fd; POLLOUT on its WRITE fd (only while the outbox holds
        // undelivered bytes). The session front end reads stdin and
        // writes stdout — different fds, and polling the read fd for
        // POLLOUT woke the round forever (a pty is always writable)
        // while the pane pty stayed full: the outbox round-tripped
        // undelivered and each round re-wrote the prefix that had
        // landed — the flashing pane (MEASURED).
        let mut fds = Vec::with_capacity(work.len() * 2);
        let mut parked = Vec::with_capacity(work.len());
        for (port, host, outbox) in work {
            let fd = host.as_raw_fd();
            let wfd = host.write_fd().filter(|w| *w != fd);
            let out_pending = !outbox.is_empty();
            // A consumed EOF (see eof_is_hangup) stops the POLLIN arm:
            // the read side is done, and an EOF-ready device (/dev/null,
            // a closed terminal) would spin the park forever.
            let mut events = if read_eof.contains(&port) {
                0
            } else {
                libc::POLLIN
            };
            if out_pending && wfd.is_none() {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            });
            if out_pending {
                if let Some(w) = wfd {
                    fds.push(libc::pollfd {
                        fd: w,
                        events: libc::POLLOUT,
                        revents: 0,
                    });
                }
            }
            parked.push((port, host, outbox, fd));
        }
        // The wake eventfd: the device writes it when guest-visible
        // progress lands on the run loop's thread (the outbox filling
        // is the one that matters — the host sockets cannot see it).
        // Always armed; drained once per round (the counter read resets
        // it) so a write between the drain and the poll wakes the poll,
        // and a write DURING the poll ends it now.
        let wake_slot = fds.len();
        fds.push(libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        let _ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as u64, 20) };
        if std::env::var_os("SANDAL_VSOCK_DEBUG").is_some() {
            let mut sum = String::new();
            for fd in fds.iter() {
                sum.push_str(&format!(" {:x}/{:x}", fd.fd, fd.revents));
            }
            crate::virtio::vsock::debug_print(format_args!("BRIDGE-POLL:{} ready={}", sum, _ready));
        }
        // Drain the wake counter (one read resets it; a zero read means
        // the poll timed out on the slice).
        if fds[wake_slot].revents & libc::POLLIN != 0 {
            let mut counter = 0u64;
            unsafe {
                let _ = libc::read(
                    wake_fd,
                    (&mut counter as *mut u64).cast(),
                    std::mem::size_of::<u64>(),
                );
            }
            if std::env::var_os("SANDAL_VSOCK_DEBUG").is_some() {
                crate::virtio::vsock::debug_print(format_args!(
                    "WAKE-DRAIN: counter was {}",
                    counter
                ));
            }
        }
        let mut read: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut closed: Vec<u32> = Vec::new();
        let mut delivered: Vec<(u32, usize)> = Vec::new();
        let mut returned = Vec::with_capacity(parked.len());
        // Every live socket: the outbox out (the command's output),
        // the socket's bytes in (the command) — nonblocking, every
        // round, regardless of what the poll reported.
        for (port, mut host, mut outbox, _) in parked.into_iter() {
            let mut port_delivered = 0usize;
            while !outbox.is_empty() {
                match host.write(&outbox) {
                    Ok(0) => {
                        // Nothing accepted and no error: leave the
                        // outbox intact — it round-trips back into the
                        // device and arms next round's POLLOUT.
                        break;
                    }
                    Ok(n) => {
                        port_delivered += n;
                        outbox.drain(..n);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(_) => {
                        // The socket is gone: the rest of the outbox
                        // is undeliverable; the closed side is marked
                        // below.
                        outbox.clear();
                        break;
                    }
                }
            }
            let mut buffer = [0u8; 64 * 1024];
            loop {
                match host.read(&mut buffer) {
                    // EOF: a hangup (the agent closed) RSTs the guest's
                    // socket; a session stdin's end just stops the read
                    // side (the command's output must keep flowing —
                    // see eof_is_hangup).
                    Ok(0) => {
                        if host.eof_is_hangup() {
                            closed.push(port);
                        } else {
                            read_eof.insert(port);
                        }
                        break;
                    }
                    Ok(n) => read.push((port, buffer[..n].to_vec())),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(_) => {
                        closed.push(port);
                        break;
                    }
                }
            }
            // Report the round's DELIVERED bytes only. The report is
            // what re-arms the guest's send window (the credit update
            // carries the new consumption counter), and bytes still in
            // flight — in this hand or back in the device's outbox —
            // are exactly what the window must stay closed over: the
            // guest's has_space counts them as unsent-to-the-peer, and
            // reporting them consumed would let it overrun the real
            // sink. The earlier full-take report (delivered + the
            // leftover, with the leftover returned to the outbox and
            // re-taken next round) counted the same bytes twice and
            // inflated the credit out of thin air; a real delivery
            // stall now shows up as a closed window — the protocol's
            // own backpressure — instead of a lie.
            if port_delivered > 0 {
                delivered.push((port, port_delivered));
            }
            returned.push((port, host, outbox));
        }
        // (c) Exchange + ONE process pass + ONE pulse, under the irq
        // lock (the locking contract: the main loop's line update runs
        // under the same lock, so the pulse can never be reordered
        // after it and lowered away). One pass — never a loop: the
        // pass is bounded by the posted set and the credit windows,
        // and whatever it leaves pending waits for the next event (see
        // the function note). The pulse: the KVM_IRQ_LINE edge — the
        // same contract as the console and net devices (the tracked
        // levels + the run loop's line mirror). MEASURED: the
        // KVM_IRQFD injection this once also used is dead weight — its
        // assign fails ENOTTY on every host this project runs on
        // (WSL2's KVM), every boot warned, and the KVM_IRQ_LINE pulse
        // carried the whole measured suite (all four: the per-command
        // channel, the relay, the ssh channel, the ssh layer) at full
        // speed. Removed, not silenced: a per-boot warning for a
        // permanent host condition is noise, and the fallback was never
        // a fallback — it was the only mechanism that ever ran.
        {
            let _guard = irq_lock.lock();
            let mut guard = device.lock().unwrap();
            guard.bridge_exchange(returned, read, closed, delivered);
            let progressed = guard.process(memory.as_shared_slice(), RAM_BASE);
            drop(guard);
            if progressed {
                irq_pulse(&irq_levels, idx, &vm, line);
            }
        }
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
                        // note: the KVM_IRQFD path is gone).
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
