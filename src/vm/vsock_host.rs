//! The virtio-vsock host machinery — every platform's session transport.
//!
//! The device itself is [`crate::virtio::vsock::VirtioVsockDevice`]; this is
//! only the host half: the listener (accept → register, the REQUEST
//! synthesized as a control packet), the bridge (the host sockets ↔ the
//! device's channels, and ONE process pass + IRQ pulse per round under the
//! irq lock — the same locking contract as the net kicker), and the wake
//! channel (the device writes it on guest-visible progress; unix: a pipe
//! the bridge's poll watches, Windows: none — the bridge's slice covers it).
//!
//! Platform parking:
//!   - unix (Linux KVM, macOS HVF): one `poll` over the live fds on a
//!     20 ms slice, the wake pipe always armed. Linux additionally pulses
//!     the IRQ line from the bridge (KVM_IRQ_LINE from a thread is fine);
//!     macOS raises nothing from here — the run loop mirrors the device's
//!     interrupt_status onto the GIC at the next exit.
//!   - Windows (WHP): no poll — a 20 ms sleep slice; the sockets are
//!     nonblocking std, every round attempts the I/O regardless. The IRQ:
//!     the run loop's per-exit edge model.

use super::GuestRam;
use super::RAM_BASE;
#[cfg(target_os = "linux")]
use crate::hypervisor::Vm;
use crate::irqs::{SPI_NET, SPI_VSOCK};
#[cfg(not(unix))]
use crate::virtio::vsock::HostStream;
use crate::virtio::vsock::VirtioVsockDevice;
use anyhow::Result;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The tracked IRQ level for the vsock line (the Linux KVM line mirror).
#[cfg(target_os = "linux")]
pub(super) type IrqLevels = Arc<[AtomicBool; super::NUM_TRACKED_SPIS]>;

#[cfg(target_os = "linux")]
pub(super) fn new_irq_levels() -> IrqLevels {
    Arc::new(std::array::from_fn(|_| AtomicBool::new(false)))
}

pub(super) struct VsockHost {
    pub(super) device: Arc<Mutex<VirtioVsockDevice>>,
    /// Set at shutdown so both threads exit; the accepter is woken by
    /// shutting its listener down (below), the bridge by the wake pipe
    /// (unix) or its slice (windows).
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    /// The listener (woken at shutdown); None without --port (the TCP
    /// proxy exists only when the operator named it).
    listener: Option<std::net::TcpListener>,
    /// The bridge's wake pipe's write end (unix only; the device writes
    /// it on progress, shutdown writes it once to end the parked poll).
    #[cfg(unix)]
    wake_w: std::os::fd::RawFd,
}

impl VsockHost {
    /// The bridge core: the device + the exchange loop, ALWAYS (the
    /// command execution line's own front end registers its stream
    /// here); the TCP accepter only when the operator named --port.
    /// One core, two front ends — the exchange loop is stream-agnostic.
    pub(super) fn spawn(
        memory: Arc<GuestRam>,
        #[cfg(target_os = "linux")] vm: Vm,
        #[cfg(target_os = "linux")] irq_lock: Arc<Mutex<()>>,
        #[cfg(target_os = "linux")] irq_levels: IrqLevels,
        listener: Option<std::net::TcpListener>,
        session: Option<super::session::SessionStream>,
    ) -> Result<Self> {
        let device = Arc::new(Mutex::new(VirtioVsockDevice::new()));
        let stop = Arc::new(AtomicBool::new(false));
        // The bridge's IRQ line (Linux only pulses from a thread): the
        // x86_64 ISA-pool GSI / the arm64 GIC INTID — both fixed for the
        // vsock SPI.
        #[cfg(target_os = "linux")]
        let irq_line = super::linux::vsock_irq_line();

        // The wake pipe (unix): the device writes it on progress; the
        // bridge's poll watches the read end. Windows: no wake channel —
        // the slice covers the latency.
        #[cfg(unix)]
        let (wake_r, wake_w): (std::os::fd::RawFd, std::os::fd::RawFd) = {
            let mut fds = [0 as libc::c_int; 2];
            anyhow::ensure!(
                unsafe { libc::pipe(fds.as_mut_ptr()) } == 0,
                "vsock: pipe: {}",
                std::io::Error::last_os_error()
            );
            // Both ends nonblocking: the device's progress write must
            // never block (a full 64 KiB pipe is 512 pending wakes), and
            // the poll side must not stall shutdown.
            for fd in fds {
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
            }
            device.lock().unwrap().set_wake_fd(fds[1]);
            (fds[0], fds[1])
        };

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
        // The shutdown wakes the accepter by dropping its listener; keep
        // a duplicated handle for that (the accepter moves the original).
        let shutdown_listener = match &listener {
            Some(l) => Some(l.try_clone()?),
            None => None,
        };
        if let Some(listener) = listener {
            // The listener stays BLOCKING: the dedicated accepter's
            // blocking accept() returns the pending connection the
            // moment it lands (MEASURED: see the accepter's note).
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
                    move || {
                        vsock_bridge(
                            memory,
                            #[cfg(target_os = "linux")]
                            (vm, irq_line),
                            #[cfg(target_os = "linux")]
                            irq_lock,
                            #[cfg(target_os = "linux")]
                            irq_levels,
                            device,
                            stop,
                            #[cfg(unix)]
                            wake_r,
                        )
                    }
                })?,
        );
        Ok(Self {
            device,
            stop,
            threads,
            listener: shutdown_listener,
            #[cfg(unix)]
            wake_w,
        })
    }

    pub(super) fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the accepter: its blocking accept() only returns when a
        // connection pends or the listener is shut down. The accepter owns
        // the ORIGINAL listener fd — dropping this duplicated handle closes
        // nothing (the socket stays open, the accept stays parked, and the
        // join below hangs the whole teardown — MEASURED: every --port run
        // froze at exit with the vCPU already stopped). The duplicate shares
        // the socket's file description, so shutdown(Both) on it IS the
        // listener's shutdown: the blocked accept() returns and the stop
        // check ends the accepter.
        if let Some(listener) = self.listener.take() {
            #[cfg(unix)]
            unsafe {
                let _ = libc::shutdown(listener.as_raw_fd(), libc::SHUT_RDWR);
            }
            #[cfg(not(unix))]
            let _ = listener;
            drop(listener);
        }
        // Wake the bridge (unix): its parked poll returns now, the round
        // top's stop check ends the loop — the join below waits
        // microseconds, not a slice.
        #[cfg(unix)]
        {
            let one = 1u64.to_ne_bytes();
            unsafe {
                let _ = libc::write(self.wake_w, one.as_ptr().cast(), one.len());
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

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
/// Exits when the listener is dropped (see shutdown) and the stop
/// flag is set.
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
                // The listener's drop makes a blocked accept return;
                // anything else retries.
                log::warn!("vsock: accepter: {error}");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// The vsock bridge thread: the host sockets polled — readable (the
/// command), writable (the command's output), EOF (the agent closed:
/// RST the guest) — then ONE exchange + ONE device process pass (+ ONE
/// pulse on Linux) under the irq lock (the locking contract: the main
/// loop updates the lines under the same lock, so a pulse can never be
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
/// posted set).
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
#[allow(clippy::too_many_arguments)]
fn vsock_bridge(
    memory: Arc<GuestRam>,
    #[cfg(target_os = "linux")] (vm, irq_line): (Vm, u32),
    #[cfg(target_os = "linux")] irq_lock: Arc<Mutex<()>>,
    #[cfg(target_os = "linux")] irq_levels: IrqLevels,
    device: Arc<Mutex<VirtioVsockDevice>>,
    stop: Arc<AtomicBool>,
    #[cfg(unix)] wake_r: std::os::fd::RawFd,
) {
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
        #[cfg(unix)]
        let parked = {
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
            // The wake pipe: the device writes it when guest-visible
            // progress lands on the run loop's thread (the outbox filling
            // is the one that matters — the host sockets cannot see it).
            // Always armed; drained once per round (the read resets it)
            // so a write between the drain and the poll wakes the poll,
            // and a write DURING the poll ends it now.
            let wake_slot = fds.len();
            fds.push(libc::pollfd {
                fd: wake_r,
                events: libc::POLLIN,
                revents: 0,
            });
            let _ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
            if std::env::var_os("SANDAL_VSOCK_DEBUG").is_some() {
                let mut sum = String::new();
                for fd in fds.iter() {
                    sum.push_str(&format!(" {:x}/{:x}", fd.fd, fd.revents));
                }
                crate::virtio::vsock::debug_print(format_args!(
                    "BRIDGE-POLL:{} ready={}",
                    sum, _ready
                ));
            }
            // Drain the wake pipe (one read resets it; a zero read means
            // the poll timed out on the slice).
            if fds[wake_slot].revents & libc::POLLIN != 0 {
                let mut buf = [0u8; 64];
                unsafe {
                    let _ = libc::read(wake_r, buf.as_mut_ptr().cast(), buf.len());
                }
            }
            parked
        };
        #[cfg(not(unix))]
        let parked: Vec<(u32, Box<dyn HostStream>, Vec<u8>, i32)> = work
            .into_iter()
            .map(|(port, host, outbox)| (port, host, outbox, -1))
            .collect();
        #[cfg(not(unix))]
        {
            // The Windows park: a plain slice. The sockets are
            // nonblocking std; the round attempts the I/O regardless of
            // any readiness hint (there is none), and the wake channel
            // does not exist — the slice bounds the delivery latency.
            std::thread::sleep(std::time::Duration::from_millis(20));
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
        // (c) Exchange + ONE process pass (+ ONE pulse on Linux), under
        // the irq lock (the locking contract: the main loop's line
        // update runs under the same lock, so the pulse can never be
        // reordered after it and lowered away). One pass — never a loop:
        // the pass is bounded by the posted set and the credit windows,
        // and whatever it leaves pending waits for the next event (see
        // the function note).
        #[cfg(target_os = "linux")]
        {
            let _guard = irq_lock.lock();
            let mut guard = device.lock().unwrap();
            guard.bridge_exchange(returned, read, closed, delivered);
            let progressed = guard.process(memory.as_shared_slice(), RAM_BASE);
            drop(guard);
            if progressed {
                let idx = (SPI_VSOCK - SPI_NET) as usize;
                super::linux::irq_pulse(&irq_levels, idx, &vm, irq_line);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No IRQ lock here: the pulse discipline is Linux's (the
            // device's own mutex already serializes this exchange).
            let mut guard = device.lock().unwrap();
            guard.bridge_exchange(returned, read, closed, delivered);
            guard.process(memory.as_shared_slice(), RAM_BASE);
            drop(guard);
            // No pulse: the run loop mirrors the device's
            // interrupt_status onto the interrupt controller at the
            // next exit (the macOS GIC's level model / the Windows
            // PIC's edge model).
        }
    }
}
