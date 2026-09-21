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
    Args, Vmm, MAX_FS_DEVICES, RAM_BASE, SPI_BLK, SPI_CONSOLE, SPI_DATA_BLK, SPI_FS_START, SPI_NET,
    SPI_RNG,
};
use crate::hypervisor::{KvmExit, Vm};
use crate::virtio::console::VirtioConsoleDevice;
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
    /// Last level issued for each tracked SPI (index: INTID - 32).
    pub(super) irq_levels: [bool; NUM_TRACKED_SPIS],
}

/// Tracked SPI INTIDs: SPI_NET (INTID 48) through
impl Vmm {
    #[cfg(target_os = "linux")]
    pub(super) fn run_loop_kvm(&mut self, _args: &Args) -> Result<i32> {
        loop {
            match self.vcpu.run()? {
                // EINTR (e.g. SIGWINCH): just re-enter the guest.
                KvmExit::Unknown(code) if code == u32::MAX => continue,
                exit => self.handle_kvm_exit(exit)?,
            }

            // Drain guest console TX → host stdout (intercepting protocol
            // markers).
            let tx = self
                .console
                .lock()
                .unwrap()
                .process_tx(self.memory.as_shared_slice(), RAM_BASE);
            if !tx.is_empty() {
                self.process_console_tx(&tx);
            }

            // Drain host input and network data into the guest, then mirror
            // the device state onto the SPI lines.
            {
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
        Ok(self.guest_exit_code.unwrap_or(0))
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
            if self.host.irq_levels[idx] != level {
                if self.vm.irq_line(line, level).is_ok() {
                    self.host.irq_levels[idx] = level;
                }
            } else if level {
                // The line is already high and the device re-pended. The
                // VGIC (arm64) re-delivers level lines automatically, but the
                // x86 PIC latches edges — pulse the line to create one.
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = self.vm.irq_line(line, false);
                    let _ = self.vm.irq_line(line, true);
                }
            }
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
#[cfg(target_os = "linux")]
pub(super) fn spawn_net_kicker(
    vm: Vm,
    net: Arc<Mutex<Option<VirtioNetDevice>>>,
    memory: Arc<GuestRam>,
    irq_lock: Arc<Mutex<()>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    use std::collections::HashSet;

    std::thread::spawn(move || {
        let line = super::x86_64::x86_irq_for_slot(0); // net = ISA pool slot 0
        let pulse = |line: u32| {
            let _ = vm.irq_line(line, true);
            // The PIC latches edges: pulse high->low->high.
            let _ = vm.irq_line(line, false);
            let _ = vm.irq_line(line, true);
        };

        let epfd = unsafe { libc::epoll_create1(0) };
        if epfd < 0 {
            return; // no net pump this boot; the run loop still polls per exit
        }
        let mut registered: HashSet<RawFd> = HashSet::new();

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
                    pulse(line);
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
/// the bytes directly into the guest console RX virtqueue and pulses the
/// console interrupt line — the main thread blocks in KVM_RUN and cannot
/// drain a host-side buffer. The irq_lock is held across "inject + raise" so
/// the raise can never be reordered after the main loop's lowering decision
/// (see [`Vmm::run_loop_kvm`]). Exits when a byte arrives on `stop_r` or
/// stdin reaches EOF.
#[cfg(target_os = "linux")]
pub(super) fn spawn_stdin_poller(
    vm: Vm,
    console: Arc<Mutex<VirtioConsoleDevice>>,
    memory: Arc<GuestRam>,
    irq_lock: Arc<Mutex<()>>,
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
                // Inject directly into the console RX virtqueue: the main
                // thread blocks in KVM_RUN and cannot drain a buffer.
                {
                    let _guard = irq_lock.lock();
                    console.lock().unwrap().push_rx_and_drain(
                        memory.as_shared_slice(),
                        RAM_BASE,
                        &chunk[..n as usize],
                    );
                    // Wake the vCPU on the console's interrupt line. The
                    // x86_64 PIC latches edges, so pulse high→low→high; on
                    // arm64 the VGIC re-delivers the level line.
                    let line = console_irq_line();
                    let _ = vm.irq_line(line, true);
                    #[cfg(target_arch = "x86_64")]
                    {
                        let _ = vm.irq_line(line, false);
                        let _ = vm.irq_line(line, true);
                    }
                }
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
