//! Windows-host run loop (`WHP` backend) and the host-side device threads.
//!
//! The loop mirrors `run_loop_kvm`: run the vCPU, handle exits, give the
//! vsock device its per-exit process pass, pump the network backend, and
//! raise device IRQ lines through the userspace PIC. The vCPU idle model
//! differs: WHP has no in-kernel halt-and-wake, so on `HLT` the loop parks
//! on a condvar until a device thread signals an event (the PIT tick, the
//! bridge's progress).

use super::{Args, Vmm, RAM_BASE};
use crate::hypervisor::KvmExit;
use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The guest timer (PIT channel 0) period, microseconds. The guest programs
/// the real PIT; the emulated tick runs at a fixed 250 Hz — enough for the
/// kernel's scheduler (the wall clock comes from the TSC).
const PIT_TICK_US: u64 = 4000;

impl Vmm {
    pub(super) fn run_loop_whp(&mut self, args: &Args) -> Result<i32> {
        let mut last_pump = Instant::now();

        loop {
            match self.vcpu.run()? {
                KvmExit::Hlt => {
                    // Park until a device event (timer tick, net arrival,
                    // net arrival) — re-entering immediately would spin.
                    self.halt.wait_timeout(50);
                }
                exit => self.handle_kvm_exit(exit)?,
            }

            // ── The vsock device: ONE process pass per exit ────────────
            // The guest's kicks land here, the same iteration the exit was
            // handled in. One pass, never a loop: whatever it cannot
            // deliver (a closed credit window, an exhausted RX ring)
            // waits for the next event (the bridge's slice, the next
            // exit) — a loop here would wedge the vCPU on the first
            // stalled pass (the bridge holds the same device mutex).
            if let Some(vsock) = self.vsock.as_ref() {
                vsock
                    .device
                    .lock()
                    .unwrap()
                    .process(self.memory.as_shared_slice(), RAM_BASE);
            }

            // ── Device IRQ lines → the userspace PIC ───────────────────
            // Edge model: assert on each 0→1 transition of a device's
            // interrupt status (the guest ACK clears it).
            if let Some(vsock) = self.vsock.as_ref() {
                if vsock.device.lock().unwrap().interrupt_status != 0 {
                    self.raise_vsock_irq();
                }
            }
            if let Some(blk) = self.blk.as_ref() {
                if blk.interrupt_status != 0 {
                    self.raise_blk_irq();
                }
            }
            if let Some(data) = self.data_blk.as_ref() {
                if data.interrupt_status != 0 {
                    self.raise_data_blk_irq();
                }
            }
            if let Some(rng) = self.rng.as_ref() {
                if rng.interrupt_status != 0 {
                    self.raise_rng_irq();
                }
            }
            #[cfg(not(target_os = "windows"))]
            for dev in self.virtiofs.iter() {
                if dev.interrupt_status != 0 {
                    self.raise_fs_irq();
                }
            }

            // ── Network pump (also driven by the timer thread) ─────────
            #[cfg(not(target_os = "windows"))]
            if self.net.lock().unwrap().is_some() {
                self.pump_net();
            }

            if self.guest_shutdown {
                eprintln!("sandal: guest requested shutdown\r");
                break;
            }
            let _ = last_pump.elapsed(); // (the pump cadence follows exits)
            last_pump = Instant::now();
        }
        eprintln!(
            "sandal: run loop ended, guest exit code {:?}\r",
            self.guest_exit_code
        );
        // The session-failure codes get a diagnostic (see
        // diagnose_session_exit): the guest produced no output — a silent
        // exit is indistinguishable from a hang. The code forwards
        // unchanged.
        let code = self.guest_exit_code.unwrap_or(0);
        crate::vm::diagnose_session_exit(code, &args.command);
        Ok(code)
    }

    /// Poll the user-space net backend and deliver pending packets to the
    /// guest RX queue (raising the net IRQ line when anything arrived).
    #[cfg(not(target_os = "windows"))]
    fn pump_net(&mut self) {
        let delivered = {
            let mut net = self.net.lock().unwrap();
            match net.as_mut() {
                Some(net) => {
                    net.poll_backend();
                    let delivered = net.process_rx(self.memory.as_shared_slice(), RAM_BASE);
                    net.drain_wakeup();
                    delivered
                }
                None => false,
            }
        };
        if delivered {
            self.raise_net_irq();
        }
    }

    // ── IRQ line helpers (the ISA IRQ numbers from the cmdline order) ──────

    fn raise_net_irq(&self) {
        let _ = self.vm.raise_irq(3);
        self.halt.notify();
    }

    pub(super) fn raise_vsock_irq(&self) {
        // ISA_IRQ_POOL[10] — the vsock slot (the cmdline's virtio_mmio
        // order; see x86_64.rs).
        let _ = self.vm.raise_irq(15);
        self.halt.notify();
    }

    fn raise_blk_irq(&self) {
        let _ = self.vm.raise_irq(6);
    }

    fn raise_data_blk_irq(&self) {
        let _ = self.vm.raise_irq(7);
    }

    fn raise_rng_irq(&self) {
        let _ = self.vm.raise_irq(9);
    }

    fn raise_fs_irq(&self) {
        // A single --share is supported per IRQ slot in this backend; every
        // mounted share raises the first virtiofs line.
        let _ = self.vm.raise_irq(10);
        self.halt.notify();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device threads
// ─────────────────────────────────────────────────────────────────────────────

pub(super) struct DeviceThreads {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl DeviceThreads {
    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.join();
        }
    }
}

/// Spawn the host-side device threads: the PIT tick (the guest timer + the
/// net pump).
pub(super) fn spawn_device_threads(vmm: &mut Vmm) -> DeviceThreads {
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // ── The PIT tick + the net pump ────────────────────────────────────────
    {
        let stop = stop.clone();
        let pic = vmm.pic_handle();
        let halt = vmm.halt_waker();
        #[cfg(not(target_os = "windows"))]
        let net = vmm.net.clone();

        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_micros(PIT_TICK_US));
                pic.lock().unwrap().tick();
                #[cfg(not(target_os = "windows"))]
                {
                    let mut net = net.lock().unwrap();
                    if let Some(net) = net.as_mut() {
                        net.poll_backend();
                        let delivered = net.process_rx(memory.as_shared_slice(), RAM_BASE);
                        net.drain_wakeup();
                        if delivered {
                            pic.lock().unwrap().raise(3); // the net IRQ line
                            halt.notify();
                        }
                    }
                }
                halt.notify();
            }
        }));
    }

    // The session input rides the vsock line (the guest's vsockd
    // bridges it to the session's pty).

    DeviceThreads { stop, handles }
}
