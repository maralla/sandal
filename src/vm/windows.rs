//! Windows-host run loop (`WHP` backend) and the host-side device threads.
//!
//! The loop mirrors `run_loop_kvm`: run the vCPU, handle exits, drain the
//! guest console TX, pump the network backend, and raise device IRQ lines
//! through the userspace PIC. The vCPU idle model differs: WHP has no
//! in-kernel halt-and-wake, so on `HLT` the loop parks on a condvar until a
//! device thread signals an event (the PIT tick, console input, net arrival).

use super::{Args, Vmm, RAM_BASE};
use crate::hypervisor::KvmExit;
use anyhow::Result;
use std::ffi::c_void;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The guest timer (PIT channel 0) period, microseconds. The guest programs
/// the real PIT; the emulated tick runs at a fixed 250 Hz — enough for the
/// kernel's scheduler (the wall clock comes from the TSC).
const PIT_TICK_US: u64 = 4000;

impl Vmm {
    pub(super) fn run_loop_whp(&mut self, _args: &Args) -> Result<i32> {
        let mut last_pump = Instant::now();

        loop {
            match self.vcpu.run()? {
                KvmExit::Hlt => {
                    // Park until a device event (timer tick, console input,
                    // net arrival) — re-entering immediately would spin.
                    self.halt.wait_timeout(50);
                }
                exit => self.handle_kvm_exit(exit)?,
            }

            // ── Guest console TX → host stdout ─────────────────────────
            let tx = self
                .console
                .lock()
                .unwrap()
                .process_tx(self.memory.as_shared_slice(), RAM_BASE);
            if !tx.is_empty() {
                let mut out = Vec::new();
                let (replied, exit_code, export_path) = {
                    let mut f = self.console_tx_filter.lock().unwrap();
                    f.feed(&tx, &self.console, &self.memory, RAM_BASE, &mut out);
                    let replied = f.replied;
                    f.replied = false;
                    (replied, f.exit_code.take(), f.export_path.take())
                };
                if !out.is_empty() {
                    let _ = std::io::stdout().write_all(&out);
                    let _ = std::io::stdout().flush();
                }
                if let Some(code) = exit_code {
                    self.guest_exit_code = Some(code);
                    self.guest_shutdown = true;
                }
                if let Some(path) = export_path {
                    self.export_save_path = Some(path);
                }
                if replied {
                    // The filter answered a terminal query: the reply is in
                    // the console RX — raise the console IRQ line.
                    self.raise_console_irq();
                }
            }

            // ── Device IRQ lines → the userspace PIC ───────────────────
            // Edge model: assert on each 0→1 transition of a device's
            // interrupt status (the guest ACK clears it).
            if self.console.lock().unwrap().interrupt_status != 0 {
                self.raise_console_irq();
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
        Ok(self.guest_exit_code.unwrap_or(0))
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

    pub(super) fn raise_console_irq(&self) {
        let _ = self.vm.raise_irq(5);
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
/// net pump) and the console input reader.
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
        let memory = vmm.memory.clone();

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

    // ── The console input reader ───────────────────────────────────────────
    {
        let stop = stop.clone();
        let pic = vmm.pic_handle();
        let halt = vmm.halt_waker();
        let console = vmm.console.clone();
        let memory = vmm.memory.clone();

        handles.push(std::thread::spawn(move || {
            let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            let mut chunk = [0u8; 256];
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let mut read: u32 = 0;
                let ok = unsafe {
                    ReadFile(
                        handle,
                        chunk.as_mut_ptr(),
                        chunk.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    // No input available (the console without buffered input
                    // blocks in ReadFile; a closed handle spins — pace it).
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                if read > 0 {
                    console.lock().unwrap().push_rx_and_drain(
                        memory.as_shared_slice(),
                        RAM_BASE,
                        &chunk[..read as usize],
                    );
                    pic.lock().unwrap().raise(5); // the console IRQ line
                    halt.notify();
                }
            }
        }));
    }

    DeviceThreads { stop, handles }
}

// ── Windows console/input FFI (kernel32, auto-linked) ──────────────────────

const STD_INPUT_HANDLE: u32 = 0xFFFF_FFD6;

unsafe extern "system" {
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn ReadFile(
        handle: *mut c_void,
        buffer: *mut u8,
        to_read: u32,
        read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
