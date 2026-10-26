//! The `sandal-export-resize` guest helper: asks the VMM to grow /dev/vdb
//! (tmpfs-upper mode) — the x86_64 side stores the RESIZE signal word to
//! the hypercall page (a /dev/mem MMIO write), the aarch64 side raises the
//! RESIZE BRK immediate. See `sandal-export` (the Rust binary that drives it).

#![no_std]
#![no_main]

mod common;

use common::*;

#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! {
    exit(126)
}

#[no_mangle]
pub extern "C" fn guest_entry(rsp: usize) -> ! {
    // The hypercall page's address rides the HYPERCALL env (the x86_64
    // MMIO window moves with --memory; there is no correct static
    // fallback). The session env carries it; capture it first.
    capture_env(rsp);
    signal_resize();
    exit(0)
}
