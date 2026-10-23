//! The `sandal-export-done` guest helper: tells the VMM the export data is
//! ready (the x86_64 side stores the DONE signal word to the hypercall
//! page, the aarch64 side raises the DONE BRK immediate; the VMM then
//! extracts the overlay upper directory into a .layer file). See
//! `sandal-export` (the script that drives it).

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
    signal_done();
    exit(0)
}
