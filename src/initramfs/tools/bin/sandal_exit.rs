//! The `sandal-exit` guest helper: the exit protocol.
//!
//! The init runs `sandal-exit <status>` once the session is reaped, and the
//! helper delivers the code: the x86_64 side stores
//! `EXIT_PORT | (code << 16)` to the VMM's hypercall page (a /dev/mem MMIO
//! write — userspace MMIO; nested KVM denies I/O-port privileges), the
//! aarch64 side raises the EXIT BRK with the code in x15. The VMM matches
//! the low half (or the BRK immediate) and reads the code from the high
//! half (x15). No console marker, no string matching, nothing user output
//! can ever act as.
//!
//! usage: sandal-exit <code>    (a missing or non-numeric argument is 0)

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
    capture_env(rsp);

    // code = atol(argv[1]): digits only, everything else stops the parse.
    let mut code: u64 = 0;
    let argc = unsafe { (rsp as *const usize).read() };
    if argc >= 2 {
        let arg = unsafe { *((rsp + 2 * core::mem::size_of::<usize>()) as *const usize) };
        if arg != 0 {
            let mut i = 0usize;
            loop {
                let b = unsafe { (arg as *const u8).add(i).read() };
                match b {
                    b'0'..=b'9' => code = code.wrapping_mul(10).wrapping_add((b - b'0') as u64),
                    _ => break,
                }
                i += 1;
            }
        }
    }

    exit_vm(code as u8);
    exit(0)
}
