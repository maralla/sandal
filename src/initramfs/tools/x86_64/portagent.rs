//! The crafted `portagent` x86_64 guest helper loader: the session agent
//! (a pty bridged to the virtio-console host device port — see
//! `portagent.c`).
//!
//! Unlike the DSL helpers (ctty, export), this one is freestanding **C**:
//! the bridge's control flow — a poll/read/write pump, a geometry
//! propagator, a reaper — is far past what hand-rolled machine code
//! should carry. build.rs compiles it into a static ELF (raw x86_64
//! Linux syscalls, no libc) and emits the `sandal_portagent_helper` cfg
//! when the build succeeded — only on x86_64 Linux hosts (the guest arch
//! matches the host; other hosts cannot run this guest). Without the
//! cfg the helper is not injected and the init script falls back to the
//! plain console session (ctty).

#[cfg(sandal_portagent_helper)]
pub fn portagent_helper() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/portagent.bin"))
}
