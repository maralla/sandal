//! The standalone guest binaries (pure Rust, no_std, raw syscalls,
//! arch-agnostic — the per-arch syscall layer lives in `common`).
//! Compiled by `build.rs` with `rustc --target {arch}-unknown-none`
//! and injected into the rootfs by `crate::ext2::inject_runtime_files`.
//!
//! Which binaries a build carries (see build.rs): `vsockd` and the export
//! signal helpers on every platform, `sandal-exit` on x86_64 (the init
//! script's exit-protocol tail), and `init` on aarch64 (the x86_64 init is
//! the shell script).

/// The compiled `vsockd` guest binary (the command execution line).
pub static VSOCKD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vsockd.bin"));

/// The compiled `vsockd` guest binary.
pub fn vsockd_helper() -> &'static [u8] {
    VSOCKD
}

/// The compiled `sandal-export-resize` guest binary (the overlay export's
/// grow-/dev/vdb signal).
pub static EXPORT_RESIZE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/export_resize.bin"));

/// The compiled `sandal-export-resize` guest binary.
pub fn export_resize_helper() -> &'static [u8] {
    EXPORT_RESIZE
}

/// The compiled `sandal-export-done` guest binary (the export's
/// data-is-ready signal).
pub static EXPORT_DONE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/export_done.bin"));

/// The compiled `sandal-export-done` guest binary.
pub fn export_done_helper() -> &'static [u8] {
    EXPORT_DONE
}

/// The compiled `sandal-exit` guest binary (the exit protocol: the
/// /dev/mem store of `EXIT_PORT | (code << 16)`). x86_64 only — the
/// aarch64 init's session exit rides the EXIT BRK from vsockd itself.
#[cfg(target_arch = "x86_64")]
pub static SANDAL_EXIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sandal_exit.bin"));

/// The compiled `sandal-exit` guest binary.
#[cfg(target_arch = "x86_64")]
pub fn sandal_exit_helper() -> &'static [u8] {
    SANDAL_EXIT
}

/// The compiled aarch64 `/init` guest binary (the Rust port of the
/// machine-code init; the x86_64 init is the shell script).
#[cfg(target_arch = "aarch64")]
pub static INIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init.bin"));

/// The compiled aarch64 `/init` guest binary.
#[cfg(target_arch = "aarch64")]
pub fn init_helper() -> &'static [u8] {
    INIT
}
