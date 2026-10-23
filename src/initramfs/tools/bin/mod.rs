//! The standalone guest binaries (pure Rust, no_std, raw syscalls,
//! arch-agnostic — the per-arch syscall layer lives in `common`).
//! Compiled by `build.rs` with `rustc --target {arch}-unknown-none`
//! and injected into the rootfs by `crate::ext2::inject_runtime_files`.

/// The compiled `vsockd` guest binary (see [`vsockd`] for the source).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub static VSOCKD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vsockd.bin"));

/// The compiled `vsockd` guest binary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn vsockd_helper() -> &'static [u8] {
    VSOCKD
}
