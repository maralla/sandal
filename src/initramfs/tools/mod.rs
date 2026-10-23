//! The guest-side helper programs: one module per concern. The compiled
//! no_std Rust binaries live in [`bin`] (built by build.rs, injected by
//! `crate::ext2::inject_runtime_files`); the shell scripts embed here.

pub mod bin;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
