//! Guest `/init` binary generation, per host architecture.
//!
//! The guest architecture matches the host (KVM and HVF are same-arch), so
//! the binary is selected at compile time:
//!
//! - [`aarch64`] — AArch64 (macOS Apple Silicon, Linux arm64): the whole ELF is
//!   const-evaluated at compile time.
//! - [`x86_64`] — x86_64 (Linux x86_64): variable-length encodings make const
//!   evaluation impractical, so the binary is built once at first use.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

/// Return the guest `/init` ELF binary for the given TTY device.
pub fn init_binary(tty_device: &str) -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::init_binary(tty_device)
    }
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::init_binary(tty_device)
    }
}
