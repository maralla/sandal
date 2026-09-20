//! x86_64 guest `/init`: a busybox shell script.
//!
//! The guest rootfs ships busybox (applet symlinks included), so a POSIX
//! script is simpler and far more maintainable than generated machine code.
//! The script lives in `init/x86_64.sh` next to this module and is embedded
//! at compile time with `include_str!`. The VMM injects the run configuration
//! as `/etc/sandal.conf` (key=value lines, see
//! [`crate::initramfs::build_init_config_text`]).
//!
//! Flow (mirrors the ARM64 init in [`super::aarch64`]):
//!   1. mount proc/sys/tmpfs (devtmpfs is moved across pivot_root)
//!   2. parse the config (disk mode, network, clock, shares, argv)
//!   3. set the wall clock; bring up the network (static 10.0.2.15 NAT)
//!   4. build the overlayfs root (tmpfs or /dev/vdb upper) and pivot_root
//!   5. mount virtiofs shares
//!   6. run the command in its own session on the console, print the
//!      `SANDAL_EXIT:<code>` marker, power off.

/// The guest init script (injected as `/init`, mode 0755).
const SCRIPT: &str = include_str!("x86_64.sh");

/// Return the x86_64 guest `/init` script for the given TTY device
/// (the console device is fixed for this guest; the argument matches the
/// ARM64 signature and is ignored).
pub fn init_binary(_tty_device: &str) -> &'static [u8] {
    SCRIPT.as_bytes()
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_script_has_shebang_and_marker() {
        let s = super::init_binary("/dev/hvc0");
        assert!(s.starts_with(b"#!/bin/sh\n"));
        let s = std::str::from_utf8(s).unwrap();
        // The exit protocol uses the per-boot token from the config — the
        // script must not contain a fixed marker string that workload
        // output could echo back.
        assert!(s.contains("EXIT_TOKEN"));
        assert!(!s.contains("SANDAL_EXIT:"));
        assert!(s.contains("pivot_root"));
        assert!(s.contains("/etc/sandal.conf"));
    }
}
