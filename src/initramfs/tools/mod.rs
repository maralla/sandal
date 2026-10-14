//! Crafted guest helper ELFs: one module per guest arch, one file per
//! tool. Each helper is pure machine code built with the per-arch DSL
//! ([`crate::elf`]) — no toolchain, no sibling binaries — and injected
//! into the rootfs at boot by [`crate::ext2::inject_runtime_files`].
//!
//! The export helpers are a cross-arch feature (overlay export) with
//! arch-specific delivery — BRK immediates on arm64, a `/dev/mem` MMIO
//! write on x86_64 — so they are re-exported here and the injection call
//! sites stay arch-uniform, exactly as the pre-split same-named
//! arch-cfg'd functions were.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::export::{export_done_helper, export_resize_helper};
#[cfg(target_arch = "aarch64")]
pub use aarch64::export::{export_done_helper, export_resize_helper};

/// Dump the crafted helpers for disassembly/inspection
/// (SANDAL_DUMP_HELPERS=1 cargo test). The export helpers take the
/// hypercall page base; the dump only checks that they build.
#[cfg(all(test, target_arch = "x86_64"))]
mod helper_tests {
    #[test]
    fn dump_helpers() {
        if std::env::var_os("SANDAL_DUMP_HELPERS").is_some() {
            let page = 0x4000_0000u64; // the dump helper only checks that it builds
            std::fs::write("/tmp/helper-done", super::export_done_helper(page)).unwrap();
            std::fs::write("/tmp/helper-resize", super::export_resize_helper(page)).unwrap();
            std::fs::write(
                "/tmp/helper-ctty",
                super::x86_64::ctty::ctty_helper(),
            )
            .unwrap();
            #[cfg(sandal_portagent_helper)]
            std::fs::write(
                "/tmp/helper-portagent",
                super::x86_64::portagent::portagent_helper(),
            )
            .unwrap();
        }
    }
}
