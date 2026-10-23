fn main() {
    // Release builds (SANDAL_EMBED_KERNEL=1) embed the guest kernel so the
    // binary is a single self-contained artifact; dev builds keep loading
    // it from disk next to the binary. The cfg is always *declared* so
    // both paths compile warning-free; only the env var enables it.
    println!("cargo::rustc-check-cfg=cfg(sandal_embed_kernel)");
    println!("cargo::rerun-if-env-changed=SANDAL_EMBED_KERNEL");
    if std::env::var_os("SANDAL_EMBED_KERNEL").is_some() {
        println!("cargo::rustc-cfg=sandal_embed_kernel");
    }

    #[cfg(target_os = "macos")]
    {
        // Link against Hypervisor framework on macOS
        println!("cargo::rustc-link-lib=framework=Hypervisor");
        println!("cargo::rerun-if-changed=src/hypervisor/hvf/ffi.c");

        // Build the Hypervisor FFI bindings
        cc::Build::new()
            .file("src/hypervisor/hvf/ffi.c")
            .compile("hvffi");
    }

    #[cfg(target_os = "linux")]
    {
        // The KVM backend talks to /dev/kvm directly via ioctls — no C glue
        // or extra libraries needed.
    }

    // ── The guest command execution line ─────────────────────────────
    // vsockd is pure Rust (no_std, raw syscalls) compiled with rustc
    // for x86_64-unknown-none: a self-contained static ELF with no
    // libc, no toolchain, no sibling binary — the target ships with
    // the toolchain (`rustup target add x86_64-unknown-none`).
    // x86_64 only: the injection site (ext2.rs inject_runtime_files)
    // is x86_64-gated.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        let out = std::env::var("OUT_DIR").unwrap();
        let bin = format!("{out}/vsockd.bin");
        println!("cargo::rerun-if-changed=src/initramfs/tools/bin/vsockd.rs");
        println!("cargo::rerun-if-env-changed=SANDAL_GUEST_DEBUG");
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        // The guest-side debug builds: SANDAL_GUEST_DEBUG=1 keeps the DWARF
        // (the debug sections were 764 KB of the first 798 KB build — the
        // code itself is 7 KB). The shipping binary: stripped.
        let debug = std::env::var_os("SANDAL_GUEST_DEBUG").is_some();
        let mut args = vec![
            "--edition".to_string(),
            "2021".to_string(),
            "--target".to_string(),
            "x86_64-unknown-none".to_string(),
            "-C".to_string(),
            "panic=abort".to_string(),
            "-C".to_string(),
            "opt-level=z".to_string(),
            "-C".to_string(),
            "codegen-units=1".to_string(),
            "-C".to_string(),
            "relocation-model=static".to_string(),
        ];
        args.push("-C".to_string());
        args.push(
            if debug {
                "debuginfo=2"
            } else {
                "strip=symbols"
            }
            .to_string(),
        );
        args.push("-o".to_string());
        args.push(bin.clone());
        args.push("src/initramfs/tools/bin/vsockd.rs".to_string());
        let status = std::process::Command::new(&rustc)
            .args(&args)
            .status()
            .expect("rustc: the guest command execution line needs it");
        assert!(
            status.success(),
            "rustc: vsockd_guest.rs failed to compile (rustup target add x86_64-unknown-none)"
        );
    }

    // Windows links against the WHP backend (whp.dll) by name from the
    // Rust side (see src/hypervisor/whp) — no build-script glue needed.
}
