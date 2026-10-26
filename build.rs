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

    // ── The guest helper binaries ────────────────────────────────────
    // Pure Rust (no_std, raw syscalls) compiled with rustc for the
    // {arch}-unknown-none target: self-contained static ELFs with no
    // libc, no toolchain, no sibling binaries — the target ships with
    // the toolchain (`rustup target add x86_64-unknown-none` /
    // `aarch64-unknown-none`). Every platform compiles its own arch's
    // set; the injection sites (ext2.rs inject_runtime_files) pick.
    //
    //   vsockd         — the command execution line (every platform)
    //   sandal-exit    — the exit protocol helper (x86_64)
    //   export resize/done — the overlay export signals (every platform)
    //   init           — the guest /init (every platform: one compiled
    //                    binary, both architectures)
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target = match arch.as_str() {
        "x86_64" => "x86_64-unknown-none",
        "aarch64" => "aarch64-unknown-none",
        other => panic!("build.rs: no guest target for host arch {other}"),
    };
    let mut guests: Vec<(&str, bool)> = vec![
        ("vsockd", true),
        ("export_resize", true),
        ("export_done", true),
        ("export", true),
        ("sandal_exit", arch == "x86_64"),
        ("init", true),
    ];
    guests.retain(|(_, build)| *build);
    println!("cargo::rerun-if-changed=src/initramfs/tools/bin/common.rs");
    println!("cargo::rerun-if-env-changed=SANDAL_GUEST_DEBUG");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    // The guest-side debug builds: SANDAL_GUEST_DEBUG=1 keeps the DWARF
    // (the debug sections dwarf the code — the shipping binaries are a
    // few KB stripped). The shipping binaries: stripped.
    let debug = std::env::var_os("SANDAL_GUEST_DEBUG").is_some();
    for (name, _) in &guests {
        let out = std::env::var("OUT_DIR").unwrap();
        let bin = format!("{out}/{name}.bin");
        println!("cargo::rerun-if-changed=src/initramfs/tools/bin/{name}.rs");
        let mut args = vec![
            "--edition".to_string(),
            "2021".to_string(),
            "--target".to_string(),
            target.to_string(),
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
        args.push(format!("src/initramfs/tools/bin/{name}.rs"));
        let status = std::process::Command::new(&rustc)
            .args(&args)
            .status()
            .expect("rustc: the guest helper binaries need it");
        assert!(
            status.success(),
            "rustc: {name}.rs failed to compile (rustup target add {target})"
        );
    }

    // Windows links against the WHP backend (whp.dll) by name from the
    // Rust side (see src/hypervisor/whp) — no build-script glue needed.
}
