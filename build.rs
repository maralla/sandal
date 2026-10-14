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

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        panic!("This project supports macOS (Hypervisor.framework) and Linux (KVM)");
    }
}

