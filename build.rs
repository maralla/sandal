fn main() {
    #[cfg(target_os = "macos")]
    {
        // Link against Hypervisor framework on macOS
        println!("cargo:rustc-link-lib=framework=Hypervisor");
        println!("cargo:rerun-if-changed=src/hypervisor/hvf/ffi.c");

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
