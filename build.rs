fn main() {
    #[cfg(target_os = "macos")]
    {
        // Link against Hypervisor framework on macOS
        println!("cargo:rustc-link-lib=framework=Hypervisor");
        println!("cargo:rerun-if-changed=src/hypervisor/ffi.c");
        
        // Build the Hypervisor FFI bindings
        cc::Build::new()
            .file("src/hypervisor/ffi.c")
            .compile("hvffi");
    }
    
    #[cfg(not(target_os = "macos"))]
    {
        panic!("This project only supports macOS");
    }
}
