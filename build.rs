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

    // The guest session agent (src/initramfs/tools/x86_64/portagent.c):
    // freestanding C — raw x86_64 Linux syscalls, no libc — compiled and
    // linked into a static ELF here. The cfg is always *declared* so
    // every host compiles warning-free; only a successful build enables
    // it (see the portagent.rs loader and the ext2 injection).
    println!("cargo::rustc-check-cfg=cfg(sandal_portagent_helper)");
    build_portagent();

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

/// Build the guest session agent: `portagent.c` → `OUT_DIR/portagent.bin`.
///
/// A freestanding static ELF: the C carries its own syscall stubs and
/// constants, so nothing but the compiler itself is needed — no libc, no
/// startup files (the C defines `_start`). Only x86_64 Linux hosts build
/// it (the guest arch matches the host; the helper is useless anywhere
/// else), and only a successful build emits the cfg — otherwise the build
/// fails loudly (this is the supported configuration).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn build_portagent() {
    use std::process::Command;

    const SRC: &str = "src/initramfs/tools/x86_64/portagent.c";
    println!("cargo::rerun-if-changed={SRC}");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let obj = format!("{out_dir}/portagent.o");
    let bin = format!("{out_dir}/portagent.bin");

    // The compiler the `cc` crate would use (it resolves CC/host defaults
    // the same way); native here — the guest arch matches this host.
    let cc = std::env::var("CC")
        .ok()
        .filter(|cc| !cc.is_empty())
        .unwrap_or_else(|| "cc".to_string());

    // Compile: freestanding, no builtins (no libc calls to synthesize),
    // no stack protector (no __stack_chk_fail to link), no PIE codegen
    // (the link below is a fixed-address ET_EXEC).
    let compiled = Command::new(&cc)
        .args([
            "-c", SRC, "-o", &obj, "-O2", "-ffreestanding", "-fno-builtin",
            "-fno-stack-protector", "-fno-pie",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let linked = compiled
        && Command::new(&cc)
            // Link: no libc, no startup files (the C defines _start), a
            // static non-PIE ELF — the same class of artifact the ELF-DSL
            // helpers produce, runnable on any x86_64 Linux rootfs.
            .args([
                &obj, "-o", &bin, "-nostdlib", "-static", "-no-pie",
                "-Wl,-e,_start",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if linked {
        println!("cargo::rustc-cfg=sandal_portagent_helper");
    } else {
        panic!("building the guest session agent ({SRC}) failed: install a C compiler (cc), or fix the compile above");
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn build_portagent() {}
