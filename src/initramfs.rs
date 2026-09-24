/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use std::fs;
#[cfg(target_arch = "x86_64")]
use std::sync::OnceLock;

#[cfg(target_arch = "aarch64")]
use crate::elf::aarch64::*;
#[cfg(target_arch = "aarch64")]
use crate::elf::ElfBuilder;

/// Marker printed by the init binary before shutdown.
/// The VM run loop looks for this to extract the exit code.
#[cfg(target_arch = "aarch64")]
pub const EXIT_MARKER: &str = "SANDAL_EXIT:";

/// Mount point and device path constants.
#[cfg(target_arch = "aarch64")]
pub const MNT_LOWER: &str = "/mnt/lower"; // bind-mount of the original root
#[cfg(target_arch = "aarch64")]
pub const MNT_OVERLAY: &str = "/mnt/overlay"; // final overlay mount (becomes new root)
pub const MNT_TMP: &str = "/mnt/tmpupper"; // tmpfs-backed upper (layer + default)
pub const MNT_DISK: &str = "/mnt/diskupper"; // ext2-backed upper (disk mode)
pub const DATA_DEV: &str = "/dev/vdb"; // secondary virtio-blk device

/// Load CA certificates from the host system for HTTPS support.
/// On macOS, reads /etc/ssl/cert.pem which contains the system CA bundle.
/// Returns None if the certificate file cannot be read.
pub fn load_host_ca_certificates() -> Option<Vec<u8>> {
    // Host CA bundles: Linux distributions and macOS, in probe order.
    let ca_paths = [
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Alpine
        "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
        "/etc/ssl/ca-bundle.pem",             // openSUSE
        "/etc/ssl/cert.pem",                  // macOS
    ];
    for path in &ca_paths {
        if let Ok(data) = fs::read(path) {
            if !data.is_empty() {
                return Some(data);
            }
        }
    }
    None
}

/// Export resize signal: guest requests the VMM to grow /dev/vdb so it can
/// write a tar archive for `sandal-export` (tmpfs-upper mode).
#[cfg(target_arch = "aarch64")]
pub const EXPORT_RESIZE_IMM: u32 = 0x5D2; // "SanDal 2"

/// Export done signal: guest has finished the export.  In disk mode the VMM
/// reads the ext2 `upper/` subtree; in tmpfs mode the guest has written an
/// uncompressed tar to /dev/vdb and the VMM reads it from there.
#[cfg(target_arch = "aarch64")]
pub const EXPORT_DONE_IMM: u32 = 0x5D3; // "SanDal 3"

/// UART marker prefix for the export save path: the guest echoes
/// `SANDAL_EXPORT_PATH:<path>` to the console and the VMM intercepts it.
pub const EXPORT_PATH_MARKER: &str = "SANDAL_EXPORT_PATH:";

/// Init config signal: guest requests VM configuration (disk mode,
/// virtiofs mounts, command argv, network flag, timestamp).
/// The VMM pushes a binary config blob into the UART RX buffer
/// and sets x0 = blob size before resuming.
#[cfg(target_arch = "aarch64")]
pub const INIT_CONFIG_IMM: u32 = 0x5D4; // "SanDal 4"

/// The crafted `ctty` guest helper: gives the user command's shell a
/// controlling terminal (job control + tty signals). Pure machine code,
/// built with the x86_64 DSL — no toolchain, no sibling binary.
///
/// Program (System V entry state: [rsp]=argc, [rsp+8+8i]=argv[i]):
/// ```text
/// r15 = rsp
/// r14 = argc                    (preserved across syscalls)
/// setsid()                      — own session (a tty can only be claimed
///                                 by a session leader without a ctty)
/// ioctl(0, TIOCSCTTY, 1)        — claim stdin (1 = force-steal; we run as
///                                 root, and init holds the console without
///                                 using it)
/// execve(argv[1], &argv[1], envp) — run the requested command; the command
///                                 must be an absolute path (the init script
///                                 resolves it with `command -v`)
/// exit(127)                     — only reached if execve failed
/// ```
#[cfg(target_arch = "x86_64")]
static CTTY_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn ctty_helper() -> &'static [u8] {
    CTTY_HELPER.get_or_init(build_ctty_elf)
}

#[cfg(target_arch = "x86_64")]
fn build_ctty_elf() -> Vec<u8> {
    use crate::elf::x86_64::{add_i, add_rr_, load64, shl_r_imm, sys, xexit, zero, X86ElfBuilder};
    use crate::elf::x86_64::{mov_rr_, xioctl_imm, xsetsid};

    let mut e = X86ElfBuilder::new();

    // r15 = rsp — the initial stack: [r15]=argc, [r15+8+8i]=argv[i].
    mov_rr_!(e, r15, rsp);
    load64!(e, r14, r15, 0); // r14 = argc

    // setsid() — own session; a tty can only be claimed by a session
    // leader without a controlling terminal.
    xsetsid!(e);

    // ioctl(0, TIOCSCTTY, 1) — claim stdin; 1 = force-steal (we run as
    // root, and init holds the console without using it).
    zero!(e, rdi);
    xioctl_imm!(e, rdi, crate::elf::x86_64_linux::TIOCSCTTY, 1);

    // rdx = envp = rsp + 16 + 8*argc — the initial environment, preserved.
    mov_rr_!(e, rdx, r14);
    e.emit(&shl_r_imm(crate::elf::x86_64::RDX, 3));
    add_i!(e, rdx, 16);
    add_rr_!(e, rdx, r15);

    // rsi = &argv[1] — the new argv (argv[argc] is still NULL after it).
    mov_rr_!(e, rsi, r15);
    add_i!(e, rsi, 16);

    // rdi = argv[1] — the command path (absolute; resolved by the caller).
    load64!(e, rdi, rsi, 0); // rdi = argv[1] — the command path

    // execve(path, argv+1, envp)
    sys!(e, crate::elf::x86_64_linux::nr::EXECVE);

    // exit(127) — only reached if execve failed.
    xexit!(e, 127);

    e.build()
}

/// Build the TEXT config injected into the rootfs as /etc/sandal.conf for
/// the x86_64 shell-script init (sourced line-by-line with `read`/`case`).
/// The text config has one field per run knob; the argument count mirrors
/// the knobs, not a design smell.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub fn build_init_config_text(
    disk_mode: Option<&str>,
    shares: &[(String, String)],
    command: &[String],
    network: bool,
    clock_secs: u64,
    console_cols: u16,
    console_rows: u16,
    exit_token: &str,
) -> Vec<u8> {
    let mut out = String::new();
    if disk_mode.is_some() {
        out.push_str("DISK_MODE=disk\n");
    }
    out.push_str(&format!("NETWORK={}\n", network as u8));
    out.push_str(&format!("CLOCK={}\n", clock_secs));
    for (tag, path) in shares {
        out.push_str(&format!("SHARE={tag}:{path}\n"));
    }
    out.push_str(&format!("COLS={}\n", console_cols));
    out.push_str(&format!("ROWS={}\n", console_rows));
    out.push_str(&format!("EXIT={}\n", exit_token));
    for arg in command {
        out.push_str(&format!("ARG={arg}\n"));
    }
    out.into_bytes()
}

/// Build the binary config blob that the VMM sends to the guest init
/// binary via UART after `BRK #INIT_CONFIG`.
///
/// Layout (little-endian):
/// ```text
/// 0x00  disk_mode: u8     (0=none, 1=disk)
/// 0x01  num_virtiofs: u8
/// 0x02  num_argv: u8
/// 0x03  network: u8       (0=off, 1=on)
/// 0x04  reserved: u32
/// 0x08  clock_secs: u64
/// 0x10  data[]:           virtiofs (tag\0 path\0)... then argv (arg\0)...
/// ```
#[cfg(target_arch = "aarch64")]
pub fn build_init_config(
    disk_mode: Option<&str>,
    shares: &[(String, String)],
    command: &[String],
    network: bool,
    clock_secs: u64,
) -> Vec<u8> {
    let mut blob = Vec::new();

    // Header (16 bytes)
    let dm: u8 = match disk_mode {
        Some("disk") => 1,
        _ => 0,
    };
    blob.push(dm);
    blob.push(shares.len() as u8);
    blob.push(command.len() as u8);
    blob.push(if network { 1 } else { 0 });
    blob.extend_from_slice(&0u32.to_le_bytes()); // reserved
    blob.extend_from_slice(&clock_secs.to_le_bytes());

    // Virtiofs entries: tag\0 path\0
    for (tag, path) in shares {
        blob.extend_from_slice(tag.as_bytes());
        blob.push(0);
        blob.extend_from_slice(path.as_bytes());
        blob.push(0);
    }

    // Argv entries: arg\0
    for arg in command {
        blob.extend_from_slice(arg.as_bytes());
        blob.push(0);
    }

    blob
}

/// Minimal guest ELF that asks the VMM to grow /dev/vdb (tmpfs-upper mode):
/// `BRK #EXPORT_RESIZE_IMM` on arm64 (const-evaluated), a hypercall OUT on
/// the resize port on x86_64.
#[cfg(target_arch = "aarch64")]
const EXPORT_RESIZE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_RESIZE_IMM);
    exit!(elf, 0);
    elf.build()
};

#[cfg(target_arch = "aarch64")]
pub fn export_resize_helper() -> &'static [u8] {
    &EXPORT_RESIZE_HELPER.0[..EXPORT_RESIZE_HELPER.1]
}

/// Minimal guest ELF that tells the VMM the export data is ready:
/// `BRK #EXPORT_DONE_IMM` on arm64, a hypercall OUT on the done port on x86_64.
#[cfg(target_arch = "aarch64")]
const EXPORT_DONE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_DONE_IMM);
    exit!(elf, 0);
    elf.build()
};

#[cfg(target_arch = "aarch64")]
pub fn export_done_helper() -> &'static [u8] {
    &EXPORT_DONE_HELPER.0[..EXPORT_DONE_HELPER.1]
}

// x86_64 variants: two-instruction programs (hypercall OUT + exit) built once
// at startup with the x86 DSL.
/// x86_64 helper: open /dev/mem, mmap the hypercall page, store the signal
/// word at the page offset (an MMIO write), then exit. MMIO works from
/// userspace without I/O-port privileges (which nested KVM denies).
#[cfg(target_arch = "x86_64")]
fn build_hypercall_elf(signal: u32, mmio_base: u64) -> Vec<u8> {
    use crate::elf::x86_64::{lea, mov_i, mov_m_imm32, sys, syscall_ins, zero, X86ElfBuilder, RSI};

    let mut e = X86ElfBuilder::new();
    let s_dev_mem = e.emit_cstring("/dev/mem");

    // fd = openat(AT_FDCWD, "/dev/mem", O_RDWR)
    mov_i!(e, rdi, crate::elf::x86_64_linux::AT_FDCWD);
    lea!(e, rsi, s_dev_mem);
    mov_i!(e, rdx, 0x2); // O_RDWR
    sys!(e, 257); // openat

    // base = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, page)
    zero!(e, rdi);
    mov_i!(e, rsi, 0x1000);
    mov_i!(e, rdx, 0x3);
    e.emit(&crate::elf::x86_64::mov_r_imm32(crate::elf::x86_64::R10, 1)); // MAP_SHARED
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::R8,
        crate::elf::x86_64::RAX,
    )); // fd
    let (page, off) = crate::vm::x86_hypercall_page_off(mmio_base);
    e.emit(&crate::elf::x86_64::mov_r_imm64(
        crate::elf::x86_64::R9,
        page,
    )); // offset needs the full 64 bits (0xa0000000)
    mov_i!(e, rax, 9); // mmap
    e.emit(&syscall_ins());
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::R15,
        crate::elf::x86_64::RAX,
    )); // mapping base

    // *(u32*)(base + off) = signal — an MMIO write through /dev/mem.
    e.emit(&crate::elf::x86_64::mov_rr(
        crate::elf::x86_64::RSI,
        crate::elf::x86_64::R15,
    ));
    mov_i!(e, rdx, off as i32);
    e.emit(&crate::elf::x86_64::add_rr(
        crate::elf::x86_64::RSI,
        crate::elf::x86_64::RDX,
    ));
    e.emit(&mov_m_imm32(RSI, 0, signal as i32));

    // exit(0)
    e.emit(&crate::elf::x86_64::xor_rr(
        crate::elf::x86_64::RDI,
        crate::elf::x86_64::RDI,
    ));
    mov_i!(e, rax, 60);
    e.emit(&syscall_ins());
    e.build()
}
#[cfg(target_arch = "x86_64")]
fn hypercall_elf(cache: &'static OnceLock<Vec<u8>>, signal: u32, mmio_base: u64) -> &'static [u8] {
    cache.get_or_init(|| build_hypercall_elf(signal, mmio_base))
}

#[cfg(target_arch = "x86_64")]
static EXPORT_RESIZE_HELPER: OnceLock<Vec<u8>> = OnceLock::new();
#[cfg(target_arch = "x86_64")]
static EXPORT_DONE_HELPER: OnceLock<Vec<u8>> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn export_resize_helper(mmio_base: u64) -> Vec<u8> {
    hypercall_elf(
        &EXPORT_RESIZE_HELPER,
        crate::elf::x86_64_linux::EXPORT_RESIZE_PORT as u32,
        mmio_base,
    )
    .to_vec()
}

#[cfg(target_arch = "x86_64")]
pub fn export_done_helper(mmio_base: u64) -> Vec<u8> {
    hypercall_elf(
        &EXPORT_DONE_HELPER,
        crate::elf::x86_64_linux::EXPORT_DONE_PORT as u32,
        mmio_base,
    )
    .to_vec()
}

/// Generate the `sandal-export` shell script for the guest.
///
/// Usage: sandal-export [path]
///
/// 1. Optionally sends the export save path to the VMM via a console marker.
/// 2. Disk mode (ext2 overlay upper): signals EXPORT_DONE directly; the VMM
///    extracts the ext2 `upper/` subtree into a `.layer` file.
/// 3. Tmpfs mode: signals EXPORT_RESIZE to grow /dev/vdb, tars the overlay
///    upper dir onto it, then signals EXPORT_DONE.
pub fn generate_export_script() -> String {
    let data_dev_name = DATA_DEV.strip_prefix("/dev/").unwrap_or(DATA_DEV);
    format!(
        include_str!("export.sh"),
        EXPORT_PATH_MARKER = EXPORT_PATH_MARKER,
        MNT_DISK = MNT_DISK,
        MNT_TMP = MNT_TMP,
        DATA_DEV = DATA_DEV,
        DATA_DEV_NAME = data_dev_name,
    )
}

#[cfg(all(test, target_arch = "x86_64"))]
mod helper_tests {
    #[test]
    fn dump_helpers() {
        if std::env::var_os("SANDAL_DUMP_HELPERS").is_some() {
            let page = 0x4000_0000u64; // the dump helper only checks that it builds
            std::fs::write("/tmp/helper-done", super::export_done_helper(page)).unwrap();
            std::fs::write("/tmp/helper-resize", super::export_resize_helper(page)).unwrap();
            #[cfg(target_arch = "x86_64")]
            std::fs::write("/tmp/helper-ctty", super::ctty_helper()).unwrap();
        }
    }
}
