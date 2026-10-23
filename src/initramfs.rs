/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use std::fs;

/// Crafted guest helper ELFs, one module per arch, one file per tool
/// (ctty, portagent, the export signal helpers).
pub mod tools;

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

/// Exit protocol signal: the crafted init BRKs with the session's exit
/// code in x15; the VMM reads the register at the trap (the marker-free
/// exit protocol — the old fixed `SANDAL_EXIT:<code>` stdout marker is
/// gone).
#[cfg(target_arch = "aarch64")]
pub const EXIT_IMM: u32 = 0x5D5; // "SanDal 5"

/// Init config signal: guest requests VM configuration (disk mode,
/// virtiofs mounts, network flag, timestamp).
/// The VMM pushes a binary config blob into the UART RX buffer
/// and sets x0 = blob size before resuming.
#[cfg(target_arch = "aarch64")]
pub const INIT_CONFIG_IMM: u32 = 0x5D4; // "SanDal 4"

/// Build the TEXT config injected into the rootfs as /etc/sandal.conf for
/// the x86_64 shell-script init (sourced line-by-line with `read`/`case`).
/// The text config has one field per run knob; the argument count mirrors
/// the knobs, not a design smell.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
pub fn build_init_config_text(
    disk_mode: Option<&str>,
    shares: &[(String, String)],
    network: bool,
    clock_secs: u64,
    host_term: &str,
    mem_cap: u64,
    vsockd_port: Option<u32>,
    hypercall_addr: Option<u64>,
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
    // Memory hotplug cap (bytes): the whole KVM slot size, passed so the
    // guest init can grow the declared RAM floor toward it on demand.
    // Zero means no hotplug (a cap at or below the floor).
    out.push_str(&format!("MEMCAP={mem_cap}\n"));
    // The command execution line's port, verbatim from the VMM's own
    // constant: the guest init starts /bin/vsockd with it (one forked
    // child per connection — the general command execution proxy: the
    // connection's own bytes decide what runs). None means no channel:
    // nothing starts, and the vsock port answers nothing.
    if let Some(vsockd_port) = vsockd_port {
        out.push_str(&format!("VSOCKD={vsockd_port}\n"));
        if let Some(addr) = hypercall_addr {
            out.push_str(&format!("HYPERCALL={addr}\n"));
        }
    }
    // The guest terminal type: the host's own, sanitized by the caller
    // (see Vmm::boot). The pty session is a REAL terminal — the guest
    // init exports this so every terminal application agrees with the
    // host side, and the matching terminfo entry is injected below
    // (inject_runtime_files). Empty: the guest keeps its linux fallback.
    if !host_term.is_empty() {
        out.push_str(&format!("TERM={host_term}\n"));
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
/// 0x08  clock_secs: u64
/// 0x10  data[]:           virtiofs (tag\0 path\0)... then argv (arg\0)...
/// ```
#[cfg(target_arch = "aarch64")]
pub fn build_init_config(
    disk_mode: Option<&str>,
    shares: &[(String, String)],
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
    blob.push(0); // no argv: the command execution line is x86_64-only
    blob.push(if network { 1 } else { 0 });
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

/// Generate the `sandal-export` shell script for the guest.
///
/// Usage: sandal-export [path]
///
/// 1. Optionally sends the export save path to the VMM via the export path
///    port (a dedicated virtio-console port whose whole stream IS the path).
/// 2. Disk mode (ext2 overlay upper): signals EXPORT_DONE directly; the VMM
///    extracts the ext2 `upper/` subtree into a `.layer` file.
/// 3. Tmpfs mode: signals EXPORT_RESIZE to grow /dev/vdb, tars the overlay
///    upper dir onto it, then signals EXPORT_DONE.
pub fn generate_export_script() -> String {
    let data_dev_name = DATA_DEV.strip_prefix("/dev/").unwrap_or(DATA_DEV);
    format!(
        include_str!("export.sh"),
        MNT_DISK = MNT_DISK,
        MNT_TMP = MNT_TMP,
        DATA_DEV = DATA_DEV,
        DATA_DEV_NAME = data_dev_name,
    )
}
