/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use std::fs;

use crate::elf::arm64::*;
use crate::elf::ElfBuilder;

/// Marker printed by the init binary before shutdown.
/// The VM run loop looks for this to extract the exit code.
pub const EXIT_MARKER: &str = "SANDAL_EXIT:";

/// Mount point and device path constants.
pub const MNT_LOWER: &str = "/mnt/lower"; // bind-mount of the original root
pub const MNT_OVERLAY: &str = "/mnt/overlay"; // final overlay mount (becomes new root)
pub const MNT_TMP: &str = "/mnt/tmpupper"; // tmpfs-backed upper (layer + default)
pub const MNT_DISK: &str = "/mnt/diskupper"; // ext2-backed upper (disk mode)
pub const DATA_DEV: &str = "/dev/vdb"; // secondary virtio-blk device

/// Load CA certificates from the host system for HTTPS support.
/// On macOS, reads /etc/ssl/cert.pem which contains the system CA bundle.
/// Returns None if the certificate file cannot be read.
pub fn load_host_ca_certificates() -> Option<Vec<u8>> {
    // macOS system CA certificate bundle
    let ca_paths = ["/etc/ssl/cert.pem"];
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
pub const EXPORT_RESIZE_IMM: u32 = 0x5D2; // "SanDal 2"

/// Export done signal: guest has finished the export.  In disk mode the VMM
/// reads the ext2 `upper/` subtree; in tmpfs mode the guest has written an
/// uncompressed tar to /dev/vdb and the VMM reads it from there.
pub const EXPORT_DONE_IMM: u32 = 0x5D3; // "SanDal 3"

/// UART marker prefix for the export save path: the guest echoes
/// `SANDAL_EXPORT_PATH:<path>` to the console and the VMM intercepts it.
pub const EXPORT_PATH_MARKER: &str = "SANDAL_EXPORT_PATH:";

/// Init config signal: guest requests VM configuration (disk mode,
/// virtiofs mounts, command argv, network flag, timestamp).
/// The VMM pushes a binary config blob into the UART RX buffer
/// and sets x0 = blob size before resuming.
pub const INIT_CONFIG_IMM: u32 = 0x5D4; // "SanDal 4"

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

/// Minimal static ARM64 ELF that triggers `BRK #EXPORT_RESIZE_IMM` — asks the
/// VMM to grow /dev/vdb (tmpfs-upper mode).  Computed at compile time.
const EXPORT_RESIZE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_RESIZE_IMM);
    exit!(elf, 0);
    elf.build()
};

pub fn export_resize_helper() -> &'static [u8] {
    &EXPORT_RESIZE_HELPER.0[..EXPORT_RESIZE_HELPER.1]
}

/// Minimal static ARM64 ELF that triggers `BRK #EXPORT_DONE_IMM` — tells the
/// VMM the export data is ready.  Computed at compile time.
const EXPORT_DONE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();
    brk!(elf, EXPORT_DONE_IMM);
    exit!(elf, 0);
    elf.build()
};

pub fn export_done_helper() -> &'static [u8] {
    &EXPORT_DONE_HELPER.0[..EXPORT_DONE_HELPER.1]
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
