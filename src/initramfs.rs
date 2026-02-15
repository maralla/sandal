/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::elf::arm64::*;
use crate::elf::linux::*;
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

/// Build a cpio archive from a pre-built initrd file (just reads it).
pub fn load_initrd(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read initrd from {path:?}"))
}

/// Write a single cpio "newc" format entry.
#[allow(clippy::too_many_arguments)]
pub fn write_cpio_entry(
    archive: &mut Vec<u8>,
    name: &str,
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    data: &[u8],
    devmajor: u32,
    devminor: u32,
) -> Result<()> {
    // The name in cpio must NOT have a leading '/'
    let name = name.trim_start_matches('/');

    // namesize includes the trailing NUL
    let namesize = name.len() + 1;
    let filesize = data.len();

    // Write header (110 bytes of ASCII hex fields)
    let header = format!(
        "070701\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}\
         {:08X}",
        ino,      // inode
        mode,     // mode
        uid,      // uid
        gid,      // gid
        nlink,    // nlink
        mtime,    // mtime
        filesize, // filesize
        0u32,     // devmajor (filesystem device, not used)
        0u32,     // devminor (filesystem device, not used)
        devmajor, // rdevmajor (character/block device major)
        devminor, // rdevminor (character/block device minor)
        namesize, // namesize
        0u32,     // checksum (always 0 for newc)
    );

    assert_eq!(header.len(), 110);
    archive.extend_from_slice(header.as_bytes());

    // Write filename + NUL
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);

    // Pad to 4-byte boundary (header + name must be 4-byte aligned)
    let header_plus_name = 110 + namesize;
    let padding = (4 - (header_plus_name % 4)) % 4;
    for _ in 0..padding {
        archive.push(0);
    }

    // Write file data
    archive.extend_from_slice(data);

    // Pad data to 4-byte boundary
    let data_padding = (4 - (filesize % 4)) % 4;
    for _ in 0..data_padding {
        archive.push(0);
    }

    Ok(())
}

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

/// Generate a minimal static ARM64 Linux ELF binary that sets up a
/// controlling terminal and execs a command.
///
/// Usage: sandal-ctty \<tty-device\> \<command\> [args...]
///
/// The binary:
/// 1. Calls `setsid()` to create a new session (making itself session leader)
/// 2. Opens the given TTY device (without O_NOCTTY — the kernel sets it as
///    the controlling terminal because the process is a session leader)
/// 3. Calls `ioctl(TIOCSCTTY)` for robustness
/// 4. Redirects stdin/stdout/stderr to the TTY via `dup3`
/// 5. Execs the given command with remaining arguments
///
/// Computed at compile time — zero runtime overhead.
const CTTY_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();

    // On entry the kernel's ELF loader places the initial stack as:
    //   [sp+0]  = argc
    //   [sp+8]  = argv[0]  (program name)
    //   [sp+16] = argv[1]  (TTY device path)
    //   [sp+24] = argv[2]  (command to exec)
    //   ...
    //   NULL terminator, then envp[]

    // Step 1: setsid()
    setsid!(elf);

    // Step 2: openat(AT_FDCWD, argv[1], O_RDWR)
    openat!(elf, [SP, 16], O_RDWR);
    mov!(elf, x19, x0); // save fd → x19

    // Step 3: ioctl(fd, TIOCSCTTY, 0)
    ioctl!(elf, x19, TIOCSCTTY, 0);

    // Step 4-6: dup3(fd, 0..2, 0) — redirect stdin/stdout/stderr
    let mut newfd: u32 = 0;
    while newfd <= 2 {
        dup3!(elf, x19, newfd);
        newfd += 1;
    }

    // Step 7: close(fd) if fd > 2
    cmp!(elf, x19, 3);
    elf.emit(b_lt(4)); // skip close if fd < 3
    close!(elf, x19);

    // Step 8: execve(argv[2], &argv[2], envp)
    execve!(elf, skip 2);

    // Step 9: exit(127) on execve failure
    exit!(elf, 127);

    assert!(elf.offset() == 45 * 4); // 45 instructions, 180 bytes

    elf.build()
};

pub fn ctty_helper() -> &'static [u8] {
    &CTTY_HELPER.0[..CTTY_HELPER.1]
}

/// Snapshot-ready signal immediate value for BRK instruction.
/// The VMM detects `BRK #SNAPSHOT_SIGNAL_IMM` (EC=0x3C) from EL0
/// and uses it as the trigger to save a snapshot.
pub const SNAPSHOT_SIGNAL_IMM: u32 = 0x5D1; // "SanDal 1"

/// Export resize signal: guest requests the VMM to grow /dev/vdb to 128 MB
/// so it can write a tar archive for `sandal-export`.
pub const EXPORT_RESIZE_IMM: u32 = 0x5D2; // "SanDal 2"

/// Export done signal: guest has finished writing tar data to /dev/vdb.
/// The VMM reads it, gzip-compresses, and saves as a .layer file.
pub const EXPORT_DONE_IMM: u32 = 0x5D3; // "SanDal 3"

/// Init config signal: guest requests VM configuration (disk mode,
/// virtiofs mounts, command argv, network flag, timestamp).
/// The VMM pushes a binary config blob into the UART RX buffer
/// and sets x0 = blob size before resuming.
pub const INIT_CONFIG_IMM: u32 = 0x5D4; // "SanDal 4"

/// Init ready signal: guest has finished processing the config blob
/// (overlay setup, network, etc.) and is about to fork+exec the user
/// command.  The VMM uses this to start forwarding UART TX to stdout,
/// so the config blob echo (kernel TTY echo of the binary blob) is
/// never shown to the user.
pub const INIT_READY_IMM: u32 = 0x5D5; // "SanDal 5"

/// UART marker prefix for communicating the export save path from guest to VMM.
/// The guest echoes `SANDAL_EXPORT_PATH:<path>` to /dev/console before the
/// BRK #EXPORT_DONE signal, and the VMM intercepts this line.
pub const EXPORT_PATH_MARKER: &str = "SANDAL_EXPORT_PATH:";

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

/// Generate a minimal static ARM64 ELF binary that signals
/// snapshot-readiness to the VMM via a BRK instruction.
///
/// The binary is just 3 instructions (12 bytes of code):
///   BRK  #0x5D1    — trapped by HVF, VMM handles it
///   MOV  x0, #0    — exit code 0
///   MOV  x8, #93   — __NR_exit
///   SVC  #0        — exit(0)
///
/// The BRK causes an immediate VM exit (EC=0x3C) while the guest
/// is in EL0 with IRQs enabled and no kernel locks held — a clean,
/// deterministic snapshot point.
///
/// Computed at compile time — zero runtime overhead.
const SIGNAL_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();

    brk!(elf, SNAPSHOT_SIGNAL_IMM);
    exit!(elf, 0);

    elf.build()
};

pub fn signal_helper() -> &'static [u8] {
    &SIGNAL_HELPER.0[..SIGNAL_HELPER.1]
}

/// Generate a minimal static ARM64 ELF binary that triggers
/// BRK #EXPORT_RESIZE_IMM — asks the VMM to grow /dev/vdb.
///
/// After the BRK returns, the kernel will process the virtio config
/// change and resize the block device asynchronously.
///
/// Computed at compile time — zero runtime overhead.
const EXPORT_RESIZE_HELPER: ([u8; ElfBuilder::MAX_ELF], usize) = {
    let mut elf = ElfBuilder::new();

    brk!(elf, EXPORT_RESIZE_IMM);
    exit!(elf, 0);

    elf.build()
};

pub fn export_resize_helper() -> &'static [u8] {
    &EXPORT_RESIZE_HELPER.0[..EXPORT_RESIZE_HELPER.1]
}

/// Generate a minimal static ARM64 ELF binary that triggers
/// BRK #EXPORT_DONE_IMM — tells the VMM the tar data is ready on /dev/vdb.
///
/// Computed at compile time — zero runtime overhead.
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
/// The script:
/// 1. Optionally sends the export save path to the VMM via UART marker
/// 2. If in disk mode (ext2 overlay), signals EXPORT_DONE directly
///    (the VMM reads the ext2 /upper subtree)
/// 3. If in tmpfs mode, signals EXPORT_RESIZE to grow /dev/vdb,
///    waits for resize, tars the overlay upper dir to /dev/vdb,
///    then signals EXPORT_DONE
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
