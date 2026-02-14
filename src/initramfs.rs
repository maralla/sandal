/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::elf::arm64::*;
use crate::elf::ElfBuilder;

/// Marker printed by the init script before shutdown.
/// The VM run loop looks for this to extract the exit code.
pub const EXIT_MARKER: &str = "SANDAL_EXIT:";

/// Marker printed by the init script once boot is complete and just
/// before running the user command.  The VM loop detects this to switch
/// from suppressed (pre-boot) output to direct character output.
pub const BOOT_MARKER: &str = "SANDAL_BOOT_COMPLETE";

/// Mount point and device path constants.
pub const MNT_LOWER: &str = "/mnt/lower"; // bind-mount of the original root
pub const MNT_OVL: &str = "/mnt/overlay"; // final overlay mount (becomes new root)
pub const MNT_TMP: &str = "/mnt/tmpupper"; // tmpfs-backed upper (layer + default)
pub const MNT_DISK: &str = "/mnt/diskupper"; // ext2-backed upper (disk mode)
pub const DATA_DEV: &str = "/dev/vdb"; // secondary virtio-blk device

/// Public version of init script generator for use by ext2 builder.
pub fn generate_init_script_ext(command: &[String], network: bool) -> String {
    generate_init_script(command, network)
}

/// Generate the /init shell script that runs inside the VM.
/// It mounts essential filesystems, reads the command from the host
/// via UART, prints an exit marker, and powers off.
///
/// The command is NOT baked into the script. Instead, after boot setup
/// completes and BOOT_MARKER is printed, the script reads a single line
/// from stdin (the UART). The host injects the shell-escaped command
/// into the UART RX buffer after detecting BOOT_MARKER.
/// This decoupling enables VM snapshots: the same booted state can
/// run different commands by injecting different UART input on restore.
fn generate_init_script(_command: &[String], network: bool) -> String {
    let net_setup = if network { include_str!("net.sh") } else { "" };

    // Get current time as Unix timestamp for guest clock sync
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // The init script template uses {now}, {net_setup}, {BOOT_MARKER},
    // and {EXIT_MARKER} as placeholders filled in by format!().
    format!(
        include_str!("init.sh"),
        now = now,
        net_setup = net_setup,
        BOOT_MARKER = BOOT_MARKER,
        EXIT_MARKER = EXIT_MARKER,
        MNT_LOWER = MNT_LOWER,
        MNT_OVL = MNT_OVL,
        MNT_TMP = MNT_TMP,
        MNT_DISK = MNT_DISK,
        DATA_DEV = DATA_DEV,
    )
}

/// Build the mount setup line injected via UART before the command.
/// Returns a single line of shell commands (or empty string for no shares).
///
/// If `disk_mode` is provided (e.g. "disk" or "layer"), it sets
/// `SANDAL_DISK_MODE` so the init script knows how to handle /dev/vdb.
pub fn build_mount_setup_line(shares: &[(String, String)], disk_mode: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(mode) = disk_mode {
        parts.push(format!("export SANDAL_DISK_MODE={mode}"));
    }

    for (tag, guest_path) in shares {
        parts.push(format!(
            "mkdir -p {guest_path} && mount -t virtiofs {tag} {guest_path} 2>/dev/null"
        ));
    }

    parts.join("; ")
}

/// Build the shell-escaped command line that the host sends to the guest
/// via UART after BOOT_MARKER.  Returns a single line (no trailing newline)
/// that the init script can `eval "set -- $line"` to recover the original
/// argv.
pub fn build_command_line(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| shell_escape(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Simple shell escaping: wrap in single quotes, escaping any embedded single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.')
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

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
pub fn generate_ctty_helper() -> Vec<u8> {
    let mut elf = ElfBuilder::new();

    // On entry the kernel's ELF loader places the initial stack as:
    //   [sp+0]  = argc
    //   [sp+8]  = argv[0]  (program name)
    //   [sp+16] = argv[1]  (TTY device path)
    //   [sp+24] = argv[2]  (command to exec)
    //   ...
    //   NULL terminator, then envp[]

    // Step 1: setsid() — create a new session
    elf.emit(movz_x(8, 157)); // __NR_setsid
    elf.emit(svc0());

    // Step 2: openat(AT_FDCWD, argv[1], O_RDWR)
    elf.emit(movn_x(0, 99)); // AT_FDCWD=-100
    elf.emit(ldr_x_sp(1, 16)); // argv[1]
    elf.emit(movz_x(2, 2)); // O_RDWR
    elf.emit(movz_x(8, 56)); // __NR_openat
    elf.emit(svc0());
    elf.emit(mov_x(19, 0)); // save fd → x19

    // Step 3: ioctl(fd, TIOCSCTTY, 0) — set controlling terminal
    elf.emit(mov_x(0, 19));
    elf.emit(movz_w(1, 0x540E)); // TIOCSCTTY
    elf.emit(movz_x(2, 0));
    elf.emit(movz_x(8, 29)); // __NR_ioctl
    elf.emit(svc0());

    // Step 4-6: dup3(fd, 0..2, 0) — redirect stdin/stdout/stderr
    for newfd in 0u32..=2 {
        elf.emit(mov_x(0, 19));
        elf.emit(movz_x(1, newfd));
        elf.emit(movz_x(2, 0));
        elf.emit(movz_x(8, 24)); // __NR_dup3
        elf.emit(svc0());
    }

    // Step 7: close(fd) if fd > 2
    elf.emit(cmp_x_imm(19, 3));
    elf.emit(b_lt(4)); // skip close if fd < 3
    elf.emit(mov_x(0, 19));
    elf.emit(movz_x(8, 57)); // __NR_close
    elf.emit(svc0());

    // Step 8: execve(argv[2], &argv[2], envp)
    //   envp = sp + (argc+2)*8
    elf.emit(ldr_x_sp(0, 24)); // argv[2]
    elf.emit(add_x_imm(4, 31, 0)); // x4 = SP
    elf.emit(add_x_imm(1, 4, 24)); // &argv[2]
    elf.emit(ldr_x_sp(3, 0)); // argc
    elf.emit(add_x_imm(3, 3, 2)); // argc+2
    elf.emit(lsl_x(3, 3, 3)); // *8
    elf.emit(add_x_reg(2, 4, 3)); // envp
    elf.emit(movz_x(8, 221)); // __NR_execve
    elf.emit(svc0());

    // Step 9: exit(127) on execve failure
    elf.emit(movz_x(0, 127));
    elf.emit(movz_x(8, 93)); // __NR_exit
    elf.emit(svc0());

    assert_eq!(elf.offset(), 45 * 4); // 45 instructions, 180 bytes

    elf.build()
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

/// UART marker prefix for communicating the export save path from guest to VMM.
/// The guest echoes `SANDAL_EXPORT_PATH:<path>` to /dev/console before the
/// BRK #EXPORT_DONE signal, and the VMM intercepts this line.
pub const EXPORT_PATH_MARKER: &str = "SANDAL_EXPORT_PATH:";

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
pub fn generate_signal_helper() -> Vec<u8> {
    let mut elf = ElfBuilder::new();

    // BRK #SNAPSHOT_SIGNAL_IMM — triggers VM exit from EL0
    elf.emit(brk(SNAPSHOT_SIGNAL_IMM));

    // exit(0) — reached after snapshot+restore
    elf.emit(movz_x(0, 0));
    elf.emit(movz_x(8, 93)); // __NR_exit
    elf.emit(svc0());

    elf.build()
}

/// Generate a minimal static ARM64 ELF binary that triggers
/// BRK #EXPORT_RESIZE_IMM — asks the VMM to grow /dev/vdb.
///
/// After the BRK returns, the kernel will process the virtio config
/// change and resize the block device asynchronously.
pub fn generate_export_resize_helper() -> Vec<u8> {
    let mut elf = ElfBuilder::new();

    elf.emit(brk(EXPORT_RESIZE_IMM));
    elf.emit(movz_x(0, 0));
    elf.emit(movz_x(8, 93)); // __NR_exit
    elf.emit(svc0());

    elf.build()
}

/// Generate a minimal static ARM64 ELF binary that triggers
/// BRK #EXPORT_DONE_IMM — tells the VMM the tar data is ready on /dev/vdb.
pub fn generate_export_done_helper() -> Vec<u8> {
    let mut elf = ElfBuilder::new();

    elf.emit(brk(EXPORT_DONE_IMM));
    elf.emit(movz_x(0, 0));
    elf.emit(movz_x(8, 93)); // __NR_exit
    elf.emit(svc0());

    elf.build()
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
