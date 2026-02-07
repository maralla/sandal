/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Marker printed by the init script before shutdown.
/// The VM run loop looks for this to extract the exit code.
pub const EXIT_MARKER: &str = "SANDAL_EXIT:";

/// Marker printed by the init script once boot is complete and just
/// before running the user command.  The VM loop detects this to switch
/// from suppressed (pre-boot) output to direct character output.
pub const BOOT_MARKER: &str = "SANDAL_BOOT_COMPLETE";

/// Build a cpio newc archive from a directory on the host,
/// injecting a command to run as the init process.
/// Returns the raw bytes of the archive (uncompressed).
pub fn build_from_directory(dir: &Path, command: &[String], network: bool, use_8250_uart: bool) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    let mut inode: u32 = 300000; // Start with a high inode number to avoid collisions

    // Collect all entries recursively
    let mut entries: Vec<PathBuf> = Vec::new();
    collect_entries(dir, dir, &mut entries)?;

    // Sort for deterministic output
    entries.sort();

    for entry_path in &entries {
        let rel_path = entry_path.strip_prefix(dir)
            .context("Failed to compute relative path")?;
        let archive_path = rel_path.to_string_lossy().to_string();

        // Skip the host's /init — we'll inject our own
        if archive_path == "init" {
            continue;
        }

        let metadata = fs::symlink_metadata(entry_path)
            .with_context(|| format!("Failed to stat {:?}", entry_path))?;

        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            let target = fs::read_link(entry_path)
                .with_context(|| format!("Failed to read symlink {:?}", entry_path))?;
            let target_bytes = target.to_string_lossy().into_owned().into_bytes();

            // Symlink: mode has 0o120000 bit set
            let mode = 0o120777;
            write_cpio_entry(&mut archive, &archive_path, inode, mode, 0, 0,
                             1, metadata.mtime() as u32, &target_bytes, 0, 0)?;
        } else if file_type.is_dir() {
            let mode = 0o040000 | (metadata.permissions().mode() & 0o7777);
            write_cpio_entry(&mut archive, &archive_path, inode, mode, 0, 0,
                             2, metadata.mtime() as u32, &[], 0, 0)?;
        } else if file_type.is_file() {
            let data = fs::read(entry_path)
                .with_context(|| format!("Failed to read {:?}", entry_path))?;
            let mode = 0o100000 | (metadata.permissions().mode() & 0o7777);
            write_cpio_entry(&mut archive, &archive_path, inode, mode, 0, 0,
                             1, metadata.mtime() as u32, &data, 0, 0)?;
        }
        // Skip other file types (devices, sockets, etc.)

        inode += 1;
    }

    // Ensure /dev directory exists (may already be in entries)
    let has_dev = entries.iter().any(|e| {
        e.strip_prefix(dir).map(|r| r.to_string_lossy() == "dev").unwrap_or(false)
    });
    if !has_dev {
        write_cpio_entry(&mut archive, "dev", inode, 0o040755, 0, 0, 2, 0, &[], 0, 0)?;
        inode += 1;
    }

    // Create essential device nodes that can't be created on macOS with mknod
    // Character device mode: 0o020000 | permissions
    // /dev/console: major 5, minor 1
    write_cpio_entry(&mut archive, "dev/console", inode, 0o020666, 0, 0, 1, 0, &[], 5, 1)?;
    inode += 1;
    // Serial console device node — depends on UART type
    if use_8250_uart {
        // /dev/ttyS0: major 4, minor 64 (8250/16550 UART)
        write_cpio_entry(&mut archive, "dev/ttyS0", inode, 0o020666, 0, 0, 1, 0, &[], 4, 64)?;
    } else {
        // /dev/ttyAMA0: major 204, minor 64 (PL011 UART)
        write_cpio_entry(&mut archive, "dev/ttyAMA0", inode, 0o020666, 0, 0, 1, 0, &[], 204, 64)?;
    }
    inode += 1;
    // /dev/null: major 1, minor 3
    write_cpio_entry(&mut archive, "dev/null", inode, 0o020666, 0, 0, 1, 0, &[], 1, 3)?;
    inode += 1;
    // /dev/tty: major 5, minor 0
    write_cpio_entry(&mut archive, "dev/tty", inode, 0o020666, 0, 0, 1, 0, &[], 5, 0)?;
    inode += 1;
    // /dev/zero: major 1, minor 5
    write_cpio_entry(&mut archive, "dev/zero", inode, 0o020666, 0, 0, 1, 0, &[], 1, 5)?;
    inode += 1;

    // Inject host CA certificates for HTTPS support
    if network {
        if let Some(ca_data) = load_host_ca_certificates() {
            // Ensure etc/ssl/certs directory exists
            let has_ssl_certs = entries.iter().any(|e| {
                e.strip_prefix(dir).map(|r| r.to_string_lossy() == "etc/ssl/certs").unwrap_or(false)
            });
            if !has_ssl_certs {
                let has_ssl = entries.iter().any(|e| {
                    e.strip_prefix(dir).map(|r| r.to_string_lossy() == "etc/ssl").unwrap_or(false)
                });
                if !has_ssl {
                    write_cpio_entry(&mut archive, "etc/ssl", inode, 0o040755, 0, 0, 2, 0, &[], 0, 0)?;
                    inode += 1;
                }
                write_cpio_entry(&mut archive, "etc/ssl/certs", inode, 0o040755, 0, 0, 2, 0, &[], 0, 0)?;
                inode += 1;
            }
            write_cpio_entry(&mut archive, "etc/ssl/certs/ca-certificates.crt", inode, 0o100644, 0, 0,
                             1, 0, &ca_data, 0, 0)?;
            inode += 1;
        }
    }

    // Inject the entropy seeder binary (needed for TLS/getrandom to work)
    let seeder_bin = generate_entropy_seeder();
    // Ensure /usr/sbin directory exists
    let has_usr_sbin = entries.iter().any(|e| {
        e.strip_prefix(dir).map(|r| r.to_string_lossy() == "usr/sbin").unwrap_or(false)
    });
    if !has_usr_sbin {
        let has_usr = entries.iter().any(|e| {
            e.strip_prefix(dir).map(|r| r.to_string_lossy() == "usr").unwrap_or(false)
        });
        if !has_usr {
            write_cpio_entry(&mut archive, "usr", inode, 0o040755, 0, 0, 2, 0, &[], 0, 0)?;
            inode += 1;
        }
        write_cpio_entry(&mut archive, "usr/sbin", inode, 0o040755, 0, 0, 2, 0, &[], 0, 0)?;
        inode += 1;
    }
    write_cpio_entry(&mut archive, "usr/sbin/seed-entropy", inode, 0o100755, 0, 0,
                     1, 0, &seeder_bin, 0, 0)?;
    inode += 1;

    // Inject the /init script that runs the user's command
    let init_script = generate_init_script(command, network);
    write_cpio_entry(&mut archive, "init", inode, 0o100755, 0, 0, 1, 0,
                     init_script.as_bytes(), 0, 0)?;
    let _inode = inode + 1;

    // Write trailer entry
    write_cpio_entry(&mut archive, "TRAILER!!!", 0, 0, 0, 0, 1, 0, &[], 0, 0)?;

    // Pad archive to 512-byte boundary (convention, helps some loaders)
    while archive.len() % 512 != 0 {
        archive.push(0);
    }

    Ok(archive)
}

/// Public version of init script generator for use by ext2 builder.
pub fn generate_init_script_ext(command: &[String], network: bool) -> String {
    generate_init_script(command, network)
}

/// Generate the /init shell script that runs inside the VM.
/// It mounts essential filesystems, runs the user's command,
/// prints an exit marker, and powers off.
fn generate_init_script(command: &[String], network: bool) -> String {
    // Shell-escape each argument
    let escaped_cmd = command.iter()
        .map(|arg| shell_escape(arg))
        .collect::<Vec<_>>()
        .join(" ");

    let net_setup = if network {
        r#"
# Network setup
ip link set lo up 2>/dev/null
if [ -e /sys/class/net/eth0 ]; then
    ip link set eth0 up 2>/dev/null
    # Try DHCP with short timeout, then fallback to static IP
    DHCP_OK=0
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i eth0 -n -q -T 1 -t 2 -s /usr/share/udhcpc/default.script 2>/dev/null && DHCP_OK=1
    elif command -v dhclient >/dev/null 2>&1; then
        timeout 3 dhclient eth0 2>/dev/null && DHCP_OK=1
    fi
    # Fallback: manual IP configuration if DHCP didn't assign one
    if [ "$DHCP_OK" = "0" ]; then
        ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
        ip route add default via 10.0.2.2 2>/dev/null
        echo "nameserver 10.0.2.3" > /etc/resolv.conf 2>/dev/null
    fi
fi
"#
    } else {
        ""
    };

    // Get current time as Unix timestamp for guest clock sync
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!(r#"#!/bin/sh
# Sandal VM init — auto-generated

# Mount essential filesystems
/bin/mount -t proc proc /proc 2>/dev/null
/bin/mount -t sysfs sysfs /sys 2>/dev/null
/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/mount -t tmpfs tmpfs /tmp 2>/dev/null

# Set system clock to host time (needed for TLS certificate validation)
date -s "@{timestamp}" >/dev/null 2>&1

# Seed kernel entropy pool (needed for TLS/getrandom)
/usr/sbin/seed-entropy 2>/dev/null

# Set up basic environment
export HOME=/root
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=linux
cd /
{net_setup}
# Signal boot complete to host (triggers direct UART output)
echo "{boot_marker}"

# Run the command
{cmd}
SANDAL_RC=$?

# Signal exit code to host
echo "{marker}$SANDAL_RC"

# Power off
exec /sbin/poweroff -f
"#, timestamp = now, net_setup = net_setup, cmd = escaped_cmd, marker = EXIT_MARKER, boot_marker = BOOT_MARKER)
}

/// Simple shell escaping: wrap in single quotes, escaping any embedded single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.') {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Build a cpio archive from a pre-built initrd file (just reads it).
pub fn load_initrd(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("Failed to read initrd from {:?}", path))
}

/// Recursively collect all filesystem entries under `base`.
fn collect_entries(base: &Path, current: &Path, entries: &mut Vec<PathBuf>) -> Result<()> {
    let read_dir = fs::read_dir(current)
        .with_context(|| format!("Failed to read directory {:?}", current))?;

    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        entries.push(path.clone());

        if entry.file_type()?.is_dir() {
            collect_entries(base, &path, entries)?;
        }
    }

    Ok(())
}

/// Write a single cpio "newc" format entry.
fn write_cpio_entry(
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
        ino,        // inode
        mode,       // mode
        uid,        // uid
        gid,        // gid
        nlink,      // nlink
        mtime,      // mtime
        filesize,   // filesize
        0u32,       // devmajor (filesystem device, not used)
        0u32,       // devminor (filesystem device, not used)
        devmajor,   // rdevmajor (character/block device major)
        devminor,   // rdevminor (character/block device minor)
        namesize,   // namesize
        0u32,       // checksum (always 0 for newc)
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
    let ca_paths = [
        "/etc/ssl/cert.pem",
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

/// Generate a minimal static ARM64 Linux ELF binary that seeds the kernel's
/// entropy pool via the RNDADDENTROPY ioctl. This is necessary because some
/// kernels (e.g. 4.14) don't have virtio-rng support, and without entropy
/// getrandom() blocks, preventing TLS/SSL from working.
///
/// The binary:
/// 1. Opens /dev/random
/// 2. Calls ioctl(fd, RNDADDENTROPY, &info) with embedded random data
/// 3. Exits
pub fn generate_entropy_seeder() -> Vec<u8> {
    // Generate 256 bytes of random data from the host
    let mut seed_data = [0u8; 256];
    let mut urandom = fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
    use std::io::Read;
    urandom.read_exact(&mut seed_data).expect("Failed to read entropy from /dev/urandom");

    // ARM64 code (assembled manually)
    //
    // The code layout at the start of the loadable segment:
    //   offset 0x00: instructions (13 instructions = 52 bytes)
    //   offset 0x34: path string "/dev/random\0" (12 bytes)
    //   offset 0x40: entropy_info struct (8 bytes header + 256 bytes data)
    //
    // Instructions:
    //   0x00: movn x0, #99          ; x0 = AT_FDCWD (-100)
    //   0x04: adr  x1, path         ; x1 = &"/dev/random"
    //   0x08: mov  x2, #1           ; x2 = O_WRONLY
    //   0x0C: mov  x8, #56          ; x8 = __NR_openat
    //   0x10: svc  #0
    //   0x14: mov  w1, #0x5203      ; low 16 bits of RNDADDENTROPY
    //   0x18: movk w1, #0x4008, lsl 16 ; w1 = 0x40085203 = RNDADDENTROPY
    //   0x1C: adr  x2, entropy_info ; x2 = &entropy_info
    //   0x20: mov  x8, #29          ; x8 = __NR_ioctl
    //   0x24: svc  #0
    //   0x28: mov  x0, #0           ; exit code 0
    //   0x2C: mov  x8, #93          ; x8 = __NR_exit
    //   0x30: svc  #0

    let mut code = Vec::new();

    // Helper to encode ARM64 instructions
    fn movn_x(rd: u32, imm16: u32) -> u32 {
        0x92800000 | (imm16 << 5) | rd
    }
    fn movz_x(rd: u32, imm16: u32) -> u32 {
        0xD2800000 | (imm16 << 5) | rd
    }
    fn movz_w(rd: u32, imm16: u32) -> u32 {
        0x52800000 | (imm16 << 5) | rd
    }
    fn movk_w_16(rd: u32, imm16: u32) -> u32 {
        // MOVK Wd, #imm16, LSL #16 (hw=1)
        0x72A00000 | (imm16 << 5) | rd
    }
    fn adr(rd: u32, offset: i32) -> u32 {
        let immlo = (offset as u32) & 3;
        let immhi = ((offset >> 2) as u32) & 0x7FFFF;
        (immlo << 29) | (0b10000 << 24) | (immhi << 5) | rd
    }
    fn svc0() -> u32 { 0xD4000001 }

    // Instruction 0 (offset 0x00): movn x0, #99 (AT_FDCWD = -100)
    code.extend_from_slice(&movn_x(0, 99).to_le_bytes());
    // Instruction 1 (offset 0x04): adr x1, +48 (path at offset 0x34)
    code.extend_from_slice(&adr(1, 0x34 - 0x04).to_le_bytes());
    // Instruction 2 (offset 0x08): movz x2, #1 (O_WRONLY)
    code.extend_from_slice(&movz_x(2, 1).to_le_bytes());
    // Instruction 3 (offset 0x0C): movz x8, #56 (__NR_openat)
    code.extend_from_slice(&movz_x(8, 56).to_le_bytes());
    // Instruction 4 (offset 0x10): svc #0
    code.extend_from_slice(&svc0().to_le_bytes());
    // Instruction 5 (offset 0x14): movz w1, #0x5203
    code.extend_from_slice(&movz_w(1, 0x5203).to_le_bytes());
    // Instruction 6 (offset 0x18): movk w1, #0x4008, lsl 16
    code.extend_from_slice(&movk_w_16(1, 0x4008).to_le_bytes());
    // Instruction 7 (offset 0x1C): adr x2, entropy_info (at offset 0x40)
    code.extend_from_slice(&adr(2, 0x40 - 0x1C).to_le_bytes());
    // Instruction 8 (offset 0x20): movz x8, #29 (__NR_ioctl)
    code.extend_from_slice(&movz_x(8, 29).to_le_bytes());
    // Instruction 9 (offset 0x24): svc #0
    code.extend_from_slice(&svc0().to_le_bytes());
    // Instruction 10 (offset 0x28): movz x0, #0 (exit code)
    code.extend_from_slice(&movz_x(0, 0).to_le_bytes());
    // Instruction 11 (offset 0x2C): movz x8, #93 (__NR_exit)
    code.extend_from_slice(&movz_x(8, 93).to_le_bytes());
    // Instruction 12 (offset 0x30): svc #0
    code.extend_from_slice(&svc0().to_le_bytes());

    assert_eq!(code.len(), 52); // 13 instructions * 4 bytes

    // Path string at offset 0x34
    code.extend_from_slice(b"/dev/random\0");
    assert_eq!(code.len(), 64); // 52 + 12

    // Pad to offset 0x40 (align to 4 bytes — already aligned)

    // struct rand_pool_info at offset 0x40
    code.extend_from_slice(&2048i32.to_le_bytes()); // entropy_count = 256 * 8 bits
    code.extend_from_slice(&256i32.to_le_bytes());  // buf_size = 256
    code.extend_from_slice(&seed_data);             // 256 bytes of random data

    // Now build the ELF binary
    let code_len = code.len();
    let load_addr: u64 = 0x400000;
    let ehdr_size: u16 = 64;
    let phdr_size: u16 = 56;
    let file_offset = ehdr_size as u64 + phdr_size as u64; // code starts at offset 120
    let entry = load_addr + file_offset;

    let mut elf = Vec::new();

    // ELF header (64 bytes for 64-bit)
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
    elf.push(2);    // EI_CLASS: ELFCLASS64
    elf.push(1);    // EI_DATA: ELFDATA2LSB (little-endian)
    elf.push(1);    // EI_VERSION: EV_CURRENT
    elf.push(0);    // EI_OSABI: ELFOSABI_NONE
    elf.extend_from_slice(&[0; 8]); // EI_ABIVERSION + padding
    elf.extend_from_slice(&2u16.to_le_bytes());  // e_type: ET_EXEC
    elf.extend_from_slice(&0xB7u16.to_le_bytes()); // e_machine: EM_AARCH64
    elf.extend_from_slice(&1u32.to_le_bytes());  // e_version: EV_CURRENT
    elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
    elf.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff (program header offset)
    elf.extend_from_slice(&0u64.to_le_bytes());  // e_shoff (no section headers)
    elf.extend_from_slice(&0u32.to_le_bytes());  // e_flags
    elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&phdr_size.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes());  // e_phnum (1 program header)
    elf.extend_from_slice(&0u16.to_le_bytes());  // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes());  // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes());  // e_shstrndx
    assert_eq!(elf.len(), 64);

    // Program header (56 bytes for 64-bit)
    elf.extend_from_slice(&1u32.to_le_bytes());  // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes());  // p_flags: PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes());  // p_offset: load from start of file
    elf.extend_from_slice(&(load_addr).to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&(load_addr).to_le_bytes()); // p_paddr
    let total_size = file_offset + code_len as u64;
    elf.extend_from_slice(&total_size.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&total_size.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    assert_eq!(elf.len(), 120);

    // Append the code
    elf.extend_from_slice(&code);

    elf
}
