/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Marker printed by the init script before shutdown.
/// The VM run loop looks for this to extract the exit code.
pub const EXIT_MARKER: &str = "SANDAL_EXIT:";

/// Marker printed by the init script once boot is complete and just
/// before running the user command.  The VM loop detects this to switch
/// from suppressed (pre-boot) output to direct character output.
pub const BOOT_MARKER: &str = "SANDAL_BOOT_COMPLETE";

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

    // Mount commands are no longer baked into the init script.
    // They are injected via UART at runtime (see build_mount_setup_line),
    // so the same rootfs/snapshot works for any --share combination.

    // Get current time as Unix timestamp for guest clock sync
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!(
        r#"#!/bin/sh
# Sandal VM init — auto-generated

# Mount essential filesystems
/bin/mount -t proc proc /proc 2>/dev/null
/bin/mount -t sysfs sysfs /sys 2>/dev/null
/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/mount -t tmpfs tmpfs /tmp 2>/dev/null

# Load virtio modules if compiled as modules (needed for some kernels
# like Debian's that don't build them in).  Order matters for deps:
# failover → net_failover → virtio_net.
KVER=$(uname -r)
KMOD="/lib/modules/$KVER/kernel"
for mod in \
    drivers/virtio/virtio_mmio.ko \
    net/core/failover.ko \
    drivers/net/net_failover.ko \
    drivers/net/virtio_net.ko \
    drivers/char/hw_random/virtio-rng.ko \
    drivers/block/virtio_blk.ko \
    fs/fuse/fuse.ko \
    fs/fuse/virtiofs.ko \
; do
    [ -f "$KMOD/$mod" ] && insmod "$KMOD/$mod" 2>/dev/null
done

# Set system clock to host time (needed for TLS certificate validation)
date -s "@{now}" >/dev/null 2>&1

# Seed kernel entropy pool (needed for TLS/getrandom)
/usr/sbin/seed-entropy 2>/dev/null

# Set up basic environment
export HOME=/root
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=linux
cd /
{net_setup}
# Determine controlling terminal device before BOOT_MARKER
# (reading /sys after boot-complete would show on stdout)
CTTY=/dev/$(cat /sys/class/tty/console/active 2>/dev/null)

# Disable echo BEFORE signaling boot complete, so the command
# line sent by the host is not echoed back to stdout.
stty -echo 2>/dev/null

# Signal boot complete to host (triggers direct UART output)
echo "{BOOT_MARKER}"

# Read mount setup + command from the UART.  The host writes two lines:
#   1. Mount commands (or empty for no shares)
#   2. Shell-escaped command line
IFS= read -r SANDAL_MOUNT_SETUP
eval "$SANDAL_MOUNT_SETUP"
IFS= read -r SANDAL_CMD_LINE

# Parse the command line back into positional parameters
eval "set -- $SANDAL_CMD_LINE"

# Re-enable echo.  The stty -echo above was only needed to suppress
# the injected command line; now that it has been read, restore echo
# so interactive programs (shells, cat, python, etc.) work properly.
stty echo 2>/dev/null

# Set up a controlling terminal.  PID 1 inherits session 0 from the
# kernel and is NOT a session leader, so open() on a TTY will not make
# it the controlling terminal.  sandal-ctty calls setsid(), opens the
# real TTY device, sets it as the controlling terminal via TIOCSCTTY,
# redirects stdio, and exec's the command.
# /dev/console itself always forces O_NOCTTY, so we use the real device.
# We also resolve the command to an absolute path because execve(2)
# does not search PATH.  `which` returns the filesystem path (not
# builtin names like `command -v` does).
SANDAL_CMD=$(which "$1" 2>/dev/null || echo "$1")
shift
if [ ! -x "$SANDAL_CMD" ]; then
    echo "Unknown command: $SANDAL_CMD" >&2
    SANDAL_RC=127
elif [ -c "$CTTY" ]; then
    /usr/sbin/sandal-ctty "$CTTY" "$SANDAL_CMD" "$@"
    SANDAL_RC=$?
else
    "$SANDAL_CMD" "$@"
    SANDAL_RC=$?
fi

# Signal exit code to host.
# Primary: write EXIT_MARKER via the normal UART path (works on cold boot).
# Fallback: write exit code directly to a special MMIO register at
# UART_BASE + 0x100 that the VMM intercepts.  This bypasses the
# TTY layer and works even after snapshot restore when the serial
# driver's interrupt-driven TX path may be broken.
echo "{EXIT_MARKER}$SANDAL_RC"
devmem 0x09000100 32 "$SANDAL_RC" 2>/dev/null

# Power off
exec /sbin/poweroff -f
"#
    )
}

/// Build the mount setup line injected via UART before the command.
/// Returns a single line of shell commands (or empty string for no shares).
pub fn build_mount_setup_line(shares: &[(String, String)]) -> String {
    if shares.is_empty() {
        return String::new();
    }
    shares
        .iter()
        .map(|(tag, guest_path)| {
            format!("mkdir -p {guest_path} && mount -t virtiofs {tag} {guest_path} 2>/dev/null")
        })
        .collect::<Vec<_>>()
        .join("; ")
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
    let mut code = Vec::new();

    // ── ARM64 instruction encoders ──────────────────────────────────────
    fn movn_x(rd: u32, imm16: u32) -> u32 {
        0x92800000 | (imm16 << 5) | rd
    }
    fn movz_x(rd: u32, imm16: u32) -> u32 {
        0xD2800000 | (imm16 << 5) | rd
    }
    fn movz_w(rd: u32, imm16: u32) -> u32 {
        0x52800000 | (imm16 << 5) | rd
    }
    fn svc0() -> u32 {
        0xD4000001
    }
    fn ldr_x_sp(rt: u32, byte_off: u32) -> u32 {
        // LDR Xt, [SP, #byte_off]  (unsigned-offset, 64-bit)
        assert!(byte_off.is_multiple_of(8));
        0xF9400000 | ((byte_off / 8) << 10) | (31 << 5) | rt
    }
    fn mov_x(rd: u32, rm: u32) -> u32 {
        // MOV Xd, Xm → ORR Xd, XZR, Xm
        0xAA0003E0 | (rm << 16) | rd
    }
    fn add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        // ADD Xd, Xn|SP, #imm12
        0x91000000 | (imm12 << 10) | (rn << 5) | rd
    }
    fn add_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
        // ADD Xd, Xn, Xm  (shifted register, shift=0)
        0x8B000000 | (rm << 16) | (rn << 5) | rd
    }
    fn cmp_x_imm(rn: u32, imm12: u32) -> u32 {
        // CMP Xn, #imm12 → SUBS XZR, Xn, #imm12
        0xF1000000 | (imm12 << 10) | (rn << 5) | 31
    }
    fn b_lt(offset_insns: i32) -> u32 {
        // B.LT — branch if less-than (signed), offset in instructions
        0x54000000 | (((offset_insns as u32) & 0x7FFFF) << 5) | 0xB
    }
    fn lsl_x(rd: u32, rn: u32, shift: u32) -> u32 {
        // LSL Xd, Xn, #shift → UBFM Xd, Xn, #(64-shift), #(63-shift)
        let immr = (64 - shift) & 63;
        let imms = 63 - shift;
        0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
    }

    // ── Instructions ────────────────────────────────────────────────────
    //
    // On entry the kernel's ELF loader places the initial stack as:
    //   [sp+0]  = argc
    //   [sp+8]  = argv[0]  (program name)
    //   [sp+16] = argv[1]  (TTY device path)
    //   [sp+24] = argv[2]  (command to exec)
    //   ...
    //   NULL terminator, then envp[]

    // Step 1: setsid() — create a new session
    code.extend_from_slice(&movz_x(8, 157).to_le_bytes()); // 0x00  __NR_setsid
    code.extend_from_slice(&svc0().to_le_bytes()); // 0x04

    // Step 2: openat(AT_FDCWD, argv[1], O_RDWR)
    code.extend_from_slice(&movn_x(0, 99).to_le_bytes()); // 0x08  AT_FDCWD=-100
    code.extend_from_slice(&ldr_x_sp(1, 16).to_le_bytes()); // 0x0C  argv[1]
    code.extend_from_slice(&movz_x(2, 2).to_le_bytes()); // 0x10  O_RDWR
    code.extend_from_slice(&movz_x(8, 56).to_le_bytes()); // 0x14  __NR_openat
    code.extend_from_slice(&svc0().to_le_bytes()); // 0x18
    code.extend_from_slice(&mov_x(19, 0).to_le_bytes()); // 0x1C  save fd → x19

    // Step 3: ioctl(fd, TIOCSCTTY, 0) — set controlling terminal
    code.extend_from_slice(&mov_x(0, 19).to_le_bytes()); // 0x20
    code.extend_from_slice(&movz_w(1, 0x540E).to_le_bytes()); // 0x24  TIOCSCTTY
    code.extend_from_slice(&movz_x(2, 0).to_le_bytes()); // 0x28
    code.extend_from_slice(&movz_x(8, 29).to_le_bytes()); // 0x2C  __NR_ioctl
    code.extend_from_slice(&svc0().to_le_bytes()); // 0x30

    // Step 4-6: dup3(fd, 0..2, 0) — redirect stdin/stdout/stderr
    for newfd in 0u32..=2 {
        code.extend_from_slice(&mov_x(0, 19).to_le_bytes());
        code.extend_from_slice(&movz_x(1, newfd).to_le_bytes());
        code.extend_from_slice(&movz_x(2, 0).to_le_bytes());
        code.extend_from_slice(&movz_x(8, 24).to_le_bytes()); // __NR_dup3
        code.extend_from_slice(&svc0().to_le_bytes());
    }
    // After the loop: offset = 0x34 + 3*20 = 0x34 + 60 = 0x70

    // Step 7: close(fd) if fd > 2
    code.extend_from_slice(&cmp_x_imm(19, 3).to_le_bytes()); // 0x70
    code.extend_from_slice(&b_lt(4).to_le_bytes()); // 0x74  → 0x84
    code.extend_from_slice(&mov_x(0, 19).to_le_bytes()); // 0x78
    code.extend_from_slice(&movz_x(8, 57).to_le_bytes()); // 0x7C  __NR_close
    code.extend_from_slice(&svc0().to_le_bytes()); // 0x80

    // Step 8: execve(argv[2], &argv[2], envp)
    //   envp = sp + (argc+2)*8   (argv[0..argc] + NULL = argc+1 pointers,
    //                              plus the argc word itself = +8)
    code.extend_from_slice(&ldr_x_sp(0, 24).to_le_bytes()); // 0x84  argv[2]
    code.extend_from_slice(&add_x_imm(4, 31, 0).to_le_bytes()); // 0x88  x4 = SP
    code.extend_from_slice(&add_x_imm(1, 4, 24).to_le_bytes()); // 0x8C  &argv[2]
    code.extend_from_slice(&ldr_x_sp(3, 0).to_le_bytes()); // 0x90  argc
    code.extend_from_slice(&add_x_imm(3, 3, 2).to_le_bytes()); // 0x94  argc+2
    code.extend_from_slice(&lsl_x(3, 3, 3).to_le_bytes()); // 0x98  *8
    code.extend_from_slice(&add_x_reg(2, 4, 3).to_le_bytes()); // 0x9C  envp
    code.extend_from_slice(&movz_x(8, 221).to_le_bytes()); // 0xA0  __NR_execve
    code.extend_from_slice(&svc0().to_le_bytes()); // 0xA4

    // Step 9: exit(127) on execve failure
    code.extend_from_slice(&movz_x(0, 127).to_le_bytes()); // 0xA8
    code.extend_from_slice(&movz_x(8, 93).to_le_bytes()); // 0xAC  __NR_exit
    code.extend_from_slice(&svc0().to_le_bytes()); // 0xB0

    assert_eq!(code.len(), 45 * 4); // 45 instructions, 180 bytes

    // ── Wrap in a minimal ELF binary ────────────────────────────────────
    build_arm64_elf(&code)
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
    urandom
        .read_exact(&mut seed_data)
        .expect("Failed to read entropy from /dev/urandom");

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
    fn svc0() -> u32 {
        0xD4000001
    }

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
    code.extend_from_slice(&256i32.to_le_bytes()); // buf_size = 256
    code.extend_from_slice(&seed_data); // 256 bytes of random data

    // Wrap in a minimal ELF binary
    build_arm64_elf(&code)
}

/// Build a minimal static ARM64 Linux ELF executable from raw code bytes.
/// The code is placed immediately after the ELF + program headers and mapped
/// as a single read+execute PT_LOAD segment at 0x400000.
fn build_arm64_elf(code: &[u8]) -> Vec<u8> {
    let code_len = code.len();
    let load_addr: u64 = 0x400000;
    let ehdr_size: u16 = 64;
    let phdr_size: u16 = 56;
    let file_offset = ehdr_size as u64 + phdr_size as u64; // code starts at offset 120
    let entry = load_addr + file_offset;

    let mut elf = Vec::new();

    // ELF header (64 bytes for 64-bit)
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // e_ident magic
    elf.push(2); // EI_CLASS: ELFCLASS64
    elf.push(1); // EI_DATA: ELFDATA2LSB (little-endian)
    elf.push(1); // EI_VERSION: EV_CURRENT
    elf.push(0); // EI_OSABI: ELFOSABI_NONE
    elf.extend_from_slice(&[0; 8]); // EI_ABIVERSION + padding
    elf.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    elf.extend_from_slice(&0xB7u16.to_le_bytes()); // e_machine: EM_AARCH64
    elf.extend_from_slice(&1u32.to_le_bytes()); // e_version: EV_CURRENT
    elf.extend_from_slice(&entry.to_le_bytes()); // e_entry
    elf.extend_from_slice(&(ehdr_size as u64).to_le_bytes()); // e_phoff (program header offset)
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff (no section headers)
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&ehdr_size.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&phdr_size.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum (1 program header)
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    elf.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(elf.len(), 64);

    // Program header (56 bytes for 64-bit)
    elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset: load from start of file
    elf.extend_from_slice(&(load_addr).to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&(load_addr).to_le_bytes()); // p_paddr
    let total_size = file_offset + code_len as u64;
    elf.extend_from_slice(&total_size.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&total_size.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    assert_eq!(elf.len(), 120);

    // Append the code
    elf.extend_from_slice(code);

    elf
}
