/// Build a cpio "newc" format archive from a host directory.
/// This is the format Linux expects for initramfs images.
///
/// Format reference: https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
use std::fs;

/// Crafted guest helper ELFs, one module per arch, one file per tool
/// (ctty, portagent, the export signal helpers).
pub mod tools;

/// Mount point and device path constants.
pub const MNT_TMP: &str = "/mnt/tmpupper"; // tmpfs-backed upper (layer + default)
pub const MNT_DISK: &str = "/mnt/diskupper"; // ext2-backed upper (disk mode)
pub const DATA_DEV: &str = "/dev/vdb"; // secondary virtio-blk device

/// The run configuration injected into the rootfs as /etc/sandal.conf (a
/// plain file read needs no privileges — the same channel on both arches).
pub const CONFIG_PATH: &str = "etc/sandal.conf";

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

/// Export resize signal: the guest asks the VMM to grow /dev/vdb so it can
/// write a tar archive for `sandal-export` (tmpfs-upper mode). The aarch64
/// raises it as a BRK immediate; the x86_64 stores the same number to the
/// hypercall page (the low half of the MMIO write selects the signal).
pub const EXPORT_RESIZE_IMM: u32 = 0x5D2; // "SanDal 2"

/// Export done signal: the guest has finished the export. In disk mode the
/// VMM reads the ext2 `upper/` subtree; in tmpfs mode the guest has written
/// an uncompressed tar to /dev/vdb and the VMM reads it from there.
pub const EXPORT_DONE_IMM: u32 = 0x5D3; // "SanDal 3"
pub const EXPORT_DONE_FULL_IMM: u32 = 0x5D7; // the full-export done

/// Exit protocol signal (aarch64): the init BRKs with the session's exit
/// code in x15; the VMM reads the register at the trap (the marker-free
/// exit protocol — the old fixed `SANDAL_EXIT:<code>` stdout marker is
/// gone). The x86_64 carries the code in the hypercall store's high half.
pub const EXIT_IMM: u32 = 0x5D5; // "SanDal 5"

/// The command execution line's readiness (aarch64): vsockd's listener is
/// bound — the VMM connects every parked front end. The x86_64 stores the
/// same number to the hypercall page.
pub const VSOCKD_READY_IMM: u32 = 0x5D6;

/// Build the TEXT config injected into the rootfs as /etc/sandal.conf —
/// the one run-configuration channel on every platform (the x86_64 init
/// script sources it line-by-line; the aarch64 init parses the same file).
/// One field per run knob; the argument count mirrors the knobs, not a
/// design smell.
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
    script_only: bool,
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
    // The script sandbox (--script): the line rejects command lines and
    // serves whole script files; the VM powers off with the script's own
    // exit status.
    if script_only {
        out.push_str("SCRIPT=1\n");
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

// The `sandal-export` guest command is a compiled binary, not a
// generated script: the flow (the overlay-upper walk, the ustar, the
// resize/done hypercalls) lives in
// src/initramfs/tools/bin/export.rs, injected at ext2.rs's runtime
// files (usr/sbin/sandal-export).
