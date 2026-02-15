//! Generate a compiled ARM64 ELF binary to replace `/init` in the guest VM.
//!
//! The binary handles: mounting essential filesystems, loading kernel modules,
//! reading a config blob from the VMM via hypercall, setting up the overlayfs
//! root, configuring the network, and executing the user command.
//!
//! Both TTY variants (PL011 and 8250) are computed at compile time as `const`
//! byte arrays — the runtime cost of calling [`init_binary`] is zero.
//!
//! A set of declarative macros (defined in `elf/macros.rs`) makes the
//! builder read like ARM64 assembly rather than raw instruction emission.

use crate::elf::arm64::*;
use crate::elf::linux::*;
use crate::elf::ElfBuilder;
use crate::initramfs;

// ── Pre-computed ELF binaries (evaluated at compile time) ───────────────

const INIT_HVC0: ([u8; ElfBuilder::MAX_ELF], usize) = build_init("/dev/hvc0");

/// Return the pre-computed init binary for the given TTY device.
/// With virtio-console, only /dev/hvc0 is used.
pub fn init_binary(_tty_device: &str) -> &'static [u8] {
    &INIT_HVC0.0[..INIT_HVC0.1]
}

// ══════════════════════════════════════════════════════════════════════════
// Compile-time init binary generation
// ══════════════════════════════════════════════════════════════════════════

/// Build the complete /init ELF binary at compile time.
// ── Module path components (shared between strings! and emit_module_loading) ──
const MOD_PREFIX: &str = "/lib/modules/";
const MOD_KERNEL: &str = "/kernel/";
const MOD_VIRTIO_MMIO: &str = "drivers/virtio/virtio_mmio.ko";
const MOD_FAILOVER: &str = "net/core/failover.ko";
const MOD_NET_FAILOVER: &str = "drivers/net/net_failover.ko";
const MOD_VIRTIO_NET: &str = "drivers/net/virtio_net.ko";
const MOD_VIRTIO_RNG: &str = "drivers/char/hw_random/virtio-rng.ko";
const MOD_VIRTIO_BLK: &str = "drivers/block/virtio_blk.ko";
const MOD_VIRTIO_CONSOLE: &str = "drivers/char/virtio_console.ko";
const MOD_FUSE: &str = "fs/fuse/fuse.ko";
const MOD_VIRTIOFS: &str = "fs/fuse/virtiofs.ko";
const MOD_SUFFIXES: &[&str] = &[
    MOD_VIRTIO_MMIO,
    MOD_FAILOVER,
    MOD_NET_FAILOVER,
    MOD_VIRTIO_NET,
    MOD_VIRTIO_RNG,
    MOD_VIRTIO_BLK,
    MOD_VIRTIO_CONSOLE,
    MOD_FUSE,
    MOD_VIRTIOFS,
];

const ENV_PATH_VAR: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const CMD_NOT_FOUND_SUFFIX: &str = ": command not found\n";
const RESOLV_DATA: &str = "nameserver 10.0.2.3\n";

const fn build_init(tty_device: &str) -> ([u8; ElfBuilder::MAX_ELF], usize) {
    let mut e = ElfBuilder::new();

    // ── Data section strings ────────────────────────────────────────
    strings!(
        e,
        s_proc = "proc",
        s_proc_path = "/proc",
        s_sysfs = "sysfs",
        s_sys_path = "/sys",
        s_devtmpfs = "devtmpfs",
        s_dev_path = "/dev",
        s_tmpfs = "tmpfs",
        s_tmp_path = "/tmp",
        s_slash = "/",
        s_empty = "",
        s_dot = ".",
        s_mod_prefix = MOD_PREFIX,
        s_mod_kernel = MOD_KERNEL,
        s_mod_virtio_mmio = MOD_VIRTIO_MMIO,
        s_mod_failover = MOD_FAILOVER,
        s_mod_net_failover = MOD_NET_FAILOVER,
        s_mod_virtio_net = MOD_VIRTIO_NET,
        s_mod_virtio_rng = MOD_VIRTIO_RNG,
        s_mod_virtio_blk = MOD_VIRTIO_BLK,
        s_mod_fuse = MOD_FUSE,
        s_mod_virtiofs = MOD_VIRTIOFS,
        s_mnt_lower = initramfs::MNT_LOWER,
        s_mnt_overlay = initramfs::MNT_OVERLAY,
        s_mnt_tmp = initramfs::MNT_TMP,
        s_mnt_disk = initramfs::MNT_DISK,
        s_data_dev = initramfs::DATA_DEV,
        s_ext2 = "ext2",
        s_overlay_type = "overlay",
        s_mnt_root_rel = "mnt/root",
        s_virtiofs = "virtiofs",
        s_upper_dir = "upper",
        s_work_dir = "work",
        s_mnt_dir = "mnt",
        s_tty_dev = tty_device,
        s_lo = "lo",
        s_eth0 = "eth0",
        s_resolv_path = "/etc/resolv.conf",
        s_resolv_data = RESOLV_DATA,
        s_env_home = "HOME=/root",
        s_env_path = ENV_PATH_VAR,
        s_env_term = "TERM=linux",
        s_env_ssl = "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
        s_exit_marker = initramfs::EXIT_MARKER,
        s_cmd_not_found = CMD_NOT_FOUND_SUFFIX,
    );

    let s_ovl_opts_disk = e.emit_cstring_parts(&[
        "lowerdir=",
        initramfs::MNT_LOWER,
        ",upperdir=",
        initramfs::MNT_DISK,
        "/upper,workdir=",
        initramfs::MNT_DISK,
        "/work",
    ]);
    let s_ovl_opts_tmp = e.emit_cstring_parts(&[
        "lowerdir=",
        initramfs::MNT_LOWER,
        ",upperdir=",
        initramfs::MNT_TMP,
        "/upper,workdir=",
        initramfs::MNT_TMP,
        "/work",
    ]);
    let mod_suffixes: [usize; 8] = [
        s_mod_virtio_mmio,
        s_mod_failover,
        s_mod_net_failover,
        s_mod_virtio_net,
        s_mod_virtio_rng,
        s_mod_virtio_blk,
        s_mod_fuse,
        s_mod_virtiofs,
    ];

    // ════════════════════════════════════════════════════════════════
    // PHASE 1: Pre-snapshot — mount essentials + load modules
    // ════════════════════════════════════════════════════════════════

    mount!(e, s_proc, s_proc_path, s_proc);
    mount!(e, s_sysfs, s_sys_path, s_sysfs);
    mount!(e, s_devtmpfs, s_dev_path, s_devtmpfs);
    mount!(e, s_tmpfs, s_tmp_path, s_tmpfs);

    emit_module_loading(&mut e, s_mod_prefix, s_mod_kernel, &mod_suffixes, s_empty);

    chdir!(e, s_slash);

    // Put stdin into raw mode BEFORE the snapshot/config BRK so that
    // when the VMM pushes config bytes into the UART, the kernel's TTY
    // line discipline is already in raw mode.  This prevents canonical-
    // mode processing (ECHO, ICRNL, etc.) from corrupting binary data.
    sub!(e, SP, SP, 48); // termios struct at SP
    movz!(e, x0, 0);
    ioctl!(e, x0, TCGETS); // read termios from fd 0 into [SP]
    ldr_w!(e, x14, SP, 0); // save original c_iflag
    ldr_w!(e, x15, SP, 12); // save original c_lflag
    str_w!(e, XZR, SP, 0); // c_iflag = 0 (disable ICRNL etc.)
    str_w!(e, XZR, SP, 12); // c_lflag = 0 (disable ICANON, ECHO)
    movz!(e, x0, 0);
    ioctl!(e, x0, TCSETS); // apply raw mode
    add!(e, SP, SP, 48); // pop termios (x14/x15 hold saved flags)

    brk!(e, initramfs::SNAPSHOT_SIGNAL_IMM);

    // ════════════════════════════════════════════════════════════════
    // PHASE 2: Post-snapshot — read config, setup overlay, network
    // ════════════════════════════════════════════════════════════════

    // BRK #INIT_CONFIG — VMM pushes config blob and sets x0 = size
    brk!(e, initramfs::INIT_CONFIG_IMM);

    // Save config size, allocate exact buffer on stack.
    // Round up config size to 16-byte alignment for SP.
    mov!(e, x28, x0); // x28 = config size
    add!(e, x0, x0, 15);
    movz!(e, x9, 15);
    bic_reg!(e, x0, x0, x9); // x0 = align_up(config_size, 16)
    sub_sp_reg!(e, SP, SP, x0); // config buffer (exact size, aligned)
    add!(e, x19, SP, 0); // x19 = config buffer (can't use mov! for SP)

    // Read config blob from stdin (TTY already in raw mode)
    movz!(e, x26, 0); // x26 = bytes_read
    let read_loop = e.offset();
    movz!(e, x0, 0); // fd = stdin
    add_reg!(e, x1, x19, x26);
    sub_reg!(e, x2, x28, x26);
    syscall!(e, nr::READ);
    cmp!(e, x0, 1);
    let read_done_ph = e.emit_placeholder();
    add_reg!(e, x26, x26, x0);
    cmp_reg!(e, x26, x28);
    b_back!(e, b_lt, read_loop);
    patch_forward!(e, read_done_ph, b_lt);

    // Restore original TTY settings
    sub!(e, SP, SP, 48); // termios struct at SP
    movz!(e, x0, 0);
    ioctl!(e, x0, TCGETS); // read current termios
    str_w!(e, x14, SP, 0); // restore c_iflag
    str_w!(e, x15, SP, 12); // restore c_lflag
    movz!(e, x0, 0);
    ioctl!(e, x0, TCSETS); // apply restored settings
    add!(e, SP, SP, 48); // pop termios

    // Parse config header: disk_mode, num_virtiofs, num_argv, network, clock_secs
    ldrb!(e, x20, x19, 0); // x20 = disk_mode
    ldrb!(e, x21, x19, 1); // x21 = num_virtiofs
    ldrb!(e, x22, x19, 2); // x22 = num_argv
    ldrb!(e, x23, x19, 3); // x23 = network
    ldr!(e, x24, x19, 8); // x24 = clock_secs
    add!(e, x25, x19, 16); // x25 = variable data

    // ── Set clock ───────────────────────────────────────────────────
    sub!(e, SP, SP, 16);
    str_x!(e, x24, SP, 0); // tv_sec
    str_x!(e, XZR, SP, 8); // tv_nsec = 0
    clock_settime!(e, 0); // CLOCK_REALTIME
    add!(e, SP, SP, 16);

    // ── Network setup (conditional) ─────────────────────────────────
    let skip_net_ph = e.emit_placeholder();
    emit_network(&mut e, s_lo, s_eth0, s_resolv_path, s_resolv_data);
    patch_forward!(e, skip_net_ph, cbz, x23);

    // ── Overlay setup ───────────────────────────────────────────────
    mkdir!(e, s_mnt_lower);
    mkdir!(e, s_mnt_overlay);
    mkdir!(e, s_mnt_tmp);
    mkdir!(e, s_mnt_disk);

    mount_bind!(e, s_slash, s_mnt_lower);

    // Branch: disk mode vs tmpfs mode
    let disk_mode_ph = e.emit_placeholder();

    // ── TMPFS mode (disk_mode == 0) ─────────────────────────────
    mount!(e, s_tmpfs, s_mnt_tmp, s_tmpfs);
    mkdir_under!(e, s_mnt_tmp, s_upper_dir);
    mkdir_under!(e, s_mnt_tmp, s_work_dir);
    adr!(e, x9, s_ovl_opts_tmp);
    let tmpfs_done_ph = e.emit_placeholder();
    let tmpfs_done = e.offset();

    // ── DISK mode (disk_mode != 0) ──────────────────────────────
    e.patch(
        disk_mode_ph,
        cbnz(
            reg!(x20),
            ElfBuilder::branch_offset(disk_mode_ph, tmpfs_done),
        ),
    );
    mount!(e, s_data_dev, s_mnt_disk, s_ext2);
    mkdir_under!(e, s_mnt_disk, s_upper_dir);
    mkdir_under!(e, s_mnt_disk, s_work_dir);
    adr!(e, x9, s_ovl_opts_disk);

    // ── overlay_mount (converge, x9 = opts) ─────────────────────
    let overlay_mount = e.offset();
    e.patch(
        tmpfs_done_ph,
        b(ElfBuilder::branch_offset(tmpfs_done_ph, overlay_mount)),
    );

    mount!(e, s_overlay_type, s_mnt_overlay, s_overlay_type, 0, x9); // data = overlay options

    // pivot_root
    chdir!(e, s_mnt_overlay);
    mkdir!(e, s_mnt_dir);
    mkdir!(e, s_mnt_root_rel);
    pivot_root!(e, s_dot, s_mnt_root_rel);

    // Re-mount essential filesystems in new root
    mount!(e, s_proc, s_proc_path, s_proc);
    mount!(e, s_sysfs, s_sys_path, s_sysfs);
    mount!(e, s_devtmpfs, s_dev_path, s_devtmpfs);
    mount!(e, s_tmpfs, s_tmp_path, s_tmpfs);
    chdir!(e, s_slash);

    // ── Mount virtiofs shares from config ───────────────────────────
    movz!(e, x26, 0);
    let vfs_loop = e.offset();
    cmp_reg!(e, x26, x21);
    let vfs_done_ph = e.emit_placeholder();

    mov!(e, x9, x25); // x9 = tag
    let tag_scan = e.offset();
    ldrb_post!(e, x2, x25);
    b_back!(e, cbnz, x2, tag_scan);
    mov!(e, x10, x25); // x10 = path
    let path_scan = e.offset();
    ldrb_post!(e, x2, x25);
    b_back!(e, cbnz, x2, path_scan);

    // mkdir + mount virtiofs
    movn!(e, x0, AT_FDCWD_NEG);
    mov!(e, x1, x10);
    movz!(e, x2, 0x1ED);
    syscall!(e, nr::MKDIRAT);

    mov!(e, x0, x9);
    mov!(e, x1, x10);
    adr!(e, x2, s_virtiofs);
    movz!(e, x3, 0);
    movz!(e, x4, 0);
    syscall!(e, nr::MOUNT);

    add!(e, x26, x26, 1);
    b_back!(e, b, vfs_loop);
    patch_forward!(e, vfs_done_ph, b_ge);

    // ════════════════════════════════════════════════════════════════
    // PHASE 3: Execute the user command
    // ════════════════════════════════════════════════════════════════

    // Build argv[] + envp[] on stack.
    // Need (num_argv + 1 + 4 envs + 1 NULL) * 8 = (num_argv + 6) * 8 bytes.
    add!(e, x0, x22, 6); // x0 = num_argv + 6
    lsl!(e, x0, x0, 3); // x0 *= 8 (bytes per pointer)
    add!(e, x0, x0, 15);
    movz!(e, x9, 15);
    bic_reg!(e, x0, x0, x9); // align up to 16 bytes
    sub_sp_reg!(e, SP, SP, x0);
    mov!(e, x27, x25); // x27 = first argv string
    movz!(e, x26, 0);
    add!(e, x9, SP, 0); // x9 = argv write pointer

    let argv_loop = e.offset();
    cmp_reg!(e, x26, x22);
    let argv_done_ph = e.emit_placeholder();
    str_x!(e, x25, x9, 0);
    add!(e, x9, x9, 8);
    let arg_scan = e.offset();
    ldrb_post!(e, x2, x25);
    b_back!(e, cbnz, x2, arg_scan);
    add!(e, x26, x26, 1);
    b_back!(e, b, argv_loop);
    patch_forward!(e, argv_done_ph, b_ge);

    // argv NULL terminator
    str_x!(e, XZR, x9, 0);
    add!(e, x9, x9, 8);

    // Build envp[] at x9
    mov!(e, x10, x9); // x10 = envp start
    adr!(e, x0, s_env_home);
    str_x!(e, x0, x9, 0);
    add!(e, x9, x9, 8);
    adr!(e, x0, s_env_path);
    str_x!(e, x0, x9, 0);
    add!(e, x9, x9, 8);
    adr!(e, x0, s_env_term);
    str_x!(e, x0, x9, 0);
    add!(e, x9, x9, 8);
    adr!(e, x0, s_env_ssl);
    str_x!(e, x0, x9, 0);
    add!(e, x9, x9, 8);
    str_x!(e, XZR, x9, 0); // envp NULL

    // Signal VMM: config processing done, start forwarding output
    brk!(e, initramfs::INIT_READY_IMM);

    fork!(e);

    let child_ph = e.emit_placeholder(); // CBZ → child

    // ── Parent: wait + exit marker + reboot ─────────────────────────
    mov!(e, x27, x0); // x27 = child PID
    sub!(e, SP, SP, 16);
    wait4!(e, x27);

    // Extract exit code: (status >> 8) & 0xFF
    ldr_w!(e, x0, SP, 0);
    ubfx!(e, x0, x0, 8, 8);
    add!(e, SP, SP, 16);
    mov!(e, x15, x0); // x15 = exit code

    // Write "SANDAL_EXIT:<code>\n" to stdout
    sub!(e, SP, SP, 32);
    add!(e, x0, SP, 0); // x0 = buffer start (ADD reads SP correctly)
    adr!(e, x1, s_exit_marker);
    let marker_copy = e.offset();
    ldrb_post!(e, x2, x1);
    strb_post!(e, x2, x0);
    b_back!(e, cbnz, x2, marker_copy);
    sub!(e, x0, x0, 1); // back up over null

    // Convert exit code to decimal ASCII (hundreds, tens, ones)
    movz!(e, x9, 100);
    udiv!(e, x2, x15, x9);
    msub!(e, x15, x2, x9, x15);
    add!(e, x2, x2, 48);
    strb_post!(e, x2, x0);
    movz!(e, x9, 10);
    udiv!(e, x2, x15, x9);
    msub!(e, x15, x2, x9, x15);
    add!(e, x2, x2, 48);
    strb_post!(e, x2, x0);
    add!(e, x15, x15, 48);
    strb_post!(e, x15, x0);
    movz!(e, x2, 10); // '\n'
    strb_post!(e, x2, x0);

    // write(stdout, buf, len)
    add!(e, x1, SP, 0); // x1 = buffer start (ADD reads SP correctly)
    sub_reg!(e, x2, x0, x1); // x2 = length
    movz!(e, x0, 1); // fd = stdout
    syscall!(e, nr::WRITE);
    add!(e, SP, SP, 32);

    reboot!(e);
    exit!(e, 0); // fallback

    // ── Child process ───────────────────────────────────────────────
    let child_code = e.offset();
    e.patch(
        child_ph,
        cbz(reg!(x0), ElfBuilder::branch_offset(child_ph, child_code)),
    );

    setsid!(e);

    // Open TTY, set controlling terminal
    openat!(e, s_tty_dev, O_RDWR);
    mov!(e, x9, x0); // x9 = tty fd

    ioctl!(e, x9, TIOCSCTTY, 0);

    // dup3(fd, 0..2, 0)
    let mut newfd: u32 = 0;
    while newfd <= 2 {
        dup3!(e, x9, newfd);
        newfd += 1;
    }

    // close(fd) if fd > 2
    cmp!(e, x9, 3);
    let skip_close_ph = e.emit_placeholder();
    close!(e, x9);
    patch_forward!(e, skip_close_ph, b_lt);

    emit_exec_with_path(&mut e, s_env_path, s_cmd_not_found);

    e.build()
}

// ── Helper: load kernel modules via uname + finit_module ────────────────
const fn emit_module_loading(
    e: &mut ElfBuilder,
    prefix: usize,
    kernel: usize,
    modules: &[usize],
    empty: usize,
) {
    // Stack layout:
    //   [SP,            SP+PATH_BUF)     — scratch buffer for full module path
    //   [SP+PATH_BUF,   SP+PATH_BUF+UTS) — struct utsname (6 × 65 = 390 bytes)
    const UTS_FIELD: usize = 65; // __NEW_UTS_LEN (64) + NUL
    const UTS_SIZE: usize = 6 * UTS_FIELD; // sysname, nodename, release, version, machine, domainname
    const UTS_RELEASE_OFF: usize = 2 * UTS_FIELD; // release is the 3rd field

    // Compute max module path from the actual strings:
    //   prefix + release (≤64) + kernel + longest suffix + NUL
    let max_suffix = const_max_str_len(MOD_SUFFIXES);
    let path_buf: usize = align16(MOD_PREFIX.len() + 64 + MOD_KERNEL.len() + max_suffix + 1);
    let frame: usize = align16(path_buf + UTS_SIZE);

    sub!(e, SP, SP, frame as u32);

    uname!(e, SP, path_buf as u32);

    // Build base path: /lib/modules/<release>/kernel/
    add!(e, x0, SP, 0);
    adr!(e, x1, prefix);
    emit_strcpy(e);
    add!(e, x1, SP, (path_buf + UTS_RELEASE_OFF) as u32); // utsname.release
    emit_strcpy(e);
    adr!(e, x1, kernel);
    emit_strcpy(e);
    mov!(e, x19, x0); // x19 = base path end

    let mut i = 0;
    while i < modules.len() {
        mov!(e, x0, x19);
        adr!(e, x1, modules[i]);
        emit_strcpy_with_null(e);

        openat!(e, SP, O_RDONLY);

        cmp!(e, x0, 0);
        let skip_ph = e.emit_placeholder();
        mov!(e, x11, x0);

        finit_module!(e, x11, empty);
        close!(e, x11);

        patch_forward!(e, skip_ph, b_lt);
        i += 1;
    }

    add!(e, SP, SP, frame as u32);
}

/// Return the length of the longest string in `strs`.
const fn const_max_str_len(strs: &[&str]) -> usize {
    let mut max = 0;
    let mut i = 0;
    while i < strs.len() {
        if strs[i].len() > max {
            max = strs[i].len();
        }
        i += 1;
    }
    max
}

/// Return the length of the longest colon-separated component in `s`.
const fn max_colon_component_len(s: &str) -> usize {
    let b = s.as_bytes();
    let mut max = 0usize;
    let mut cur = 0usize;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b':' {
            if cur > max {
                max = cur;
            }
            cur = 0;
        } else {
            cur += 1;
        }
        i += 1;
    }
    // last segment
    if cur > max {
        max = cur;
    }
    max
}

/// Round `n` up to the next multiple of 16.
const fn align16(n: usize) -> usize {
    (n + 15) & !15
}

// ── Helper: strcpy [x1] → [x0] (excluding null) ────────────────────────
const fn emit_strcpy(e: &mut ElfBuilder) {
    let loop_start = e.offset();
    ldrb_post!(e, x2, x1);
    e.emit(cbz(reg!(x2), 3)); // skip STRB + B, land after loop
    strb_post!(e, x2, x0);
    b_back!(e, b, loop_start);
}

// ── Helper: strcpy [x1] → [x0] (including null) ────────────────────────
const fn emit_strcpy_with_null(e: &mut ElfBuilder) {
    let loop_start = e.offset();
    ldrb_post!(e, x2, x1);
    strb_post!(e, x2, x0);
    b_back!(e, cbnz, x2, loop_start);
}

// ── Helper: execve with PATH resolution ─────────────────────────────────
//
// At entry: x27 = command name, x10 = envp, argv[] at SP.
//
// If argv[0] contains '/', exec directly.
// Otherwise, parse s_env_path ("PATH=<dirs>"), try each colon-separated
// directory by constructing "<dir>/<cmd>" in a stack buffer and calling execve.
// Falls through to exit(127) if nothing works.
// Buffer = longest PATH dir + "/" + NAME_MAX + NUL, aligned to 16.
const EXEC_PATH_BUF: u32 = {
    let (_, dirs) = ENV_PATH_VAR.split_at(5); // skip "PATH="
    align16(max_colon_component_len(dirs) + 1 + NAME_MAX + 1) as u32
};

const fn emit_exec_with_path(e: &mut ElfBuilder, s_env_path: usize, s_cmd_not_found: usize) {
    // ── Scan argv[0] for '/' — if found, skip PATH search ────────
    mov!(e, x4, x27);
    let scan = e.offset();
    ldrb_post!(e, x5, x4);
    let no_slash_ph = e.emit_placeholder(); // CBZ x5 → path_search
    sub!(e, x5, x5, 0x2F); // x5 = byte - '/'
    b_back!(e, cbnz, x5, scan); // not '/', keep scanning
                                // Found '/' → skip to direct exec
    let has_slash_ph = e.emit_placeholder(); // B → direct_exec

    // ── PATH search ──────────────────────────────────────────────
    let path_search = e.offset();
    e.patch(
        no_slash_ph,
        cbz(
            reg!(x5),
            ElfBuilder::branch_offset(no_slash_ph, path_search),
        ),
    );

    adr!(e, x3, s_env_path);
    add!(e, x3, x3, 5); // skip "PATH="
    sub!(e, SP, SP, EXEC_PATH_BUF); // allocate path buffer

    let path_loop = e.offset();
    ldrb!(e, x5, x3, 0); // peek: end of PATH?
    let path_done_ph = e.emit_placeholder(); // CBZ x5 → path_done

    // Copy directory to buffer until ':' or null
    add!(e, x0, SP, 0);
    let copy_dir = e.offset();
    ldrb_post!(e, x5, x3);
    let null_ph = e.emit_placeholder(); // CBZ x5 → copy_done (null)
    sub!(e, x6, x5, 0x3A); // x6 = x5 - ':'
    let colon_ph = e.emit_placeholder(); // CBZ x6 → copy_done (colon)
    strb_post!(e, x5, x0);
    b_back!(e, b, copy_dir);

    // copy_done — x5: 0 = end of PATH string, 0x3A = colon (more entries)
    let copy_done = e.offset();
    e.patch(
        null_ph,
        cbz(reg!(x5), ElfBuilder::branch_offset(null_ph, copy_done)),
    );
    e.patch(
        colon_ph,
        cbz(reg!(x6), ElfBuilder::branch_offset(colon_ph, copy_done)),
    );

    mov!(e, x14, x5); // remember: 0 = last entry, non-zero = more

    // Append '/' then command name (with null)
    movz!(e, x5, 0x2F); // '/'
    strb_post!(e, x5, x0);
    mov!(e, x1, x27);
    emit_strcpy_with_null(e);

    // Try execve(buffer, argv @ SP+EXEC_PATH_BUF, envp @ x10)
    execve!(e, SP + 0, SP + EXEC_PATH_BUF, x10);

    // Failed — if more entries (colon), loop back; else done
    b_back!(e, cbnz, x14, path_loop);

    // path_done: all PATH entries exhausted
    let path_done = e.offset();
    e.patch(
        path_done_ph,
        cbz(reg!(x5), ElfBuilder::branch_offset(path_done_ph, path_done)),
    );
    add!(e, SP, SP, EXEC_PATH_BUF); // free path buffer

    // ── Direct exec (absolute/relative path, or PATH exhausted) ──
    let direct_exec = e.offset();
    e.patch(
        has_slash_ph,
        b(ElfBuilder::branch_offset(has_slash_ph, direct_exec)),
    );

    execve!(e, x27, x10);

    // ── Command not found — write "<cmd>: command not found\n" to stderr ──
    strlen!(e, x27);
    sys_write!(e, 2, x27);
    sys_write!(e, 2, s_cmd_not_found, CMD_NOT_FOUND_SUFFIX.len() as u32);
    exit!(e, 127);
}

// ── Helper: static IP network setup ─────────────────────────────────────
const fn emit_network(
    e: &mut ElfBuilder,
    s_lo: usize,
    s_eth0: usize,
    s_resolv_path: usize,
    s_resolv_data: usize,
) {
    // The buffer is shared by struct ifreq (40 bytes) and struct rtentry.
    // On aarch64, sizeof(struct rtentry) ≈ 120 bytes (includes pointers,
    // padding for 8-byte alignment).  The kernel's SIOCADDRT handler does
    // copy_from_user of the full struct, so we must allocate at least that
    // much.  128 = next 16-byte aligned value ≥ 120.
    const NET_BUF: u32 = 128;

    socket!(e, AF_INET, SOCK_DGRAM);
    mov!(e, x27, x0); // x27 = sock fd

    sub!(e, SP, SP, NET_BUF);
    zero_stack!(e, NET_BUF / 8);

    // ── lo: IFF_UP ──────────────────────────────────────────────────
    add!(e, x0, SP, 0);
    adr!(e, x1, s_lo);
    emit_strcpy_with_null(e);
    movz!(e, x0, IFF_UP);
    strh!(e, x0, SP, 16);
    ioctl!(e, x27, SIOCSIFFLAGS);

    // ── eth0: IP address ────────────────────────────────────────────
    zero_stack!(e, NET_BUF / 8);
    add!(e, x0, SP, 0);
    adr!(e, x1, s_eth0);
    emit_strcpy_with_null(e);
    movz!(e, x0, AF_INET);
    strh!(e, x0, SP, 16);
    movz_w!(e, x0, 0x000A);
    movk_w!(e, x0, 0x0F02, 16); // 10.0.2.15
    str_w!(e, x0, SP, 20);
    ioctl!(e, x27, SIOCSIFADDR);

    // ── eth0: netmask ───────────────────────────────────────────────
    movz_w!(e, x0, 0xFFFF);
    movk_w!(e, x0, 0x00FF, 16); // 255.255.255.0
    str_w!(e, x0, SP, 20);
    ioctl!(e, x27, SIOCSIFNETMASK);

    // ── eth0: IFF_UP ────────────────────────────────────────────────
    str_x!(e, XZR, SP, 16);
    movz!(e, x0, IFF_UP);
    strh!(e, x0, SP, 16);
    ioctl!(e, x27, SIOCSIFFLAGS);

    // ── Default route via 10.0.2.2 ──────────────────────────────────
    zero_stack!(e, NET_BUF / 8);
    movz!(e, x0, AF_INET);
    strh!(e, x0, SP, 24);
    movz_w!(e, x0, 0x000A);
    movk_w!(e, x0, 0x0202, 16); // 10.0.2.2
    str_w!(e, x0, SP, 28);
    movz!(e, x0, AF_INET);
    strh!(e, x0, SP, 8);
    strh!(e, x0, SP, 40);
    movz!(e, x0, RTF_UP | RTF_GATEWAY);
    strh!(e, x0, SP, 56);
    ioctl!(e, x27, SIOCADDRT);

    add!(e, SP, SP, NET_BUF);
    close!(e, x27);

    // ── /etc/resolv.conf ────────────────────────────────────────────
    openat!(e, s_resolv_path, O_WRONLY | O_CREAT | O_TRUNC, 0x1A4);
    mov!(e, x11, x0);
    sys_write!(e, x11, s_resolv_data, RESOLV_DATA.len() as u32);
    close!(e, x11);
}
