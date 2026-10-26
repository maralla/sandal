//! The `sandal-export` guest binary: turns the overlay upper directory
//! into the tar archive the VMM consumes as a `.layer` file.
//!
//! Rust replaces the busybox shell script — the flow is syscall-shaped
//! (walk, tar, two hypercalls) and the tar writing is where the script
//! was thinnest (exclusions, device buffering). Both architectures:
//!
//! 1. Find the overlay upper (the disk mode's ext2 upper, else the
//!    tmpfs one).
//! 2. The requested layer name (argv[1]) rides the marker file
//!    `.sandal-layer-name` in the upper — the VMM consumes it,
//!    sanitizes it hard, and filters it from the layer content.
//! 3. Disk mode: sync (the ext2's dirty page cache must reach the
//!    VMM's image), signal DONE — the VMM reads the upper straight off
//!    the device.
//! 4. Tmpfs mode: signal RESIZE (grow /dev/vdb), poll for the new
//!    size, write a ustar of the upper onto the device, sync, signal
//!    DONE.
//!
//! The tar: ustar with the prefix field, in exactly the VMM's own
//! writer's conventions (crate::tar) — the archive round-trips through
//! the VMM's parser. `tmp/` at the upper root is excluded (workspace
//! scratch; the VMM filters it again on its side).

#![no_std]
#![no_main]

mod common;

use common::*;

#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! {
    exit(126)
}

// ── The ustar writer: the VMM's own field conventions ──────────────

const BLOCK: usize = 512;
const CHUNK: usize = 16 * 1024;
const O_DIRECTORY: usize = 0o200000;
const NAME_CAP: usize = 100;
const PREFIX_CAP: usize = 155;
const PATH_CAP: usize = 512;
const DEPTH_CAP: u32 = 32;

fn write_field(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len() - 1);
    field[..n].copy_from_slice(&value[..n]);
}

/// Zero-padded octal, NUL-terminated; the high digits drop first when
/// the value outgrows the field (the VMM's writer does the same).
fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let mut digits = [0u8; 24];
    let mut n = 0usize;
    let mut v = value;
    loop {
        digits[n] = b'0' + (v % 8) as u8;
        n += 1;
        v /= 8;
        if v == 0 {
            break;
        }
    }
    let take = n.min(width);
    field[..width].fill(b'0');
    field[width] = 0;
    for i in 0..take {
        field[width - 1 - i] = digits[i];
    }
}

/// One 512-byte ustar header, checksummed: the VMM's writer's exact
/// field layout, so the archive parses back to the same entries.
fn write_header(
    h: &mut [u8; BLOCK],
    name: &[u8],
    prefix: &[u8],
    mode: u16,
    size: u64,
    typeflag: u8,
    link: &[u8],
) {
    h.fill(0);
    write_field(&mut h[0..100], name);
    write_octal(&mut h[100..108], mode as u64);
    write_octal(&mut h[108..116], 0); // uid
    write_octal(&mut h[116..124], 0); // gid
    write_octal(&mut h[124..136], size);
    write_octal(&mut h[136..148], 0); // mtime
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    write_field(&mut h[157..257], link);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    write_field(&mut h[345..500], prefix);
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    for i in 0..6 {
        h[148 + i] = b'0' + ((sum >> ((5 - i) * 3)) & 7) as u8;
    }
    h[154] = 0;
    h[155] = b' ';
}

/// Split a path into (name ≤ 100, prefix ≤ 155) at the last '/' that
/// fits — the VMM's writer's rule, so its parser joins the same path
/// back. None: no split fits (the entry is skipped with a note).
fn ustar_split(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= NAME_CAP {
        return Some((path, &[]));
    }
    let mut i = path.len();
    while i > 0 {
        i -= 1;
        if path[i] == b'/' {
            let name = &path[i + 1..];
            if i <= PREFIX_CAP && !name.is_empty() && name.len() <= NAME_CAP {
                return Some((&path[..i], name));
            }
        }
    }
    None
}

// ── The small syscall-shaped helpers ────────────────────────────────

fn path_exists(path: &[u8]) -> bool {
    let fd = open(path, O_RDONLY, 0);
    if fd < 0 {
        return false;
    }
    close(fd);
    true
}

fn join<'a>(buf: &'a mut [u8], base: &[u8], name: &[u8]) -> &'a [u8] {
    let mut i = base.len().min(buf.len() - 2);
    buf[..i].copy_from_slice(&base[..i]);
    if i > 0 && buf[i - 1] != b'/' {
        buf[i] = b'/';
        i += 1;
    }
    let n = name.len().min(buf.len() - i - 1);
    buf[i..i + n].copy_from_slice(&name[..n]);
    &buf[..i + n]
}

/// read(2) a small file whole (bounded by `buf`).
fn read_file_whole<'a>(path: &[u8], buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let fd = open(path, O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let n = read(fd, buf);
    close(fd);
    if n <= 0 {
        return None;
    }
    Some(&buf[..n as usize])
}

fn disk_mode() -> bool {
    let mut buf = [0u8; 16 * 1024];
    let Some(data) = read_file_whole(b"/proc/mounts\0", &mut buf) else {
        return false;
    };
    for line in data.split(|&b| b == b'\n') {
        if line.starts_with(b"/dev/vdb ")
            && line.windows(5).any(|w| w == b" ext2")
        {
            return true;
        }
    }
    false
}

/// The /dev/vdb size in sectors, parsed from the sysfs attr.
fn dev_size() -> u64 {
    let mut buf = [0u8; 32];
    let Some(data) = read_file_whole(b"/sys/block/vdb/size\0", &mut buf) else {
        return 0;
    };
    let mut v: u64 = 0;
    for &b in data {
        if !b.is_ascii_digit() {
            break;
        }
        v = v * 10 + (b - b'0') as u64;
    }
    v
}

/// The RESIZE poll: the config-change IRQ lands the new capacity within
/// a few polls; 5 s of 100 ms slices is generous.
fn wait_resize() -> bool {
    for _ in 0..50 {
        if dev_size() > 4096 {
            return true;
        }
        nanosleep(0, 100_000_000);
    }
    false
}

fn note_skip(path: &[u8], why: &[u8]) {
    let _ = write(2, b"sandal-export: skipping ");
    let _ = write(2, path);
    let _ = write(2, b": ");
    let _ = write(2, why);
    let _ = write(2, b"\n");
}

// ── The tree walk: the ustar onto the export device ─────────────────

fn export_file(abs: &[u8], rel: &[u8], mode: u16, dev: i32) -> bool {
    let Some((name, prefix)) = ustar_split(rel) else {
        note_skip(abs, b"the path fits no ustar split");
        return true; // soft: keep the export going
    };
    let fd = open(abs, O_RDONLY, 0);
    if fd < 0 {
        note_skip(abs, b"unreadable");
        return true;
    }
    // The size first (the header precedes the data), then back to 0.
    let size = lseek(fd, 0, 2);
    if size < 0 {
        close(fd);
        note_skip(abs, b"unseekable");
        return true;
    }
    let _ = lseek(fd, 0, 0);

    let mut h = [0u8; BLOCK];
    write_header(&mut h, name, prefix, mode, size as u64, b'0', &[]);
    if !write_chunk_blocking(dev, &h) {
        close(fd);
        return false;
    }
    let mut chunk = [0u8; CHUNK];
    let mut left = size as u64;
    let mut ok = true;
    while left > 0 {
        let want = (left as usize).min(CHUNK);
        let n = read(fd, &mut chunk[..want]);
        if n <= 0 && n != -EINTR {
            ok = false;
            break;
        }
        if n > 0 {
            if !write_chunk_blocking(dev, &chunk[..n as usize]) {
                ok = false;
                break;
            }
            left -= n as u64;
        }
    }
    close(fd);
    if ok && size % 512 != 0 {
        let pad = (BLOCK - size as usize % BLOCK) % BLOCK;
        let zeros = [0u8; BLOCK];
        ok = write_chunk_blocking(dev, &zeros[..pad]);
    }
    ok
}

fn export_symlink(abs: &[u8], rel: &[u8], mode: u16, dev: i32) -> bool {
    let Some((name, prefix)) = ustar_split(rel) else {
        note_skip(abs, b"the path fits no ustar split");
        return true;
    };
    let mut target = [0u8; 512];
    let n = readlinkat(AT_FDCWD as i32, abs, &mut target);
    if n <= 0 {
        note_skip(abs, b"unreadable link");
        return true;
    }
    let mut h = [0u8; BLOCK];
    write_header(&mut h, name, prefix, mode, 0, b'2', &target[..n as usize]);
    write_chunk_blocking(dev, &h)
}

fn export_dir(path: &[u8], mode: u16, dev: i32) -> bool {
    let Some((name, prefix)) = ustar_split(path) else {
        note_skip(path, b"the path fits no ustar split");
        return true;
    };
    let mut h = [0u8; BLOCK];
    write_header(&mut h, name, prefix, mode, 0, b'5', &[]);
    write_chunk_blocking(dev, &h)
}

/// Walk `rel` (relative to the upper root; empty at the root) and write
/// the ustar onto `dev`. Returns false only when the export device
/// failed — entry-level failures are soft (noted, skipped).
fn export_tree(rel: &[u8], depth: u32, dev: i32, upper: &[u8]) -> bool {
    if depth >= DEPTH_CAP {
        note_skip(rel, b"too deep");
        return true;
    }
    let mut abs_buf = [0u8; PATH_CAP];
    let abs = if rel.is_empty() {
        upper
    } else {
        join(&mut abs_buf, upper, rel)
    };
    let dirfd = open(abs, O_RDONLY | O_DIRECTORY, 0);
    if dirfd < 0 {
        note_skip(abs, b"cannot open the directory");
        return true;
    }
    let mut ents = [0u8; 4096];
    let mut ok = true;
    loop {
        let n = getdents64(dirfd, &mut ents);
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let rec = &ents[off..];
            let reclen = u16::from_le_bytes([rec[16], rec[17]]) as usize;
            if reclen == 0 || off + reclen > n as usize {
                break;
            }
            let name_all = &rec[19..off + reclen];
            let name = &name_all[..name_all.iter().position(|&b| b == 0).unwrap_or(0)];
            off += reclen;
            if name.is_empty() || name == b"." || name == b".." {
                continue;
            }
            // The workspace scratch never exports (the VMM filters it
            // again on its side).
            if depth == 0 && name == b"tmp" {
                continue;
            }
            // The child's relative and absolute paths.
            let mut rel_buf = [0u8; PATH_CAP];
            let child_rel = if rel.is_empty() {
                let n = name.len().min(rel_buf.len() - 1);
                rel_buf[..n].copy_from_slice(name);
                &rel_buf[..n]
            } else {
                join(&mut rel_buf, rel, name)
            };
            let mut abs_buf = [0u8; PATH_CAP];
            let child_abs = join(&mut abs_buf, upper, child_rel);

            // The real mode bits (statx is arch-independent, unlike
            // struct stat); the type rides the mode's S_IFMT.
            let mut sb = [0u8; 256];
            let have = statx(
                AT_FDCWD as i32,
                child_abs,
                STATX_SYMLINK_NOFOLLOW,
                0x7ff,
                &mut sb,
            ) >= 0;
            let mode_bits = if have {
                u16::from_le_bytes([sb[STATX_MODE_OFF], sb[STATX_MODE_OFF + 1]])
            } else {
                0
            };
            let kind = mode_bits & 0xF000;
            match kind {
                0x4000 => {
                    // A directory: the entry, then the subtree.
                    if ok && !export_dir(child_rel, mode_bits & 0o7777, dev) {
                        ok = false;
                    }
                    if ok && !export_tree(child_rel, depth + 1, dev, upper) {
                        ok = false;
                    }
                }
                0xA000 => {
                    if ok && !export_symlink(child_abs, child_rel, mode_bits & 0o7777, dev) {
                        ok = false;
                    }
                }
                0x8000 => {
                    if ok && !export_file(child_abs, child_rel, mode_bits & 0o7777, dev) {
                        ok = false;
                    }
                }
                _ => note_skip(child_abs, b"unsupported file type"),
            }
        }
    }
    close(dirfd);
    ok
}

// ── The flow ────────────────────────────────────────────────────────

const UPPER_DISK: &[u8] = b"/mnt/root/mnt/diskupper/upper\0";
const UPPER_TMP: &[u8] = b"/mnt/root/mnt/tmpupper/upper\0";

fn run(full: bool, name: Option<&[u8]>) -> usize {
    // 1. The overlay upper: the disk mode's, else the tmpfs one. The
    //    consts are NUL-terminated (open wants the C string); the upper
    //    slice strips it (join copies bytes, no NUL wanted).
    let upper = if path_exists(UPPER_DISK) {
        &UPPER_DISK[..UPPER_DISK.len() - 1]
    } else if path_exists(UPPER_TMP) {
        &UPPER_TMP[..UPPER_TMP.len() - 1]
    } else {
        let _ = write(2, b"sandal-export: cannot find overlay upper directory\n");
        return 1;
    };

    // 2. The requested layer name rides the marker file; the VMM
    //    consumes it and filters it from the layer content.
    if let Some(n) = name {
        let mut p_buf = [0u8; PATH_CAP];
        let p = join(&mut p_buf, upper, b".sandal-layer-name");
        let mut p_nul = [0u8; PATH_CAP];
        p_nul[..p.len()].copy_from_slice(p);
        let fd = open(&p_nul, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
        if fd >= 0 {
            write_chunk_blocking(fd, n);
            close(fd);
        }
    }

    // 3. Disk mode: the VMM reads the ext2 upper straight off the
    //    device — the dirty page cache must reach it first.
    if disk_mode() {
        sync();
        if full {
            signal_done_full();
        } else {
            signal_done();
        }
        let _ = write(2, b"Layer exported (disk mode).\n");
        return 0;
    }

    // 4. Tmpfs mode: grow the device, tar the upper onto it, signal.
    signal_resize();
    if !wait_resize() {
        let _ = write(2, b"sandal-export: /dev/vdb never grew\n");
        return 1;
    }
    let dev = open(b"/dev/vdb\0", O_WRONLY, 0);
    if dev < 0 {
        let _ = write(2, b"sandal-export: cannot open /dev/vdb\n");
        return 1;
    }
    let ok = export_tree(b"", 0, dev, upper);
    close(dev);
    if !ok {
        let _ = write(2, b"sandal-export: the device write failed\n");
        return 1;
    }
    // The tar went out over virtio-blk; the page cache still sits
    // between the guest's writes and the device — flush it.
    sync();
    if full {
        signal_done_full();
    } else {
        signal_done();
    }
    let _ = write(2, b"Layer exported.\n");
    0
}

#[no_mangle]
pub extern "C" fn guest_entry(rsp: usize) -> ! {
    // The hypercall page's address rides the HYPERCALL env (the x86_64
    // MMIO window moves with --memory; there is no correct static
    // fallback). The signal helpers need it; capture before anything.
    capture_env(rsp);
    // The CLI: sandal-export [--full] [name]. --full: the VMM merges
    // the specified layers with the upper into one consolidated layer;
    // without it the export is the upper alone (the diff, whiteouts
    // included).
    let argc = unsafe { (rsp as *const usize).read() };
    let mut full = false;
    let mut name: Option<&'static [u8]> = None;
    for k in 1..argc.min(8) {
        let p = unsafe { (rsp as *const usize).add(1 + k).read() } as *const u8;
        if p.is_null() {
            break;
        }
        let mut n = 0usize;
        while n < 128 && unsafe { p.add(n).read() } != 0 {
            n += 1;
        }
        let arg = unsafe { core::slice::from_raw_parts(p, n) };
        if arg == b"--full" {
            full = true;
        } else if name.is_none() {
            name = Some(arg);
        }
    }
    let code = run(full, name);
    exit(code)
}
