//! Built-in minimal rootfs (busybox + musl) embedded as zstd-compressed ext2.
//!
//! This allows sandal to work out of the box with no external files.
//! Users who need a richer environment (Python, etc.) can override with `--rootfs`.
//!
//! zstd (not gzip) is used for the embedded blob: the VMM decompresses it on
//! every VM start, and zstd decodes ~3x faster than gzip at a similar ratio
//! (~10ms off the boot time). The `.layer` archives keep using gzip — their
//! format is part of the export/load interface.

/// zstd-compressed minimal ext2 rootfs image.
pub const BUILTIN_ROOTFS_ZST: &[u8] = include_bytes!("rootfs.ext2.zst");

/// Decompress and return the built-in rootfs as a raw ext2 image.
pub fn load() -> Vec<u8> {
    // Single-shot decode with a capacity hint: `decode_all` streams into a
    // growing Vec (a dozen realloc-copies of the accumulated data). The
    // hint is an upper bound on the image size; fall back to the streaming
    // path if a future rootfs outgrows it.
    match zstd::bulk::decompress(BUILTIN_ROOTFS_ZST, 64 * 1024 * 1024) {
        Ok(img) => img,
        Err(_) => {
            zstd::decode_all(BUILTIN_ROOTFS_ZST).expect("Failed to decompress built-in rootfs")
        }
    }
}
