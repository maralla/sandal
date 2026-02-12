//! Built-in minimal rootfs (busybox + musl) embedded as gzip-compressed ext2.
//!
//! This allows sandal to work out of the box with no external files.
//! Users who need a richer environment (Python, etc.) can override with `--rootfs`.

use std::io::Read;

/// Gzip-compressed minimal ext2 rootfs image.
pub const BUILTIN_ROOTFS_GZ: &[u8] = include_bytes!("rootfs.ext2.gz");

/// Decompress and return the built-in rootfs as a raw ext2 image.
pub fn load() -> Vec<u8> {
    let mut decoder = flate2::read::GzDecoder::new(BUILTIN_ROOTFS_GZ);
    let mut image = Vec::new();
    decoder
        .read_to_end(&mut image)
        .expect("Failed to decompress built-in rootfs");
    image
}
