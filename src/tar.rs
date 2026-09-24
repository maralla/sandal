/// Minimal tar archive reader.
///
/// Supports reading raw tar archives (for finding the end of a tar written
/// to a block device) and parsing gzip-compressed tar archives (.layer files).
///
/// Only handles regular files, directories, and symlinks — sufficient for
/// the `.layer` format used by `sandal-export`.
use anyhow::{Context, Result};

/// Tar entry types we support.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TarEntryType {
    File,
    Directory,
    Symlink,
}

/// A single entry in a tar archive.
#[derive(Debug, Clone)]
pub struct TarEntry {
    pub path: String,
    pub mode: u16,
    pub entry_type: TarEntryType,
    pub link_target: String,
    pub data: Vec<u8>,
}

/// Read a zstd-compressed tar archive (.layer file) and return parsed entries.
///
/// Decompresses the zstd layer, then parses each tar header to extract
/// files, directories, and symlinks.  Used by the host to inject layer
/// contents into an ext2 disk image.
pub fn read_tar_zst(zst_data: &[u8]) -> Result<Vec<TarEntry>> {
    let tar_data = zstd::decode_all(zst_data).context("Failed to decompress .layer zstd data")?;

    parse_tar(&tar_data)
}

/// Return the total uncompressed data size of all file entries.
/// Used to estimate the ext2 disk size needed to hold all layer content.
pub fn total_data_size(entries: &[TarEntry]) -> usize {
    entries.iter().map(|e| e.data.len()).sum()
}

/// Return the length of the uncompressed tar archive in `data` (header +
/// payload + the two terminating zero blocks), or `data.len()` if no
/// end-of-archive marker is found.  Used for tars that the guest wrote
/// directly to a raw block device (`sandal-export` in tmpfs mode).
pub fn find_tar_end(data: &[u8]) -> usize {
    let block_size = 512;
    if data.len() < block_size * 2 {
        return data.len();
    }

    let zero_block = [0u8; 512];
    let mut i = 0;
    while i + block_size * 2 <= data.len() {
        if data[i..i + block_size] == zero_block
            && data[i + block_size..i + block_size * 2] == zero_block
        {
            return i + block_size * 2;
        }

        // Skip past this entry: parse size from the header to jump over data.
        if data[i..i + block_size] != zero_block {
            let size = parse_octal(&data[i + 124..i + 136]);
            let data_blocks = size.div_ceil(block_size);
            i += block_size + data_blocks * block_size;
        } else {
            i += block_size;
        }
    }

    data.len()
}

/// Serialize entries as an uncompressed ustar archive.
///
/// Used by `sandal-export` to turn the overlay upper directory (read back out
/// of the ext2 data disk) into a `.layer` payload before gzip compression.
pub fn write_tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        let (name, prefix) = split_ustar_path(&e.path);
        let typeflag = match e.entry_type {
            TarEntryType::File => b'0',
            TarEntryType::Directory => b'5',
            TarEntryType::Symlink => b'2',
        };
        let link = e.link_target.as_bytes();
        let size = if e.entry_type == TarEntryType::File {
            e.data.len()
        } else {
            0
        };

        let mut h = [0u8; 512];
        write_field(&mut h[0..100], name.as_bytes());
        write_octal(&mut h[100..108], e.mode as u64);
        write_octal(&mut h[108..116], 0);
        write_octal(&mut h[116..124], 0);
        write_octal(&mut h[124..136], size as u64);
        write_octal(&mut h[136..148], 0);
        h[148..156].copy_from_slice(b"        "); // chksum placeholder (spaces)
        h[156] = typeflag;
        write_field(&mut h[157..257], link);
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        write_field(&mut h[345..500], prefix.as_bytes());

        let checksum: u32 = h.iter().map(|&b| b as u32).sum();
        let sum = format!("{checksum:06o}\0 ");
        h[148..156].copy_from_slice(sum.as_bytes());
        out.extend_from_slice(&h);

        if size > 0 {
            out.extend_from_slice(&e.data);
            let pad = (512 - size % 512) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
    }
    out.extend_from_slice(&[0u8; 1024]); // end-of-archive
    out
}

/// Split a path into (name, ustar prefix) so `name` fits in 100 bytes.
///
/// ustar allows a prefix of up to 155 bytes and a name of up to 100 bytes,
/// so the split must happen at a '/' whose index is in
/// `[len - 101, 155]`.  Prefer the last such slash (longest prefix).
fn split_ustar_path(path: &str) -> (String, String) {
    let len = path.len();
    if len <= 100 {
        return (path.to_string(), String::new());
    }

    let lo = len.saturating_sub(101);
    let mut split = None;
    for (i, c) in path.char_indices() {
        if c == '/' && i >= lo && i <= 155 {
            split = Some(i);
        }
    }
    if let Some(pos) = split {
        return (path[pos + 1..].to_string(), path[..pos].to_string());
    }

    // Fallback for an over-long single component: keep the last 100 bytes at
    // a char boundary (no prefix fits).
    let start = path
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| len - i <= 100)
        .unwrap_or(len);
    (path[start..].to_string(), String::new())
}

/// Copy `value` into `field`, truncating to fit and NUL-terminating.
fn write_field(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len().saturating_sub(1));
    field[..n].copy_from_slice(&value[..n]);
}

/// Write a NUL-terminated octal number into `field` (7 digits + NUL max).
fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let s = format!("{value:0width$o}");
    let bytes = s.as_bytes();
    let start = if bytes.len() > width {
        bytes.len() - width
    } else {
        0
    };
    field[field.len() - 1] = 0;
    let n = (field.len() - 1).min(bytes.len() - start);
    field[..n].copy_from_slice(&bytes[start..start + n]);
}

/// Parse an uncompressed tar archive into a list of entries.
fn parse_tar(data: &[u8]) -> Result<Vec<TarEntry>> {
    let block = 512;
    let zero_block = [0u8; 512];
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos + block <= data.len() {
        // Check for end-of-archive (two consecutive zero blocks)
        if data[pos..pos + block] == zero_block {
            break;
        }

        let header = &data[pos..pos + block];

        // Parse name (0..100) + prefix (345..500) for ustar
        let name_raw = &header[0..100];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&name_raw[..name_end])
            .unwrap_or("")
            .to_string();

        let prefix_raw = &header[345..500];
        let prefix_end = prefix_raw.iter().position(|&b| b == 0).unwrap_or(155);
        let prefix = std::str::from_utf8(&prefix_raw[..prefix_end])
            .unwrap_or("")
            .to_string();

        let full_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        // Normalize: strip leading "./" and trailing "/"
        let path = full_path
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_string();

        // Skip empty paths (the "." directory entry)
        if path.is_empty() {
            let size = parse_octal(&header[124..136]);
            let data_blocks = size.div_ceil(block);
            pos += block + data_blocks * block;
            continue;
        }

        // Mode (100..108)
        let mode = parse_octal(&header[100..108]) as u16;

        // Size (124..136)
        let size = parse_octal(&header[124..136]);

        // Typeflag (156)
        let typeflag = header[156];
        let entry_type = match typeflag {
            b'0' | 0 => TarEntryType::File,
            b'5' => TarEntryType::Directory,
            b'2' => TarEntryType::Symlink,
            _ => {
                // Skip unsupported types (hard links, block devs, etc.)
                let data_blocks = size.div_ceil(block);
                pos += block + data_blocks * block;
                continue;
            }
        };

        // Linkname (157..257) for symlinks
        let link_target = if entry_type == TarEntryType::Symlink {
            let link_raw = &header[157..257];
            let link_end = link_raw.iter().position(|&b| b == 0).unwrap_or(100);
            std::str::from_utf8(&link_raw[..link_end])
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };

        // Read file data
        let file_data = if entry_type == TarEntryType::File && size > 0 {
            let data_start = pos + block;
            let data_end = data_start + size;
            if data_end > data.len() {
                break; // Truncated archive
            }
            data[data_start..data_end].to_vec()
        } else {
            Vec::new()
        };

        entries.push(TarEntry {
            path,
            mode,
            entry_type,
            link_target,
            data: file_data,
        });

        // Advance past header + data (padded to 512-byte boundary)
        let data_blocks = size.div_ceil(block);
        pos += block + data_blocks * block;
    }

    Ok(entries)
}

/// Parse an octal string from a tar header field.
fn parse_octal(field: &[u8]) -> usize {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .filter(|&&b| (b'0'..=b'7').contains(&b))
        .map(|&b| b as char)
        .collect();
    usize::from_str_radix(&s, 8).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, data: &[u8], mode: u16) -> TarEntry {
        TarEntry {
            path: path.to_string(),
            mode,
            entry_type: TarEntryType::File,
            link_target: String::new(),
            data: data.to_vec(),
        }
    }

    fn dir(path: &str) -> TarEntry {
        TarEntry {
            path: path.to_string(),
            mode: 0o755,
            entry_type: TarEntryType::Directory,
            link_target: String::new(),
            data: Vec::new(),
        }
    }

    fn symlink(path: &str, target: &str) -> TarEntry {
        TarEntry {
            path: path.to_string(),
            mode: 0o777,
            entry_type: TarEntryType::Symlink,
            link_target: target.to_string(),
            data: Vec::new(),
        }
    }

    #[test]
    fn ustar_roundtrip_all_entry_types() {
        let entries = vec![
            dir("etc"),
            file("etc/config", b"key=value\n", 0o644),
            symlink("etc/link", "config"),
            file("empty", b"", 0o600),
        ];
        let tar = write_tar(&entries);
        let parsed = parse_tar(&tar).expect("parse generated tar");

        assert_eq!(parsed.len(), entries.len());
        assert_eq!(parsed[0].path, "etc");
        assert_eq!(parsed[0].entry_type, TarEntryType::Directory);
        assert_eq!(parsed[1].path, "etc/config");
        assert_eq!(parsed[1].data, b"key=value\n");
        assert_eq!(parsed[1].mode, 0o644);
        assert_eq!(parsed[2].entry_type, TarEntryType::Symlink);
        assert_eq!(parsed[2].link_target, "config");
        assert_eq!(parsed[3].path, "empty");
        assert_eq!(parsed[3].data, Vec::<u8>::new());
    }

    #[test]
    fn ustar_checksum_is_valid() {
        let tar = write_tar(&[file("a.txt", b"hello", 0o644)]);
        let header = &tar[..512];
        let stored = parse_octal(&header[148..156]);
        let computed: u32 = header
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    b' ' as u32
                } else {
                    b as u32
                }
            })
            .sum();
        assert_eq!(stored, computed as usize);
        // ustar magic
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(&header[263..265], b"00");
    }

    #[test]
    fn ustar_long_paths_split_and_roundtrip() {
        // A path longer than the 100-byte name field must use the ustar
        // prefix field and still round-trip exactly.
        let long_path = format!("root/{}/{}.txt", "d".repeat(120), "f".repeat(60));
        assert!(long_path.len() > 100);
        let (name, prefix) = split_ustar_path(&long_path);
        assert!(name.len() <= 100, "name too long: {name}");
        assert!(prefix.len() <= 155, "prefix too long: {prefix}");
        assert_eq!(format!("{prefix}/{name}"), long_path);

        let ta = write_tar(&[file(&long_path, b"long", 0o644)]);
        let parsed = parse_tar(&ta).expect("parse tar with long path");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path, long_path);
        assert_eq!(parsed[0].data, b"long");
    }

    #[test]
    fn find_tar_end_ignores_trailing_device_space() {
        let tar = write_tar(&[file("a", b"abc", 0o644), dir("d")]);
        assert_eq!(find_tar_end(&tar), tar.len());

        let mut with_junk = tar.clone();
        with_junk.extend_from_slice(&[0xAA; 4096]);
        assert_eq!(find_tar_end(&with_junk), tar.len());
    }

    #[test]
    fn zstd_layer_roundtrip() {
        // `read_tar_zst` (host layer loader) must accept what `write_tar`
        // produces after zstd compression.
        use std::io::Write;

        let entries = vec![dir("bin"), file("bin/tool", b"#!/bin/sh\n", 0o755)];
        let tar = write_tar(&entries);
        let mut enc = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        enc.write_all(&tar).unwrap();
        let zst = enc.finish().unwrap();

        let parsed = read_tar_zst(&zst).expect("read generated .layer");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "bin");
        assert_eq!(parsed[1].path, "bin/tool");
        assert_eq!(parsed[1].data, b"#!/bin/sh\n");
    }
}
