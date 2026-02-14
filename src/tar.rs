/// Minimal tar archive reader.
///
/// Supports reading raw tar archives (for finding the end of a tar written
/// to a block device) and parsing gzip-compressed tar archives (.layer files).
///
/// Only handles regular files, directories, and symlinks — sufficient for
/// the `.layer` format used by `sandal-export`.
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;

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

/// Find the end of a raw tar archive in a byte buffer.
///
/// Tar archives are terminated by two consecutive 512-byte all-zero blocks.
/// Returns the byte offset just past the end-of-archive marker.
/// If no valid end is found, returns the buffer length.
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

        // Skip past this entry: parse size from header to jump over data
        if data[i..i + block_size] != zero_block {
            let size = parse_octal(&data[i + 124..i + 136]);
            let data_blocks = size.div_ceil(block_size);
            i += block_size + data_blocks * block_size;
        } else {
            // Single zero block but not double — advance one block
            i += block_size;
        }
    }

    data.len()
}

/// Read a gzip-compressed tar archive (.layer file) and return parsed entries.
///
/// Decompresses the gzip layer, then parses each tar header to extract
/// files, directories, and symlinks.  Used by the host to inject layer
/// contents into an ext2 disk image.
pub fn read_tar_gz(gz_data: &[u8]) -> Result<Vec<TarEntry>> {
    let mut decoder = GzDecoder::new(gz_data);
    let mut tar_data = Vec::new();
    decoder
        .read_to_end(&mut tar_data)
        .context("Failed to decompress .layer gzip data")?;

    parse_tar(&tar_data)
}

/// Return the total uncompressed data size of all file entries.
/// Used to estimate the ext2 disk size needed to hold all layer content.
pub fn total_data_size(entries: &[TarEntry]) -> usize {
    entries.iter().map(|e| e.data.len()).sum()
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
