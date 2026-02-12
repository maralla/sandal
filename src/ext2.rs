/// Minimal ext2 filesystem image builder.
///
/// Creates a small ext2 filesystem in memory from a host directory.
/// Only supports the subset needed for a VM rootfs:
/// - Regular files
/// - Directories
/// - Symlinks
/// - Character device nodes
///
/// Layout (4KB blocks):
///   Block 0: Boot record + superblock (at byte offset 1024)
///   Block 1: Block group descriptor table
///   Block 2: Data block bitmap
///   Block 3: Inode bitmap
///   Blocks 4..4+N: Inode table
///   Blocks 4+N+1..: Data blocks
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::initramfs;

const BLOCK_SIZE: usize = 4096;
const INODE_SIZE: usize = 128;
const SUPERBLOCK_OFFSET: usize = 1024;
const EXT2_SUPER_MAGIC: u16 = 0xEF53;

// Inode numbers
const ROOT_INO: u32 = 2;
const FIRST_FREE_INO: u32 = 11; // First non-reserved inode

// File type constants for directory entries
const EXT2_FT_UNKNOWN: u8 = 0;
const EXT2_FT_REG_FILE: u8 = 1;
const EXT2_FT_DIR: u8 = 2;
const EXT2_FT_CHRDEV: u8 = 3;
const EXT2_FT_SYMLINK: u8 = 7;

// Inode mode bits
const S_IFREG: u16 = 0o100000;
const S_IFDIR: u16 = 0o040000;
const S_IFCHR: u16 = 0o020000;
const S_IFLNK: u16 = 0o120000;

/// An entry to be written into the filesystem
struct FsEntry {
    mode: u16,
    size: u32,
    data: Vec<u8>, // File content or symlink target
    links: u16,
    dev_major: u8,
    dev_minor: u8,
    children: BTreeMap<String, u32>, // For directories: name → inode
}

/// Pack a host directory into a "base" ext2 image (no runtime files injected).
/// This is used by `sandal pack` to create a rootfs image from a directory.
/// Essential directories are ensured but /init, device nodes, CA certs, etc.
/// are NOT included — those are injected at runtime by `inject_runtime_files`.
pub fn pack_directory(dir: &Path) -> Result<Vec<u8>> {
    let mut builder = Ext2Builder::new();

    // Walk the host directory and add entries
    builder.add_directory_recursive(dir, dir, ROOT_INO)?;

    // Ensure essential directories exist
    for subdir in &[
        "dev", "proc", "sys", "tmp", "etc", "root", "sbin", "bin", "usr", "usr/sbin",
    ] {
        builder.ensure_dir(ROOT_INO, subdir);
    }

    // Build the image
    builder.build()
}

struct Ext2Builder {
    next_ino: u32,
    entries: BTreeMap<u32, FsEntry>,
}

impl Ext2Builder {
    fn new() -> Self {
        let mut entries = BTreeMap::new();

        // Create root directory (inode 2)
        entries.insert(
            ROOT_INO,
            FsEntry {
                mode: S_IFDIR | 0o755,
                size: 0,
                data: Vec::new(),
                links: 2, // . and parent
                dev_major: 0,
                dev_minor: 0,
                children: BTreeMap::new(),
            },
        );

        Ext2Builder {
            next_ino: FIRST_FREE_INO,
            entries,
        }
    }

    fn alloc_ino(&mut self) -> u32 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Ensure a directory path exists under parent_ino.
    /// Returns the inode of the (possibly created) directory.
    fn ensure_dir(&mut self, parent_ino: u32, name: &str) -> u32 {
        // Handle nested paths like "dev/pts"
        let parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
        let mut current_ino = parent_ino;
        for part in parts {
            let existing = self
                .entries
                .get(&current_ino)
                .and_then(|e| e.children.get(part).copied());
            if let Some(child_ino) = existing {
                current_ino = child_ino;
            } else {
                let new_ino = self.alloc_ino();
                self.entries.insert(
                    new_ino,
                    FsEntry {
                        mode: S_IFDIR | 0o755,
                        size: 0,
                        data: Vec::new(),
                        links: 2,
                        dev_major: 0,
                        dev_minor: 0,
                        children: BTreeMap::new(),
                    },
                );
                // Add to parent
                if let Some(parent) = self.entries.get_mut(&current_ino) {
                    parent.children.insert(part.to_string(), new_ino);
                    parent.links += 1;
                }
                current_ino = new_ino;
            }
        }
        current_ino
    }

    fn add_file_data(&mut self, parent_ino: u32, path: &str, data: &[u8], perm: u16) {
        let parts: Vec<&str> = path.split('/').collect();
        let (dir_parts, name) = parts.split_at(parts.len() - 1);
        let name = name[0];
        let mut dir_ino = parent_ino;
        for part in dir_parts {
            dir_ino = self.ensure_dir(dir_ino, part);
        }

        // Remove existing entry with same name
        if let Some(dir) = self.entries.get_mut(&dir_ino) {
            if let Some(old_ino) = dir.children.remove(name) {
                self.entries.remove(&old_ino);
            }
        }

        let ino = self.alloc_ino();
        self.entries.insert(
            ino,
            FsEntry {
                mode: S_IFREG | perm,
                size: data.len() as u32,
                data: data.to_vec(),
                links: 1,
                dev_major: 0,
                dev_minor: 0,
                children: BTreeMap::new(),
            },
        );
        if let Some(dir) = self.entries.get_mut(&dir_ino) {
            dir.children.insert(name.to_string(), ino);
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn add_directory_recursive(
        &mut self,
        base: &Path,
        current: &Path,
        parent_ino: u32,
    ) -> Result<()> {
        let read_dir = fs::read_dir(current)
            .with_context(|| format!("Failed to read directory {current:?}"))?;

        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // Skip /init — we inject our own
            if parent_ino == ROOT_INO && name == "init" {
                continue;
            }

            let metadata = fs::symlink_metadata(&path)?;
            let ft = metadata.file_type();

            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                let target_str = target.to_string_lossy().to_string();
                let ino = self.alloc_ino();
                self.entries.insert(
                    ino,
                    FsEntry {
                        mode: S_IFLNK | 0o777,
                        size: target_str.len() as u32,
                        data: target_str.into_bytes(),
                        links: 1,
                        dev_major: 0,
                        dev_minor: 0,
                        children: BTreeMap::new(),
                    },
                );
                if let Some(parent) = self.entries.get_mut(&parent_ino) {
                    parent.children.insert(name, ino);
                }
            } else if ft.is_dir() {
                let dir_ino = self.ensure_dir(parent_ino, &name);
                // Set permissions from host
                let perm = (metadata.permissions().mode() & 0o7777) as u16;
                if let Some(e) = self.entries.get_mut(&dir_ino) {
                    e.mode = S_IFDIR | perm;
                }
                self.add_directory_recursive(base, &path, dir_ino)?;
            } else if ft.is_file() {
                let data = fs::read(&path)?;
                let perm = (metadata.permissions().mode() & 0o7777) as u16;
                self.add_file_data(parent_ino, &name, &data, perm);
            }
            // Skip other file types
        }
        Ok(())
    }

    /// Calculate how many indirect meta-blocks a file of `data_blocks` needs.
    fn indirect_blocks_needed(data_blocks: usize) -> usize {
        let ptrs_per_block = BLOCK_SIZE / 4; // 1024 pointers per 4K block
        let mut meta = 0;
        if data_blocks > 12 {
            // Single indirect block
            meta += 1;
        }
        if data_blocks > 12 + ptrs_per_block {
            // Double indirect: 1 top + ceil((remaining) / ptrs_per_block)
            let remaining = data_blocks - 12 - ptrs_per_block;
            meta += 1 + remaining.div_ceil(ptrs_per_block);
        }
        meta
    }

    fn build(&self) -> Result<Vec<u8>> {
        // Ensure enough free inodes for runtime file creation (wget, tmp files, etc.)
        // At least 256 extra inodes beyond what the rootfs uses
        let num_inodes = (self.next_ino as usize + 256).max(512);
        let inode_table_blocks = (num_inodes * INODE_SIZE).div_ceil(BLOCK_SIZE);
        let first_data_block = 4 + inode_table_blocks; // after superblock, bgdt, bitmaps, inode table

        // First pass: figure out how many data blocks we need (including indirect blocks)
        let mut data_blocks_needed = 0usize;
        for entry in self.entries.values() {
            if entry.mode & 0xF000 == S_IFDIR {
                data_blocks_needed += 1; // One block per directory
            } else if entry.mode & 0xF000 == S_IFREG {
                let file_blocks = entry.data.len().div_ceil(BLOCK_SIZE).max(1);
                data_blocks_needed += file_blocks + Self::indirect_blocks_needed(file_blocks);
            }
            // Symlinks < 60 bytes stored inline, chardevs have no data blocks
        }

        // Add extra free space: at least 2MB (512 blocks) for temporary files, wget output, etc.
        let extra_blocks = 512.max(data_blocks_needed / 4); // 2MB or 25% of data, whichever is larger
        let total_blocks = first_data_block + data_blocks_needed + extra_blocks;
        let image_size = total_blocks * BLOCK_SIZE;
        let mut image = vec![0u8; image_size];

        // Assign data blocks to entries. Each entry gets a flat list of ALL blocks
        // (data + indirect meta-blocks). We'll sort them out in write_inodes_and_data.
        let mut block_map: BTreeMap<u32, Vec<u32>> = BTreeMap::new(); // ino → data blocks only
        let mut indirect_map: BTreeMap<u32, Vec<u32>> = BTreeMap::new(); // ino → indirect meta-blocks
        let mut next_block = first_data_block as u32;

        // Allocate blocks for directories first
        for (&ino, entry) in &self.entries {
            if entry.mode & 0xF000 == S_IFDIR {
                block_map.insert(ino, vec![next_block]);
                next_block += 1;
            }
        }

        // Allocate blocks for regular files (data blocks + indirect blocks)
        for (&ino, entry) in &self.entries {
            if entry.mode & 0xF000 == S_IFREG {
                let num_data = entry.data.len().div_ceil(BLOCK_SIZE).max(1);
                let data_blocks: Vec<u32> = (next_block..next_block + num_data as u32).collect();
                next_block += num_data as u32;

                let num_indirect = Self::indirect_blocks_needed(num_data);
                let ind_blocks: Vec<u32> = (next_block..next_block + num_indirect as u32).collect();
                next_block += num_indirect as u32;

                block_map.insert(ino, data_blocks);
                if !ind_blocks.is_empty() {
                    indirect_map.insert(ino, ind_blocks);
                }
            }
        }

        let used_blocks = next_block as usize;

        // Write superblock
        self.write_superblock(
            &mut image,
            total_blocks,
            num_inodes,
            used_blocks,
            first_data_block,
        );

        // Write block group descriptor
        self.write_bgdt(
            &mut image,
            num_inodes,
            used_blocks,
            first_data_block,
            inode_table_blocks,
        );

        // Write block bitmap
        self.write_block_bitmap(&mut image, used_blocks, total_blocks);

        // Write inode bitmap
        self.write_inode_bitmap(&mut image, num_inodes);

        // Write inodes (with indirect block pointers) and data
        self.write_inodes(&mut image, &block_map, &indirect_map);
        self.write_directory_data(&mut image, &block_map);
        self.write_file_data(&mut image, &block_map);

        Ok(image)
    }

    fn write_superblock(
        &self,
        image: &mut [u8],
        total_blocks: usize,
        num_inodes: usize,
        used_blocks: usize,
        _first_data_block: usize,
    ) {
        let sb = &mut image[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + 1024];

        let free_blocks = total_blocks - used_blocks;
        let free_inodes = num_inodes - (self.next_ino as usize - 1);

        // s_inodes_count
        write_le32(sb, 0, num_inodes as u32);
        // s_blocks_count
        write_le32(sb, 4, total_blocks as u32);
        // s_r_blocks_count (reserved)
        write_le32(sb, 8, 0);
        // s_free_blocks_count
        write_le32(sb, 12, free_blocks as u32);
        // s_free_inodes_count
        write_le32(sb, 16, free_inodes as u32);
        // s_first_data_block (0 for 4KB blocks)
        write_le32(sb, 20, 0);
        // s_log_block_size (log2(block_size) - 10 = log2(4096) - 10 = 2)
        write_le32(sb, 24, 2);
        // s_log_frag_size
        write_le32(sb, 28, 2);
        // s_blocks_per_group
        write_le32(sb, 32, total_blocks as u32);
        // s_frags_per_group
        write_le32(sb, 36, total_blocks as u32);
        // s_inodes_per_group
        write_le32(sb, 40, num_inodes as u32);
        // s_mtime, s_wtime
        write_le32(sb, 44, 0);
        write_le32(sb, 48, 0);
        // s_mnt_count
        write_le16(sb, 52, 0);
        // s_max_mnt_count
        write_le16(sb, 54, u16::MAX);
        // s_magic
        write_le16(sb, 56, EXT2_SUPER_MAGIC);
        // s_state (clean)
        write_le16(sb, 58, 1);
        // s_errors (continue)
        write_le16(sb, 60, 1);
        // s_minor_rev_level
        write_le16(sb, 62, 0);
        // s_lastcheck
        write_le32(sb, 64, 0);
        // s_checkinterval
        write_le32(sb, 68, 0);
        // s_creator_os (Linux)
        write_le32(sb, 72, 0);
        // s_rev_level (1 = dynamic revision for inode size)
        write_le32(sb, 76, 1);
        // s_def_resuid
        write_le16(sb, 80, 0);
        // s_def_resgid
        write_le16(sb, 82, 0);
        // == EXT2_DYNAMIC_REV fields ==
        // s_first_ino
        write_le32(sb, 84, FIRST_FREE_INO);
        // s_inode_size
        write_le16(sb, 88, INODE_SIZE as u16);
        // s_block_group_nr
        write_le16(sb, 90, 0);
        // s_feature_compat (EXT2_FEATURE_COMPAT_EXT_ATTR = 0x08)
        write_le32(sb, 92, 0);
        // s_feature_incompat (EXT2_FEATURE_INCOMPAT_FILETYPE = 0x02)
        write_le32(sb, 96, 0x02);
        // s_feature_ro_compat
        write_le32(sb, 100, 0);
        // s_uuid (16 bytes) - leave as zeros
        // s_volume_name (16 bytes)
        sb[120..128].copy_from_slice(b"sandal\0\0");
    }

    fn write_bgdt(
        &self,
        image: &mut [u8],
        num_inodes: usize,
        used_blocks: usize,
        _first_data_block: usize,
        _inode_table_blocks: usize,
    ) {
        let bgdt_offset = BLOCK_SIZE; // Block 1
        let total_blocks = image.len() / BLOCK_SIZE;
        let free_blocks = total_blocks - used_blocks;
        let free_inodes = num_inodes - (self.next_ino as usize - 1);
        let dir_count = self
            .entries
            .values()
            .filter(|e| e.mode & 0xF000 == S_IFDIR)
            .count();

        let bg = &mut image[bgdt_offset..bgdt_offset + 64]; // Use 64 bytes for ext4 compat

        // bg_block_bitmap
        write_le32(bg, 0, 2);
        // bg_inode_bitmap
        write_le32(bg, 4, 3);
        // bg_inode_table
        write_le32(bg, 8, 4);
        // bg_free_blocks_count
        write_le16(bg, 12, free_blocks as u16);
        // bg_free_inodes_count
        write_le16(bg, 14, free_inodes as u16);
        // bg_used_dirs_count
        write_le16(bg, 16, dir_count as u16);
        // bg_flags: EXT4_BG_INODE_ZEROED (0x4) — tells ext4 inode table is already zeroed
        write_le16(bg, 18, 0x0004);
        // bg_itable_unused_lo: number of unused inodes in the inode table
        write_le16(bg, 28, free_inodes as u16);
    }

    fn write_block_bitmap(&self, image: &mut [u8], used_blocks: usize, total_blocks: usize) {
        let bitmap_offset = 2 * BLOCK_SIZE; // Block 2
        let bitmap = &mut image[bitmap_offset..bitmap_offset + BLOCK_SIZE];

        // Mark used blocks as allocated
        for i in 0..used_blocks {
            bitmap[i / 8] |= 1 << (i % 8);
        }

        // Mark blocks beyond total_blocks as used (padding/reserved — required by ext2 spec)
        let bits_in_bitmap = BLOCK_SIZE * 8; // max blocks representable
        for i in total_blocks..bits_in_bitmap {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }

    fn write_inode_bitmap(&self, image: &mut [u8], num_inodes: usize) {
        let bitmap_offset = 3 * BLOCK_SIZE; // Block 3
        let bitmap = &mut image[bitmap_offset..bitmap_offset + BLOCK_SIZE];

        // Mark reserved inodes (1..FIRST_FREE_INO-1) as used
        for i in 0..(FIRST_FREE_INO as usize) {
            if i > 0 {
                bitmap[(i - 1) / 8] |= 1 << ((i - 1) % 8);
            }
        }

        // Mark allocated inodes
        for &ino in self.entries.keys() {
            let idx = (ino as usize) - 1;
            bitmap[idx / 8] |= 1 << (idx % 8);
        }

        // Mark inodes beyond num_inodes as used (padding — required by ext2 spec)
        let bits_in_bitmap = BLOCK_SIZE * 8;
        for i in num_inodes..bits_in_bitmap {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }

    fn write_inodes(
        &self,
        image: &mut [u8],
        block_map: &BTreeMap<u32, Vec<u32>>,
        indirect_map: &BTreeMap<u32, Vec<u32>>,
    ) {
        let inode_table_offset = 4 * BLOCK_SIZE;
        let ptrs_per_block = BLOCK_SIZE / 4; // 1024

        for (&ino, entry) in &self.entries {
            let inode_off = inode_table_offset + ((ino as usize - 1) * INODE_SIZE);

            // Write inode fields using direct offsets into image
            // i_mode
            write_le16(image, inode_off, entry.mode);
            // i_uid
            write_le16(image, inode_off + 2, 0);
            // i_size
            write_le32(image, inode_off + 4, entry.size);
            // i_atime, i_ctime, i_mtime, i_dtime
            write_le32(image, inode_off + 8, 0);
            write_le32(image, inode_off + 12, 0);
            write_le32(image, inode_off + 16, 0);
            write_le32(image, inode_off + 20, 0);
            // i_gid
            write_le16(image, inode_off + 24, 0);
            // i_links_count
            write_le16(image, inode_off + 26, entry.links);
            // i_blocks (512-byte blocks) — includes both data and indirect blocks
            let data_count = block_map.get(&ino).map_or(0, |b| b.len());
            let ind_count = indirect_map.get(&ino).map_or(0, |b| b.len());
            write_le32(
                image,
                inode_off + 28,
                ((data_count + ind_count) * (BLOCK_SIZE / 512)) as u32,
            );
            // i_flags, i_osd1
            write_le32(image, inode_off + 32, 0);
            write_le32(image, inode_off + 36, 0);

            if let Some(blocks) = block_map.get(&ino) {
                let n = blocks.len();

                // i_block[0..11] — direct block pointers
                for (i, &blk) in blocks.iter().take(12).enumerate() {
                    write_le32(image, inode_off + 40 + i * 4, blk);
                }

                if n > 12 {
                    // Need indirect blocks
                    let ind_blocks = indirect_map
                        .get(&ino)
                        .expect("indirect_map missing for large file");
                    let mut ind_idx = 0;

                    // i_block[12] — single indirect block
                    let single_ind_blk = ind_blocks[ind_idx];
                    ind_idx += 1;
                    write_le32(image, inode_off + 40 + 12 * 4, single_ind_blk);

                    // Fill single indirect block with pointers to data blocks 12..12+ptrs_per_block
                    let single_end = n.min(12 + ptrs_per_block);
                    let single_offset = single_ind_blk as usize * BLOCK_SIZE;
                    for (i, &blk) in blocks[12..single_end].iter().enumerate() {
                        write_le32(image, single_offset + i * 4, blk);
                    }

                    if n > 12 + ptrs_per_block {
                        // i_block[13] — double indirect block
                        let double_ind_blk = ind_blocks[ind_idx];
                        ind_idx += 1;
                        write_le32(image, inode_off + 40 + 13 * 4, double_ind_blk);

                        let double_offset = double_ind_blk as usize * BLOCK_SIZE;
                        let remaining = &blocks[12 + ptrs_per_block..];
                        let chunks: Vec<&[u32]> = remaining.chunks(ptrs_per_block).collect();

                        for (ci, chunk) in chunks.iter().enumerate() {
                            let level1_blk = ind_blocks[ind_idx];
                            ind_idx += 1;
                            // Write pointer to level1 block in double indirect
                            write_le32(image, double_offset + ci * 4, level1_blk);
                            // Fill level1 block with data block pointers
                            let l1_offset = level1_blk as usize * BLOCK_SIZE;
                            for (j, &blk) in chunk.iter().enumerate() {
                                write_le32(image, l1_offset + j * 4, blk);
                            }
                        }
                    }
                }
            } else if entry.mode & 0xF000 == S_IFCHR {
                // Device number in i_block[0] for character devices
                let dev = ((entry.dev_major as u32) << 8) | (entry.dev_minor as u32);
                write_le32(image, inode_off + 40, dev);
            } else if entry.mode & 0xF000 == S_IFLNK && entry.data.len() < 60 {
                // Short symlinks stored inline in i_block
                image[inode_off + 40..inode_off + 40 + entry.data.len()]
                    .copy_from_slice(&entry.data);
            }
        }
    }

    fn write_directory_data(&self, image: &mut [u8], block_map: &BTreeMap<u32, Vec<u32>>) {
        for (&ino, entry) in &self.entries {
            if entry.mode & 0xF000 != S_IFDIR {
                continue;
            }

            let blocks = match block_map.get(&ino) {
                Some(b) => b,
                None => continue,
            };
            let block_offset = blocks[0] as usize * BLOCK_SIZE;
            let dir_block = &mut image[block_offset..block_offset + BLOCK_SIZE];

            let mut offset = 0usize;

            // . entry
            offset += write_dirent(dir_block, offset, ino, ".", EXT2_FT_DIR, false);

            // .. entry (parent = self for root)
            let parent_ino = if ino == ROOT_INO {
                ROOT_INO
            } else {
                // Find parent by searching all directories
                self.find_parent(ino).unwrap_or(ROOT_INO)
            };
            offset += write_dirent(dir_block, offset, parent_ino, "..", EXT2_FT_DIR, false);

            // Child entries
            let child_names: Vec<String> = entry.children.keys().cloned().collect();
            for (i, name) in child_names.iter().enumerate() {
                let child_ino = entry.children[name];
                let child_entry = &self.entries[&child_ino];
                let ft = match child_entry.mode & 0xF000 {
                    x if x == S_IFREG => EXT2_FT_REG_FILE,
                    x if x == S_IFDIR => EXT2_FT_DIR,
                    x if x == S_IFCHR => EXT2_FT_CHRDEV,
                    x if x == S_IFLNK => EXT2_FT_SYMLINK,
                    _ => EXT2_FT_UNKNOWN,
                };
                let is_last = i == child_names.len() - 1;
                offset += write_dirent(dir_block, offset, child_ino, name, ft, is_last);
            }

            // If no children (only . and ..), make .. the last entry
            if child_names.is_empty() {
                // Re-write .. as last entry (expand its rec_len to fill the block)
                let remaining = BLOCK_SIZE - 12; // after "." entry (12 bytes)
                write_le16(&mut dir_block[12..], 4, remaining as u16);
            }

            // Update directory size in inode
            // (We need to update the FsEntry but since build() is &self, we set size via inode directly)
            let inode_table_offset = 4 * BLOCK_SIZE;
            let inode_off = inode_table_offset + ((ino as usize - 1) * INODE_SIZE);
            write_le32(image, inode_off + 4, BLOCK_SIZE as u32);
        }
    }

    fn write_file_data(&self, image: &mut [u8], block_map: &BTreeMap<u32, Vec<u32>>) {
        for (&ino, entry) in &self.entries {
            if entry.mode & 0xF000 != S_IFREG {
                continue;
            }
            if entry.data.is_empty() {
                continue;
            }

            let blocks = match block_map.get(&ino) {
                Some(b) => b,
                None => continue,
            };

            let mut remaining = &entry.data[..];
            for &blk in blocks {
                let block_offset = blk as usize * BLOCK_SIZE;
                let to_write = remaining.len().min(BLOCK_SIZE);
                image[block_offset..block_offset + to_write]
                    .copy_from_slice(&remaining[..to_write]);
                remaining = &remaining[to_write..];
            }
        }
    }

    fn find_parent(&self, child_ino: u32) -> Option<u32> {
        for (&ino, entry) in &self.entries {
            if entry.children.values().any(|&c| c == child_ino) {
                return Some(ino);
            }
        }
        None
    }
}

/// Write a directory entry. Returns the number of bytes written.
fn write_dirent(
    block: &mut [u8],
    offset: usize,
    ino: u32,
    name: &str,
    ft: u8,
    is_last: bool,
) -> usize {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len();
    // rec_len must be 4-byte aligned, minimum 8 + name_len
    let base_len = 8 + name_len;
    let rec_len = if is_last {
        // Last entry fills remaining block
        BLOCK_SIZE - offset
    } else {
        (base_len + 3) & !3
    };

    if offset + rec_len > BLOCK_SIZE {
        return 0;
    }

    let ent = &mut block[offset..offset + rec_len];
    // d_inode
    write_le32(ent, 0, ino);
    // d_rec_len
    write_le16(ent, 4, rec_len as u16);
    // d_name_len
    ent[6] = name_len as u8;
    // d_file_type
    ent[7] = ft;
    // d_name
    ent[8..8 + name_len].copy_from_slice(name_bytes);

    rec_len
}

fn write_le16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_le32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// ── ext2 Reader ──────────────────────────────────────────────────────

fn read_le16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

fn read_le32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

/// Parsed ext2 superblock — only the fields we need.
struct Ext2Superblock {
    inodes_count: u32,
    blocks_count: u32,
    block_size: usize,
    inode_size: usize,
    first_ino: u32,
}

impl Ext2Superblock {
    fn parse(image: &[u8]) -> Result<Self> {
        if image.len() < SUPERBLOCK_OFFSET + 256 {
            anyhow::bail!("Image too small for ext2 superblock");
        }
        let sb = &image[SUPERBLOCK_OFFSET..];
        let magic = read_le16(sb, 56);
        if magic != EXT2_SUPER_MAGIC {
            anyhow::bail!(
                "Not an ext2 image: magic=0x{:04x} (expected 0x{:04x})",
                magic,
                EXT2_SUPER_MAGIC
            );
        }
        let log_block_size = read_le32(sb, 24);
        let block_size = 1024usize << log_block_size;
        let inode_size = read_le16(sb, 88) as usize;
        let inode_size = if inode_size == 0 { 128 } else { inode_size };
        Ok(Ext2Superblock {
            inodes_count: read_le32(sb, 0),
            blocks_count: read_le32(sb, 4),
            block_size,
            inode_size,
            first_ino: read_le32(sb, 84),
        })
    }
}

/// Parsed block group descriptor — only the fields we need.
struct Ext2Bgd {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
}

impl Ext2Bgd {
    fn parse(image: &[u8], sb: &Ext2Superblock) -> Result<Self> {
        // Block group descriptor table is in the block after the superblock.
        let bgdt_offset = sb.block_size; // Block 1 for 4K blocks, or block 2 for 1K blocks
        if bgdt_offset + 32 > image.len() {
            anyhow::bail!("Image too small for block group descriptor");
        }
        let bg = &image[bgdt_offset..];
        Ok(Ext2Bgd {
            block_bitmap: read_le32(bg, 0),
            inode_bitmap: read_le32(bg, 4),
            inode_table: read_le32(bg, 8),
        })
    }
}

/// In-memory representation of a parsed ext2 inode.
struct Ext2Inode {
    mode: u16,
    size: u32,
    links_count: u16,
    block_ptrs: [u32; 15],
    dev_major: u8,
    dev_minor: u8,
}

impl Ext2Inode {
    fn parse(image: &[u8], sb: &Ext2Superblock, bgd: &Ext2Bgd, ino: u32) -> Result<Self> {
        if ino < 1 || ino > sb.inodes_count {
            anyhow::bail!("Inode number {} out of range (1..{})", ino, sb.inodes_count);
        }
        let idx = (ino - 1) as usize;
        let offset = bgd.inode_table as usize * sb.block_size + idx * sb.inode_size;
        if offset + sb.inode_size > image.len() {
            anyhow::bail!(
                "Inode {} at offset 0x{:x} extends past image (len=0x{:x})",
                ino,
                offset,
                image.len()
            );
        }
        let raw = &image[offset..];
        let mode = read_le16(raw, 0);
        let size = read_le32(raw, 4);
        let links_count = read_le16(raw, 26);
        let mut block_ptrs = [0u32; 15];
        for (i, ptr) in block_ptrs.iter_mut().enumerate() {
            *ptr = read_le32(raw, 40 + i * 4);
        }
        // For char devices, dev number is in block_ptrs[0]
        let dev = block_ptrs[0];
        let dev_major = ((dev >> 8) & 0xFF) as u8;
        let dev_minor = (dev & 0xFF) as u8;
        Ok(Ext2Inode {
            mode,
            size,
            links_count,
            block_ptrs,
            dev_major,
            dev_minor,
        })
    }

    fn is_dir(&self) -> bool {
        self.mode & 0xF000 == S_IFDIR
    }
    fn is_file(&self) -> bool {
        self.mode & 0xF000 == S_IFREG
    }
    fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == S_IFLNK
    }
    fn is_chardev(&self) -> bool {
        self.mode & 0xF000 == S_IFCHR
    }
}

/// Read file data from an ext2 inode, following direct/indirect block pointers.
fn read_inode_data(image: &[u8], sb: &Ext2Superblock, inode: &Ext2Inode) -> Vec<u8> {
    let size = inode.size as usize;
    if size == 0 {
        return Vec::new();
    }
    // Short symlinks are stored inline in block pointers area
    if inode.is_symlink() && size < 60 {
        let mut data = Vec::with_capacity(size);
        // The symlink target is stored in the block pointer bytes
        let raw_bytes: Vec<u8> = inode
            .block_ptrs
            .iter()
            .flat_map(|p| p.to_le_bytes())
            .collect();
        data.extend_from_slice(&raw_bytes[..size]);
        return data;
    }

    let bs = sb.block_size;
    let ptrs_per_block = bs / 4;
    let mut data = Vec::with_capacity(size);
    let mut remaining = size;

    // Collect all data block numbers
    let mut block_nums: Vec<u32> = Vec::new();

    // Direct blocks (0..11)
    for i in 0..12 {
        if remaining == 0 {
            break;
        }
        block_nums.push(inode.block_ptrs[i]);
        remaining = remaining.saturating_sub(bs);
    }

    // Single indirect (block_ptrs[12])
    if remaining > 0 && inode.block_ptrs[12] != 0 {
        let ind_off = inode.block_ptrs[12] as usize * bs;
        for i in 0..ptrs_per_block {
            if remaining == 0 {
                break;
            }
            let blk = read_le32(image, ind_off + i * 4);
            if blk == 0 {
                break;
            }
            block_nums.push(blk);
            remaining = remaining.saturating_sub(bs);
        }
    }

    // Double indirect (block_ptrs[13])
    if remaining > 0 && inode.block_ptrs[13] != 0 {
        let dind_off = inode.block_ptrs[13] as usize * bs;
        for i in 0..ptrs_per_block {
            if remaining == 0 {
                break;
            }
            let ind_blk = read_le32(image, dind_off + i * 4);
            if ind_blk == 0 {
                break;
            }
            let ind_off = ind_blk as usize * bs;
            for j in 0..ptrs_per_block {
                if remaining == 0 {
                    break;
                }
                let blk = read_le32(image, ind_off + j * 4);
                if blk == 0 {
                    break;
                }
                block_nums.push(blk);
                remaining = remaining.saturating_sub(bs);
            }
        }
    }

    // Read data from blocks
    remaining = size;
    for blk in block_nums {
        let off = blk as usize * bs;
        let to_read = remaining.min(bs);
        if off + to_read <= image.len() {
            data.extend_from_slice(&image[off..off + to_read]);
        }
        remaining -= to_read;
        if remaining == 0 {
            break;
        }
    }

    data
}

/// Directory entry as parsed from an ext2 directory block.
struct Ext2DirEntry {
    inode: u32,
    name: String,
}

/// Read directory entries from an ext2 directory inode.
fn read_dir_entries(image: &[u8], sb: &Ext2Superblock, inode: &Ext2Inode) -> Vec<Ext2DirEntry> {
    let data = read_inode_data(image, sb, inode);
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let ino = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(data[off + 4..off + 6].try_into().unwrap()) as usize;
        let name_len = data[off + 6] as usize;
        if rec_len == 0 {
            break;
        }
        if ino != 0 && name_len > 0 && off + 8 + name_len <= data.len() {
            let name = String::from_utf8_lossy(&data[off + 8..off + 8 + name_len]).to_string();
            if name != "." && name != ".." {
                entries.push(Ext2DirEntry { inode: ino, name });
            }
        }
        off += rec_len;
    }
    entries
}

/// An entry extracted from an ext2 image for conversion to cpio.
pub struct Ext2Entry {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub nlink: u32,
}

/// Walk the entire ext2 filesystem starting from root and collect all entries.
fn walk_ext2(image: &[u8], sb: &Ext2Superblock, bgd: &Ext2Bgd) -> Result<Vec<Ext2Entry>> {
    let mut entries = Vec::new();
    let mut stack: Vec<(u32, String)> = vec![(ROOT_INO, String::new())];

    while let Some((ino, prefix)) = stack.pop() {
        let inode = Ext2Inode::parse(image, sb, bgd, ino)?;
        if !inode.is_dir() {
            continue;
        }

        // Add the directory itself (skip root "")
        if !prefix.is_empty() {
            entries.push(Ext2Entry {
                path: prefix.clone(),
                mode: inode.mode as u32,
                data: Vec::new(),
                dev_major: 0,
                dev_minor: 0,
                nlink: inode.links_count as u32,
            });
        }

        let dir_entries = read_dir_entries(image, sb, &inode);
        // Sort for deterministic output
        let mut dir_entries = dir_entries;
        dir_entries.sort_by(|a, b| a.name.cmp(&b.name));

        for ent in dir_entries {
            let child_path = if prefix.is_empty() {
                ent.name.clone()
            } else {
                format!("{}/{}", prefix, ent.name)
            };

            let child_inode = Ext2Inode::parse(image, sb, bgd, ent.inode)?;

            if child_inode.is_dir() {
                // Push directory for later traversal
                stack.push((ent.inode, child_path));
            } else if child_inode.is_file() || child_inode.is_symlink() {
                let data = read_inode_data(image, sb, &child_inode);
                entries.push(Ext2Entry {
                    path: child_path,
                    mode: child_inode.mode as u32,
                    data,
                    dev_major: 0,
                    dev_minor: 0,
                    nlink: child_inode.links_count as u32,
                });
            } else if child_inode.is_chardev() {
                entries.push(Ext2Entry {
                    path: child_path,
                    mode: child_inode.mode as u32,
                    data: Vec::new(),
                    dev_major: child_inode.dev_major as u32,
                    dev_minor: child_inode.dev_minor as u32,
                    nlink: child_inode.links_count as u32,
                });
            }
        }
    }

    // Sort all entries by path for deterministic output
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

// ── ext2 In-place Modification ──────────────────────────────────────

/// Allocate a free block from the block bitmap. Returns the block number.
fn alloc_block(image: &mut [u8], sb: &Ext2Superblock, bgd: &Ext2Bgd) -> Result<u32> {
    let bitmap_off = bgd.block_bitmap as usize * sb.block_size;
    let total_blocks = sb.blocks_count as usize;

    for i in 0..total_blocks {
        let byte = image[bitmap_off + i / 8];
        if byte & (1 << (i % 8)) == 0 {
            // Free block found
            image[bitmap_off + i / 8] |= 1 << (i % 8);
            // Update superblock free_blocks_count
            let sb_off = SUPERBLOCK_OFFSET;
            let old = read_le32(image, sb_off + 12);
            write_le32(image, sb_off + 12, old.saturating_sub(1));
            // Update bgdt free_blocks_count
            let bgdt_off = sb.block_size;
            let old = read_le16(image, bgdt_off + 12);
            write_le16(image, bgdt_off + 12, old.saturating_sub(1));
            return Ok(i as u32);
        }
    }
    anyhow::bail!("No free blocks in ext2 image")
}

/// Allocate a free inode from the inode bitmap. Returns the inode number.
fn alloc_inode(image: &mut [u8], sb: &Ext2Superblock, bgd: &Ext2Bgd) -> Result<u32> {
    let bitmap_off = bgd.inode_bitmap as usize * sb.block_size;
    let total_inodes = sb.inodes_count as usize;

    // Start from first_ino (skip reserved inodes)
    for i in (sb.first_ino as usize - 1)..total_inodes {
        let byte = image[bitmap_off + i / 8];
        if byte & (1 << (i % 8)) == 0 {
            // Free inode found
            image[bitmap_off + i / 8] |= 1 << (i % 8);
            // Update superblock free_inodes_count
            let sb_off = SUPERBLOCK_OFFSET;
            let old = read_le32(image, sb_off + 16);
            write_le32(image, sb_off + 16, old.saturating_sub(1));
            // Update bgdt free_inodes_count
            let bgdt_off = sb.block_size;
            let old = read_le16(image, bgdt_off + 14);
            write_le16(image, bgdt_off + 14, old.saturating_sub(1));
            return Ok((i + 1) as u32); // inodes are 1-based
        }
    }
    anyhow::bail!("No free inodes in ext2 image")
}

/// Write an inode structure into the inode table.
#[allow(clippy::too_many_arguments)]
fn write_inode_raw(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    ino: u32,
    mode: u16,
    size: u32,
    links: u16,
    block_ptrs: &[u32],
    blocks_512: u32,
) {
    let idx = (ino - 1) as usize;
    let offset = bgd.inode_table as usize * sb.block_size + idx * sb.inode_size;

    // Zero the inode first
    for b in &mut image[offset..offset + sb.inode_size] {
        *b = 0;
    }

    write_le16(image, offset, mode);
    write_le32(image, offset + 4, size);
    write_le16(image, offset + 26, links);
    write_le32(image, offset + 28, blocks_512);

    for (i, &blk) in block_ptrs.iter().enumerate() {
        if i >= 15 {
            break;
        }
        write_le32(image, offset + 40 + i * 4, blk);
    }
}

/// Look up a name in a directory inode. Returns the child inode number if found.
fn dir_lookup(
    image: &[u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    dir_ino: u32,
    name: &str,
) -> Result<Option<u32>> {
    let inode = Ext2Inode::parse(image, sb, bgd, dir_ino)?;
    let entries = read_dir_entries(image, sb, &inode);
    for ent in entries {
        if ent.name == name {
            return Ok(Some(ent.inode));
        }
    }
    Ok(None)
}

/// Add a directory entry to an existing directory.
/// This appends to the directory's first data block by shrinking the last
/// entry's rec_len and inserting the new entry in the freed space.
fn add_dir_entry(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    dir_ino: u32,
    child_ino: u32,
    child_name: &str,
    child_ft: u8,
) -> Result<()> {
    let inode = Ext2Inode::parse(image, sb, bgd, dir_ino)?;
    if !inode.is_dir() || inode.block_ptrs[0] == 0 {
        anyhow::bail!(
            "add_dir_entry: inode {} is not a directory or has no data block",
            dir_ino
        );
    }

    let bs = sb.block_size;
    let block_off = inode.block_ptrs[0] as usize * bs;
    let dir_block = &mut image[block_off..block_off + bs];

    // Walk to the last entry
    let mut off = 0usize;
    let mut last_off = 0usize;
    while off < bs {
        let rec_len = u16::from_le_bytes(dir_block[off + 4..off + 6].try_into().unwrap()) as usize;
        if rec_len == 0 {
            break;
        }
        last_off = off;
        off += rec_len;
    }

    // Calculate the actual size of the last entry
    let last_name_len = dir_block[last_off + 6] as usize;
    let last_actual = (8 + last_name_len + 3) & !3; // 4-byte aligned
    let last_rec_len =
        u16::from_le_bytes(dir_block[last_off + 4..last_off + 6].try_into().unwrap()) as usize;
    let free_space = last_rec_len - last_actual;

    // Check if there's enough space for the new entry
    let new_name_len = child_name.len();
    let new_entry_size = (8 + new_name_len + 3) & !3;
    if free_space < new_entry_size {
        anyhow::bail!(
            "Not enough space in directory block for entry '{}' ({} needed, {} available)",
            child_name,
            new_entry_size,
            free_space,
        );
    }

    // Shrink last entry's rec_len to its actual size
    write_le16(dir_block, last_off + 4, last_actual as u16);

    // Write new entry at last_off + last_actual
    let new_off = last_off + last_actual;
    let new_rec_len = last_rec_len - last_actual; // fills remainder of block
    write_le32(dir_block, new_off, child_ino);
    write_le16(dir_block, new_off + 4, new_rec_len as u16);
    dir_block[new_off + 6] = new_name_len as u8;
    dir_block[new_off + 7] = child_ft;
    dir_block[new_off + 8..new_off + 8 + new_name_len].copy_from_slice(child_name.as_bytes());

    Ok(())
}

/// Ensure a directory exists at the given path under root. Creates intermediate
/// directories as needed. Returns the inode number of the leaf directory.
fn ensure_dir_path(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    path: &str,
) -> Result<u32> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut current_ino = ROOT_INO;

    for part in parts {
        match dir_lookup(image, sb, bgd, current_ino, part)? {
            Some(child_ino) => {
                current_ino = child_ino;
            }
            None => {
                // Create new directory
                let new_ino = alloc_inode(image, sb, bgd)?;
                let data_blk = alloc_block(image, sb, bgd)?;

                // Write inode for new directory
                write_inode_raw(
                    image,
                    sb,
                    bgd,
                    new_ino,
                    S_IFDIR | 0o755,
                    sb.block_size as u32,
                    2, // . and ..
                    &[data_blk],
                    (sb.block_size / 512) as u32,
                );

                // Initialize directory block with . and .. entries
                let bs = sb.block_size;
                let blk_off = data_blk as usize * bs;
                // Zero the block
                for b in &mut image[blk_off..blk_off + bs] {
                    *b = 0;
                }
                let dir_block = &mut image[blk_off..blk_off + bs];
                // . entry (12 bytes: 4+2+1+1+1+padding)
                write_le32(dir_block, 0, new_ino);
                write_le16(dir_block, 4, 12);
                dir_block[6] = 1; // name_len
                dir_block[7] = EXT2_FT_DIR;
                dir_block[8] = b'.';
                // .. entry (fills rest of block)
                write_le32(dir_block, 12, current_ino);
                write_le16(dir_block, 16, (bs - 12) as u16);
                dir_block[18] = 2; // name_len
                dir_block[19] = EXT2_FT_DIR;
                dir_block[20] = b'.';
                dir_block[21] = b'.';

                // Add entry in parent directory
                add_dir_entry(image, sb, bgd, current_ino, new_ino, part, EXT2_FT_DIR)?;

                // Update parent link count
                let parent_idx = (current_ino - 1) as usize;
                let parent_off =
                    bgd.inode_table as usize * sb.block_size + parent_idx * sb.inode_size;
                let old_links = read_le16(image, parent_off + 26);
                write_le16(image, parent_off + 26, old_links + 1);

                // Update bgdt used_dirs_count
                let bgdt_off = sb.block_size;
                let old_dirs = read_le16(image, bgdt_off + 16);
                write_le16(image, bgdt_off + 16, old_dirs + 1);

                current_ino = new_ino;
            }
        }
    }

    Ok(current_ino)
}

/// Write a regular file into the ext2 image. If the file already exists, it is
/// replaced (the old inode's blocks are not freed — this is acceptable for
/// injecting a handful of small runtime files).
fn inject_file(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    path: &str,
    data: &[u8],
    perm: u16,
) -> Result<()> {
    let parts: Vec<&str> = path.split('/').collect();
    let (dir_parts, file_name) = parts.split_at(parts.len() - 1);
    let file_name = file_name[0];

    // Ensure parent directory exists
    let dir_path = dir_parts.join("/");
    let dir_ino = if dir_path.is_empty() {
        ROOT_INO
    } else {
        ensure_dir_path(image, sb, bgd, &dir_path)?
    };

    // Check if file already exists
    let existing = dir_lookup(image, sb, bgd, dir_ino, file_name)?;
    if existing.is_some() {
        // Remove existing entry from directory and rewrite the new one.
        // For simplicity, we don't reclaim old blocks. Just allocate a new inode.
        remove_dir_entry(image, sb, bgd, dir_ino, file_name)?;
    }

    // Allocate inode
    let new_ino = alloc_inode(image, sb, bgd)?;

    // Allocate data blocks
    let bs = sb.block_size;
    let num_blocks = if data.is_empty() {
        1
    } else {
        data.len().div_ceil(bs)
    };
    let mut block_nums = Vec::with_capacity(num_blocks);
    for _ in 0..num_blocks {
        block_nums.push(alloc_block(image, sb, bgd)?);
    }

    // Write data to blocks
    let mut remaining = data;
    for &blk in &block_nums {
        let off = blk as usize * bs;
        let to_write = remaining.len().min(bs);
        // Zero the block first
        for b in &mut image[off..off + bs] {
            *b = 0;
        }
        image[off..off + to_write].copy_from_slice(&remaining[..to_write]);
        remaining = &remaining[to_write..];
    }

    // Handle indirect blocks if needed
    let mut inode_block_ptrs = [0u32; 15];
    let ptrs_per_block = bs / 4;

    if num_blocks <= 12 {
        for (i, &blk) in block_nums.iter().enumerate() {
            inode_block_ptrs[i] = blk;
        }
    } else {
        // Direct blocks
        for (i, &blk) in block_nums.iter().take(12).enumerate() {
            inode_block_ptrs[i] = blk;
        }
        // Single indirect
        let ind_blk = alloc_block(image, sb, bgd)?;
        inode_block_ptrs[12] = ind_blk;
        let ind_off = ind_blk as usize * bs;
        for b in &mut image[ind_off..ind_off + bs] {
            *b = 0;
        }
        let single_end = num_blocks.min(12 + ptrs_per_block);
        for (i, &blk) in block_nums[12..single_end].iter().enumerate() {
            write_le32(image, ind_off + i * 4, blk);
        }

        if num_blocks > 12 + ptrs_per_block {
            // Double indirect
            let dind_blk = alloc_block(image, sb, bgd)?;
            inode_block_ptrs[13] = dind_blk;
            let dind_off = dind_blk as usize * bs;
            for b in &mut image[dind_off..dind_off + bs] {
                *b = 0;
            }
            let remain_blocks = &block_nums[12 + ptrs_per_block..];
            for (ci, chunk) in remain_blocks.chunks(ptrs_per_block).enumerate() {
                let l1_blk = alloc_block(image, sb, bgd)?;
                write_le32(image, dind_off + ci * 4, l1_blk);
                let l1_off = l1_blk as usize * bs;
                for b in &mut image[l1_off..l1_off + bs] {
                    *b = 0;
                }
                for (j, &blk) in chunk.iter().enumerate() {
                    write_le32(image, l1_off + j * 4, blk);
                }
            }
        }
    }

    let blocks_512 = (num_blocks * (bs / 512)) as u32;
    write_inode_raw(
        image,
        sb,
        bgd,
        new_ino,
        S_IFREG | perm,
        data.len() as u32,
        1,
        &inode_block_ptrs,
        blocks_512,
    );

    // Add directory entry
    add_dir_entry(
        image,
        sb,
        bgd,
        dir_ino,
        new_ino,
        file_name,
        EXT2_FT_REG_FILE,
    )?;

    Ok(())
}

/// Inject a character device node into the ext2 image.
fn inject_chardev(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    path: &str,
    perm: u16,
    major: u8,
    minor: u8,
) -> Result<()> {
    let parts: Vec<&str> = path.split('/').collect();
    let (dir_parts, dev_name) = parts.split_at(parts.len() - 1);
    let dev_name = dev_name[0];

    let dir_path = dir_parts.join("/");
    let dir_ino = if dir_path.is_empty() {
        ROOT_INO
    } else {
        ensure_dir_path(image, sb, bgd, &dir_path)?
    };

    // Skip if already exists
    if dir_lookup(image, sb, bgd, dir_ino, dev_name)?.is_some() {
        return Ok(());
    }

    let new_ino = alloc_inode(image, sb, bgd)?;

    // Device number encoded in block_ptrs[0]
    let dev_num = ((major as u32) << 8) | (minor as u32);
    write_inode_raw(image, sb, bgd, new_ino, S_IFCHR | perm, 0, 1, &[dev_num], 0);

    add_dir_entry(image, sb, bgd, dir_ino, new_ino, dev_name, EXT2_FT_CHRDEV)?;

    Ok(())
}

/// Remove a directory entry by name from a directory's data block.
fn remove_dir_entry(
    image: &mut [u8],
    sb: &Ext2Superblock,
    bgd: &Ext2Bgd,
    dir_ino: u32,
    name: &str,
) -> Result<()> {
    let inode = Ext2Inode::parse(image, sb, bgd, dir_ino)?;
    if !inode.is_dir() || inode.block_ptrs[0] == 0 {
        return Ok(());
    }

    let bs = sb.block_size;
    let block_off = inode.block_ptrs[0] as usize * bs;

    let mut off = 0usize;
    let mut prev_off: Option<usize> = None;

    while off < bs {
        let rec_len = u16::from_le_bytes(
            image[block_off + off + 4..block_off + off + 6]
                .try_into()
                .unwrap(),
        ) as usize;
        if rec_len == 0 {
            break;
        }
        let name_len = image[block_off + off + 6] as usize;
        let ino = read_le32(image, block_off + off);
        if ino != 0 && name_len == name.len() {
            let entry_name = &image[block_off + off + 8..block_off + off + 8 + name_len];
            if entry_name == name.as_bytes() {
                // Found it. Merge its rec_len into the previous entry.
                if let Some(prev) = prev_off {
                    let prev_rec_len = u16::from_le_bytes(
                        image[block_off + prev + 4..block_off + prev + 6]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    write_le16(image, block_off + prev + 4, (prev_rec_len + rec_len) as u16);
                } else {
                    // First entry — just zero the inode to mark as deleted
                    write_le32(image, block_off + off, 0);
                }
                return Ok(());
            }
        }
        prev_off = Some(off);
        off += rec_len;
    }

    Ok(())
}

/// Inject all runtime files into a pre-built ext2 image.
/// This adds /init, device nodes, CA certificates, entropy seeder, ctty helper.
pub fn inject_runtime_files(
    image: &mut [u8],
    command: &[String],
    network: bool,
    use_8250_uart: bool,
) -> Result<()> {
    let sb = Ext2Superblock::parse(image)?;
    let bgd = Ext2Bgd::parse(image, &sb)?;

    // Ensure essential directories
    for dir in &["dev", "proc", "sys", "tmp", "etc", "root", "sbin", "bin"] {
        ensure_dir_path(image, &sb, &bgd, dir)?;
    }

    // Device nodes
    inject_chardev(image, &sb, &bgd, "dev/console", 0o666, 5, 1)?;
    inject_chardev(image, &sb, &bgd, "dev/null", 0o666, 1, 3)?;
    inject_chardev(image, &sb, &bgd, "dev/zero", 0o666, 1, 5)?;
    inject_chardev(image, &sb, &bgd, "dev/tty", 0o666, 5, 0)?;
    if use_8250_uart {
        inject_chardev(image, &sb, &bgd, "dev/ttyS0", 0o666, 4, 64)?;
    } else {
        inject_chardev(image, &sb, &bgd, "dev/ttyAMA0", 0o666, 204, 64)?;
    }

    // CA certificates
    if network {
        if let Some(ca_data) = initramfs::load_host_ca_certificates() {
            inject_file(
                image,
                &sb,
                &bgd,
                "etc/ssl/certs/ca-certificates.crt",
                &ca_data,
                0o644,
            )?;
        }
    }

    // Ctty helper binary
    let ctty_bin = initramfs::generate_ctty_helper();
    inject_file(image, &sb, &bgd, "usr/sbin/sandal-ctty", &ctty_bin, 0o755)?;

    // /init script
    let init_script = initramfs::generate_init_script_ext(command, network);
    inject_file(image, &sb, &bgd, "init", init_script.as_bytes(), 0o755)?;

    Ok(())
}

// ── ext2 to cpio conversion ─────────────────────────────────────────

/// Convert an ext2 image (with runtime files already injected) to a cpio
/// archive suitable for loading as initramfs.
pub fn ext2_to_cpio(image: &[u8]) -> Result<Vec<u8>> {
    let sb = Ext2Superblock::parse(image)?;
    let bgd = Ext2Bgd::parse(image, &sb)?;

    let entries = walk_ext2(image, &sb, &bgd)?;

    let mut archive = Vec::new();
    let mut ino: u32 = 300000;

    for entry in &entries {
        let mode = entry.mode;
        let nlink = entry.nlink;
        let (devmajor, devminor) = (entry.dev_major, entry.dev_minor);

        initramfs::write_cpio_entry(
            &mut archive,
            &entry.path,
            ino,
            mode,
            0,
            0,
            nlink,
            0,
            &entry.data,
            devmajor,
            devminor,
        )?;
        ino += 1;
    }

    // Trailer
    initramfs::write_cpio_entry(&mut archive, "TRAILER!!!", 0, 0, 0, 0, 1, 0, &[], 0, 0)?;

    // Pad to 512-byte boundary
    while archive.len() % 512 != 0 {
        archive.push(0);
    }

    Ok(archive)
}
