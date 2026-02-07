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
    #[allow(dead_code)]
    ino: u32,
    mode: u16,
    size: u32,
    data: Vec<u8>, // File content or symlink target
    links: u16,
    dev_major: u8,
    dev_minor: u8,
    children: BTreeMap<String, u32>, // For directories: name → inode
}

/// Build an ext2 filesystem image from a host directory.
/// Injects an /init script and device nodes automatically.
pub fn build_ext2_from_directory(
    dir: &Path,
    command: &[String],
    network: bool,
    use_8250_uart: bool,
) -> Result<Vec<u8>> {
    let mut builder = Ext2Builder::new();

    // Walk the host directory and add entries
    builder.add_directory_recursive(dir, dir, ROOT_INO)?;

    // Ensure essential directories exist
    for subdir in &["dev", "proc", "sys", "tmp", "etc", "root", "sbin", "bin"] {
        builder.ensure_dir(ROOT_INO, subdir);
    }

    // Add device nodes
    builder.add_chardev(ROOT_INO, "dev/console", 0o666, 5, 1);
    builder.add_chardev(ROOT_INO, "dev/null", 0o666, 1, 3);
    builder.add_chardev(ROOT_INO, "dev/zero", 0o666, 1, 5);
    builder.add_chardev(ROOT_INO, "dev/tty", 0o666, 5, 0);
    if use_8250_uart {
        builder.add_chardev(ROOT_INO, "dev/ttyS0", 0o666, 4, 64);
    } else {
        builder.add_chardev(ROOT_INO, "dev/ttyAMA0", 0o666, 204, 64);
    }

    // Inject host CA certificates for HTTPS support
    if network {
        if let Some(ca_data) = crate::initramfs::load_host_ca_certificates() {
            builder.ensure_dir(ROOT_INO, "etc/ssl/certs");
            builder.add_file_data(
                ROOT_INO,
                "etc/ssl/certs/ca-certificates.crt",
                &ca_data,
                0o644,
            );
        }
    }

    // Inject entropy seeder binary (needed for TLS/getrandom to work)
    let seeder_bin = crate::initramfs::generate_entropy_seeder();
    builder.ensure_dir(ROOT_INO, "usr/sbin");
    builder.add_file_data(ROOT_INO, "usr/sbin/seed-entropy", &seeder_bin, 0o755);

    // Generate and inject /init script
    let init_script = crate::initramfs::generate_init_script_ext(command, network);
    builder.add_file_data(ROOT_INO, "init", init_script.as_bytes(), 0o755);

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
                ino: ROOT_INO,
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
                        ino: new_ino,
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

    fn add_chardev(&mut self, parent_ino: u32, path: &str, perm: u16, major: u8, minor: u8) {
        // Ensure parent directory exists
        let parts: Vec<&str> = path.split('/').collect();
        let (dir_parts, name) = parts.split_at(parts.len() - 1);
        let name = name[0];
        let mut dir_ino = parent_ino;
        for part in dir_parts {
            dir_ino = self.ensure_dir(dir_ino, part);
        }

        // Check if already exists
        if self
            .entries
            .get(&dir_ino)
            .is_some_and(|e| e.children.contains_key(name))
        {
            return;
        }

        let ino = self.alloc_ino();
        self.entries.insert(
            ino,
            FsEntry {
                ino,
                mode: S_IFCHR | perm,
                size: 0,
                data: Vec::new(),
                links: 1,
                dev_major: major,
                dev_minor: minor,
                children: BTreeMap::new(),
            },
        );
        if let Some(dir) = self.entries.get_mut(&dir_ino) {
            dir.children.insert(name.to_string(), ino);
        }
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
                ino,
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
                        ino,
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
