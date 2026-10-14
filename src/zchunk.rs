//! The chunked zstd container for `.layer` files.
//!
//! A `.layer` is a zstd-compressed tar. A single zstd frame is inherently
//! sequential — no multi-threaded zstd decompression exists (measured:
//! `zstd -T0` does not engage for `-d`) — and decoding a whole 74 MB
//! layer cost ~100 ms, the single largest term of the layer load path.
//!
//! This container splits the payload into independent chunks, each its own
//! complete zstd frame, so BOTH directions parallelize across cores:
//!
//!   * the LOAD decodes the chunks in parallel — each chunk's pages fault
//!     once, in parallel, in the decoder's own slice of the one output
//!     buffer (never a per-chunk buffer: that would fault every page
//!     twice, and never a second pass later);
//!   * the EXPORT compresses them in parallel too — compression was the
//!     slow direction, and this is the same win.
//!
//! Measured on a 74 MB layer (148 MB uncompressed, 24 cores): the load
//! decode dropped from ~100 ms to ~10 ms.
//!
//! Format:
//! ```text
//!   [0..4]     b"SDLZ"       the magic
//!   [4..8]     u32 version (1)
//!   [8..12]    u32 chunk count
//!   [12..16]   u32 uncompressed chunk size (the LAST chunk is shorter)
//!   [16..24]   u64 total uncompressed size
//!   [24..]     u32 compressed size per chunk
//!   then       the compressed chunks, concatenated
//! ```
//!
//! A legacy single-frame `.layer` (the zstd magic `28 B5 2F FD` at offset
//! 0) still loads through `zstd::decode_all` — the sequential path, for
//! files made before this container existed.

/// The container magic.
pub const MAGIC: [u8; 4] = *b"SDLZ";
/// The container version.
const VERSION: u32 = 1;
/// The uncompressed chunk size. Small enough to parallelize across any
/// real core count (a 148 MB layer = 37 chunks), large enough that the
/// per-frame overhead and the lost cross-chunk context are noise.
const CHUNK: usize = 4 * 1024 * 1024;
/// Sanity cap on the claimed uncompressed size: a corrupt or hostile
/// layer must not turn the header into an absurd allocation.
const MAX_TOTAL: u64 = 8 * 1024 * 1024 * 1024;

/// True when `data` is a chunked container (see the module docs).
pub fn is_chunked(data: &[u8]) -> bool {
    data.len() >= 24 && data[..4] == MAGIC
}

fn rd_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn wr_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// The uncompressed size of chunk `i` of `total` bytes.
fn chunk_out_size(i: usize, total: usize) -> usize {
    let start = i * CHUNK;
    if start >= total {
        0
    } else {
        (total - start).min(CHUNK)
    }
}

/// Compress `data` into the chunked container, in parallel across cores.
///
/// Each chunk is an independent zstd frame at `level`; the per-chunk loss
/// (no cross-chunk context) is noise at this chunk size.
pub fn compress_chunked(data: &[u8], level: i32) -> anyhow::Result<Vec<u8>> {
    use zstd::bulk::Compressor;

    let chunks = data.len().div_ceil(CHUNK).max(1);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(chunks);
    let per = chunks.div_ceil(workers);

    // ONE scope: every worker spawns before any joins, and each worker's
    // compressed chunks come back through its joined handle. The
    // per-thread compressor context stays in the thread — zstd contexts
    // are not Send.
    let results: Vec<anyhow::Result<Vec<Vec<u8>>>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|w| {
                let lo = w * per;
                let hi = ((w + 1) * per).min(chunks);
                let data = data;
                scope.spawn(move || -> anyhow::Result<Vec<Vec<u8>>> {
                    if lo >= hi {
                        return Ok(Vec::new());
                    }
                    let mut comp = Compressor::new(level)
                        .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
                    let mut out = Vec::with_capacity(hi - lo);
                    for i in lo..hi {
                        let src = &data[i * CHUNK..i * CHUNK + chunk_out_size(i, data.len())];
                        let c = comp
                            .compress(src)
                            .map_err(|e| anyhow::anyhow!("chunk {i}: {e}"))?;
                        out.push(c);
                    }
                    Ok(out)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("compress worker panicked"))
            .collect()
    });

    // Flatten to per-chunk (global index). Empty-range workers contribute
    // nothing; the ranges are contiguous by construction, so the flat
    // list must land at exactly `chunks`.
    let mut flat: Vec<Vec<u8>> = Vec::with_capacity(chunks);
    for r in results {
        flat.extend(r?);
    }
    if flat.len() != chunks {
        anyhow::bail!("chunked container: worker ranges did not cover the payload");
    }

    // Assemble: header + per-chunk compressed sizes + the chunks.
    let mut out = Vec::with_capacity(
        24 + 4 * chunks + flat.iter().map(|c| c.len()).sum::<usize>(),
    );
    out.extend_from_slice(&MAGIC);
    wr_u32(&mut out, VERSION);
    wr_u32(&mut out, chunks as u32);
    wr_u32(&mut out, CHUNK as u32);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    for c in &flat {
        wr_u32(&mut out, c.len() as u32);
    }
    for c in &flat {
        out.extend_from_slice(c);
    }
    Ok(out)
}

/// Decompress a chunked container, in parallel across cores.
///
/// Each chunk decodes directly into its slice of the one output buffer —
/// never a per-chunk buffer (that would fault every page twice).
pub fn decompress_chunked(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use zstd::bulk::Decompressor;

    if data.len() < 24 || data[..4] != MAGIC {
        anyhow::bail!("not a chunked container");
    }
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != VERSION {
        anyhow::bail!("unsupported chunked container version {version}");
    }
    let chunks = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let chunk_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
    let total = u64::from_le_bytes(data[16..24].try_into().unwrap());
    if chunk_size == 0 || chunks == 0 {
        anyhow::bail!("chunked container: empty");
    }
    if total > MAX_TOTAL {
        anyhow::bail!("chunked container: total size beyond the sanity cap");
    }
    let total = total as usize;
    if total.div_ceil(chunk_size) != chunks {
        anyhow::bail!("chunked container: inconsistent sizes");
    }
    let header_end = 24 + 4 * chunks;
    if data.len() < header_end {
        anyhow::bail!("chunked container: truncated header");
    }
    // The compressed chunk offsets (the prefix sum of the sizes).
    let mut offsets = Vec::with_capacity(chunks + 1);
    let mut acc = header_end;
    for i in 0..chunks {
        offsets.push(acc);
        let sz = u32::from_le_bytes([
            data[24 + 4 * i],
            data[25 + 4 * i],
            data[26 + 4 * i],
            data[27 + 4 * i],
        ]) as usize;
        acc = acc
            .checked_add(sz)
            .ok_or_else(|| anyhow::anyhow!("chunked container: size overflow"))?;
    }
    if acc > data.len() {
        anyhow::bail!("chunked container: chunk data past end of file");
    }
    offsets.push(acc);

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(chunks);
    let per = chunks.div_ceil(workers);

    let mut out = vec![0u8; total];
    // Worker w decodes chunks [w*per, (w+1)*per) into the contiguous
    // output slice covering them — the slices are disjoint by
    // construction, and the scope joins before return.
    {
        // The per-worker output slice boundaries (capped at `total`; NO
        // dedup — an empty range yields an empty slice, and the worker
        // checks out immediately). Each worker's slice covers exactly
        // its chunk range, disjoint by construction.
        let bounds: Vec<usize> = (0..=workers)
            .map(|w| (w * per * chunk_size).min(total))
            .collect();
        let mut slices: Vec<&mut [u8]> = Vec::with_capacity(workers);
        {
            let mut rest: &mut [u8] = &mut out;
            let mut prev = 0usize;
            for &b in bounds.iter().skip(1) {
                let (head, tail) = rest.split_at_mut(b - prev);
                slices.push(head);
                rest = tail;
                prev = b;
            }
        }
        let results: Vec<anyhow::Result<()>> = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for (w, slice) in slices.iter_mut().enumerate() {
                let lo = w * per;
                let hi = ((w + 1) * per).min(chunks);
                let data = data;
                let offsets = &offsets;
                let chunk_size = chunk_size;
                let total = total;
                handles.push(scope.spawn(move || -> anyhow::Result<()> {
                    if lo >= hi {
                        return Ok(());
                    }
                    // The decompressor context stays in the thread (see
                    // compress_chunked).
                    let mut dec = Decompressor::new()
                        .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
                    for i in lo..hi {
                        let want = chunk_out_size(i, total);
                        let src = &data[offsets[i]..offsets[i + 1]];
                        let base = (i - lo) * chunk_size;
                        let dst = &mut slice[base..base + want];
                        // Decode straight into the output slice: the
                        // chunk's pages fault ONCE, here, in parallel.
                        let n = dec
                            .decompress_to_buffer(src, dst)
                            .map_err(|e| anyhow::anyhow!("chunk {i}: {e}"))?;
                        if n != want {
                            anyhow::bail!("chunk {i}: decoded {n} of {want}");
                        }
                    }
                    Ok(())
                }));
            }
            handles
                .into_iter()
                .map(|h| h.join().expect("decode worker panicked"))
                .collect()
        });
        for r in results {
            r?;
        }
    }
    Ok(out)
}

/// Decompress a chunked container READ DIRECTLY FROM THE FILE, in
/// parallel across cores — each worker `pread`s its own chunks and
/// decodes them into its slice of the one output buffer.
///
/// MEASURED: the serial `fs::read` of the whole compressed file was the
/// load path's dominant cost (~200 ms of a 310 ms data-disk phase for a
/// 520 MB layer) — one core copying the file into a fresh buffer, page
/// by faulting page. Distributed across the decode workers, the read
/// rides the same parallelism the decode already has, and the whole
/// file-to-buffer copy disappears: each worker reads its own compressed
/// chunk into a small per-chunk buffer and decodes straight out of it.
pub fn decompress_chunked_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::io::AsRawFd;

    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
    let fd = file.as_raw_fd();
    let file_len = {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(anyhow::anyhow!("fstat {}: failed", path.display()));
        }
        st.st_size as usize
    };

    // The header.
    let mut head = [0u8; 24];
    pread_exact(fd, 0, &mut head)?;
    if head[..4] != MAGIC {
        anyhow::bail!("not a chunked container");
    }
    let version = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    if version != VERSION {
        anyhow::bail!("unsupported chunked container version {version}");
    }
    let chunks = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize;
    let chunk_size = u32::from_le_bytes([head[12], head[13], head[14], head[15]]) as usize;
    let total = u64::from_le_bytes(head[16..24].try_into().unwrap());
    if chunk_size == 0 || chunks == 0 {
        anyhow::bail!("chunked container: empty");
    }
    if total > MAX_TOTAL {
        anyhow::bail!("chunked container: total size beyond the sanity cap");
    }
    let total = total as usize;
    if total.div_ceil(chunk_size) != chunks {
        anyhow::bail!("chunked container: inconsistent sizes");
    }
    let header_end = 24 + 4 * chunks;
    if header_end > file_len {
        anyhow::bail!("chunked container: truncated header");
    }
    let mut sizes = vec![0u8; 4 * chunks];
    pread_exact(fd, 24, &mut sizes)?;
    let mut offsets = Vec::with_capacity(chunks + 1);
    let mut acc = header_end;
    for i in 0..chunks {
        offsets.push(acc);
        let sz = u32::from_le_bytes([
            sizes[4 * i],
            sizes[4 * i + 1],
            sizes[4 * i + 2],
            sizes[4 * i + 3],
        ]) as usize;
        acc = acc
            .checked_add(sz)
            .ok_or_else(|| anyhow::anyhow!("chunked container: size overflow"))?;
    }
    if acc > file_len {
        anyhow::bail!("chunked container: chunk data past end of file");
    }
    offsets.push(acc);

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(chunks);
    let per = chunks.div_ceil(workers);

    let mut out = vec![0u8; total];
    // The per-worker output slice boundaries (capped at `total`; NO
    // dedup — an empty range yields an empty slice and that worker
    // no-ops). Each worker's slice covers exactly its chunk range,
    // disjoint by construction.
    let bounds: Vec<usize> = (0..=workers)
        .map(|w| (w * per * chunk_size).min(total))
        .collect();
    let mut slices: Vec<&mut [u8]> = Vec::with_capacity(workers);
    {
        let mut rest: &mut [u8] = &mut out;
        let mut prev = 0usize;
        for &b in bounds.iter().skip(1) {
            let (head, tail) = rest.split_at_mut(b - prev);
            slices.push(head);
            rest = tail;
            prev = b;
        }
    }
    let results: Vec<anyhow::Result<()>> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (w, slice) in slices.iter_mut().enumerate() {
            let lo = w * per;
            let hi = ((w + 1) * per).min(chunks);
            let fd = fd;
            let offsets = &offsets;
            let chunk_size = chunk_size;
            let total = total;
            handles.push(scope.spawn(move || -> anyhow::Result<()> {
                if lo >= hi {
                    return Ok(());
                }
                // The decompressor context stays in the thread (see
                // compress_chunked).
                let mut dec = zstd::bulk::Decompressor::new()
                    .map_err(|e| anyhow::anyhow!("zstd init: {e}"))?;
                // ONE reusable input buffer per worker, sized to the
                // largest chunk this worker will read. MEASURED
                // (520 MB layer): a fresh `vec!` per chunk ran the
                // phase at 103-123 ms, this at 97-110 ms — a ~12% win,
                // not the 40% a fault-count model predicted: the
                // allocator was already handing the freed buffer's
                // faulted pages straight back to the next `vec!`, so
                // the input side was never the fault count it looked
                // like. What the reuse buys is the allocator churn; the
                // phase's real floor is the OUTPUT buffer's fresh pages
                // (one fault each, and the faults do NOT parallelize —
                // see the thrashing note in virtio::blk). The buffer
                // is fully overwritten by each pread (short reads are
                // errors).
                let max_comp = (lo..hi)
                    .map(|i| offsets[i + 1] - offsets[i])
                    .max()
                    .unwrap_or(0);
                let mut comp = vec![0u8; max_comp];
                for i in lo..hi {
                    let want = chunk_out_size(i, total);
                    let comp_len = offsets[i + 1] - offsets[i];
                    // Read straight from the file, HERE, in this worker
                    // — the read rides the decode's parallelism instead
                    // of serializing ahead of it.
                    let comp = &mut comp[..comp_len];
                    pread_exact(fd, offsets[i], comp)?;
                    let base = (i - lo) * chunk_size;
                    let dst = &mut slice[base..base + want];
                    // Decode straight out of the buffer into the output
                    // slice: the chunk's output pages fault ONCE, here.
                    let n = dec
                        .decompress_to_buffer(comp, dst)
                        .map_err(|e| anyhow::anyhow!("chunk {i}: {e}"))?;
                    if n != want {
                        anyhow::bail!("chunk {i}: decoded {n} of {want}");
                    }
                }
                Ok(())
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("decode worker panicked"))
            .collect()
    });
    for r in results {
        r?;
    }
    Ok(out)
}

/// `pread` exactly `buf.len()` bytes at `off` (a helper for the
/// per-worker chunk reads; every short read is an error).
fn pread_exact(fd: libc::c_int, off: usize, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe {
            libc::pread(
                fd,
                unsafe { buf.as_mut_ptr().add(done) }.cast(),
                buf.len() - done,
                (off + done) as libc::off_t,
            )
        };
        if n <= 0 {
            anyhow::bail!("pread at {off}: short read ({done}/{})", buf.len());
        }
        done += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_roundtrip_random() {
        // Incompressible data: many full chunks, one short tail.
        let data: Vec<u8> = (0..CHUNK as u32 * 3 + 12345)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let c = compress_chunked(&data, 3).expect("compress");
        assert!(is_chunked(&c));
        let d = decompress_chunked(&c).expect("decompress");
        assert_eq!(d, data);
    }

    #[test]
    fn chunked_roundtrip_compressible() {
        // Compressible data: real compression through the parallel path,
        // with the short tail chunk.
        let mut data = vec![0u8; CHUNK + CHUNK / 2];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i / 1024) as u8;
        }
        let c = compress_chunked(&data, 3).expect("compress");
        let d = decompress_chunked(&c).expect("decompress");
        assert_eq!(d, data);
    }

    #[test]
    fn chunked_file_roundtrip() {
        // The file-based load path (decompress_chunked_file) must accept
        // exactly what compress_chunked produces, reading per chunk.
        let data: Vec<u8> = (0..CHUNK as u32 * 2 + 999)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let c = compress_chunked(&data, 3).expect("compress");
        let dir = std::env::temp_dir().join(format!(
            "zchunk-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.layer");
        std::fs::write(&path, &c).unwrap();
        let d = decompress_chunked_file(&path).expect("decompress from file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(d, data);
    }

    #[test]
    fn truncated_container_fails() {
        let data = vec![7u8; 1024];
        let c = compress_chunked(&data, 3).unwrap();
        // A corrupt total size must not drive an absurd allocation.
        let mut bad = c.clone();
        bad[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decompress_chunked(&bad).is_err());
        // A truncated file must fail, not read past the end.
        let mut short = c.clone();
        short.truncate(short.len() / 2);
        assert!(decompress_chunked(&short).is_err());
    }
}
