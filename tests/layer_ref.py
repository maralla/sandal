"""Shared helpers for the layer (.layer) tests.

The .layer container: `src/zchunk.rs` — a chunked zstd container ("SDLZ"
magic), each chunk an independent zstd frame, so both directions
parallelize. A LEGACY single-frame layer (the zstd magic `28 B5 2F FD`)
still exists. The verification helpers here understand both, so the tests
share one reference path.
"""

import pathlib
import struct
import subprocess


def decompress_layer(layer: pathlib.Path) -> bytes:
    """The decompressed (tar) content of a .layer, either format."""
    raw = pathlib.Path(layer).read_bytes()
    if raw[:4] != b"SDLZ":
        # Legacy single frame.
        return subprocess.run(
            ["zstd", "-dc", str(layer)], capture_output=True, check=True
        ).stdout
    # The chunked container: parse the header (see src/zchunk.rs), decode
    # each chunk (an independent zstd frame), reassemble.
    ver = struct.unpack("<I", raw[4:8])[0]
    if ver != 1:
        raise ValueError(f"unsupported SDLZ version {ver}")
    n = struct.unpack("<I", raw[8:12])[0]
    chunk_sz = struct.unpack("<I", raw[12:16])[0]
    total = struct.unpack("<Q", raw[16:24])[0]
    sizes = [
        struct.unpack("<I", raw[24 + 4 * i : 28 + 4 * i])[0] for i in range(n)
    ]
    offs, acc = [], 24 + 4 * n
    for sz in sizes:
        offs.append(acc)
        acc += sz
    out = bytearray()
    for i in range(n):
        piece = subprocess.run(
            ["zstd", "-dc", "-"],
            input=raw[offs[i] : offs[i] + sizes[i]],
            capture_output=True,
            check=True,
        ).stdout
        out += piece
    if len(out) != total:
        raise ValueError(f"SDLZ: reassembled {len(out)} of {total}")
    return bytes(out)
