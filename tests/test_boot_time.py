#!/usr/bin/env python3
"""Boot-time regression test for the layer (.layer) load path.

`--layer` pre-populates the overlay data disk. Two scenarios, both
measured on this machine:

  * vim.layer — a 74 MB layer (148 MB uncompressed), ~6800 files: the
    many-small-files worst case for the metadata pass.
  * big.layer — a 520 MB layer of incompressible data across a few big
    files: the decode-at-full-rate worst case (the file does not
    compress, so the compressed size IS the content size).

The load path's phases and their floors:

  * zstd decode + the compressed-file read — the chunked container
    (src/zchunk.rs) decodes across cores, and each worker preads its
    own chunks straight from the file: the read rides the decode's
    parallelism. MEASURED: the serial fs::read ahead of the decode was
    the load path's dominant cost — one core copying the file into a
    fresh buffer, page by faulting page: ~200 ms of a 310 ms
    data-disk phase for the 520 MB layer (the whole phase ran 310 ms;
    with the pread it runs 110-125 ms).
  * the archive parse — zero-copy (crate::tar::TarEntryRef): ~3 ms
    (vim) / ~0.03 ms (big) of header walking. The OLD owned path copied
    every entry into a per-entry buffer — ~100 ms.
  * the ext2 injection — the composite disk (virtio::blk::SparseRegion):
    the data blocks are RECORDED as sparse regions, served from the
    decompressed archive by the block device and COW'd on the first
    guest write, and the image only ever holds the metadata:
    ~14 ms (vim) / ~2 ms (big). The per-entry metadata walks are cached
    (src/ext2.rs Ext2Alloc: the path cache, the append-tail cursor, the
    duplicate record) — the uncached design ran ~46 ms (three
    O(directory) walks per entry: the parent-path walk, the duplicate
    check, the append walk). The OLD copying path faulted the whole
    148 MB into the image: ~90 ms, and it was unmovable
    (run-coalescing: no change; a parallel copy: 9x WORSE — the fault
    path serializes on the mm lock, it is not core-bound).

The bounds are ABSOLUTE, not ratio-based: the decode parallelizes with
the core count, so a ratio against it is not stable across machines.
Each bound catches a NAMED reversion with margin (the measured floor in
parentheses):

  * tar_parse ≤ 10 ms (floor 3 / 0.03) — the owned-copy path ran
    ~100 ms;
  * ext2_inject ≤ 30 ms (floor 14 / 2) — the copying path ran ~90 ms
    and the uncached three-walk design ran ~46 ms;
  * data_disk ≤ 90 ms (vim, floor 50-54) / ≤ 250 ms (big, floor
    110-125) — the serial-read design ran the whole phase at 97-111 ms
    (vim) / 310 ms (big). The floor includes the decode, which scales
    with the core count: a machine whose decode floor alone exceeds the
    bound fails it — the same acceptance the absolute-bound philosophy
    makes, and the price of catching the serial read by name;
  * the wall tripwire: the layer boot < 3x the no-layer baseline (the
    baseline carries the same guest boot + teardown) — the catastrophe
    catch (a full copy of the layer into the image).

The runtime half of the composite's contract — the layer's content
actually working through the sparse path — lives in test_layer.py.

Usage (from the repo root, after `make`):
    uv run python tests/test_boot_time.py
"""

import os
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import SANDAL, test_main  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
LAYERS = [
    # (name, path, the data_disk bound in ms)
    ("vim", REPO / "vim.layer", 90.0),
    ("big", REPO / "big.layer", 250.0),
]


def timed_boot(extra_args):
    """Run one boot with the timing probes on; return (fields, wall, rc)."""
    env = dict(os.environ)
    env["SANDAL_DEBUG_TIMING"] = "1"
    t0 = time.time()
    out = subprocess.run(
        [str(SANDAL), *extra_args, "--", "uname", "-a"],
        env=env,
        stdin=subprocess.DEVNULL,  # the VMM's stdin poller drains whatever it gets
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    wall = time.time() - t0
    stderr = out.stderr.decode("utf-8", "replace")
    fields = {}
    for line in stderr.splitlines():
        m = re.match(r"BOOT_TIMING\s+(\S+):\s+([0-9.]+)(µs|ms|s)", line)
        if m:
            name, val, unit = m.groups()
            fields[name] = float(val) * {"µs": 1e-3, "ms": 1.0, "s": 1000.0}[unit]
    return fields, wall, out.returncode, stderr


def main() -> None:
    # The no-layer baseline first: the wall tripwire divides by it.
    base_fields, base_wall, base_rc, base_stderr = timed_boot([])
    print(f"base boot:  rc={base_rc} wall={base_wall:.2f}s")
    if base_rc != 0:
        print("VMM stderr:", base_stderr)
        raise SystemExit(1)

    for name, layer, disk_bound in LAYERS:
        if not layer.exists():
            print(f"[{name}] SKIP: {layer} missing")
            continue
        print(f"[{name}] {layer}")
        fields, wall, rc, _ = timed_boot(["--layer", str(layer)])
        print(f"  boot: rc={rc} wall={wall:.2f}s")
        for k in ("zstd_decode", "tar_parse", "ext2_inject", "data_disk"):
            if k in fields:
                print(f"  {k}: {fields[k]:.0f} ms")
        if rc != 0:
            raise SystemExit(1)

        # The parse bound: the header walk, never a owned-copy pass.
        parse = fields.get("tar_parse", 0.0)
        if parse > 10.0:
            print(f"  tar_parse {parse:.0f} ms > 10 ms: WRONG (the owned-copy path?)")
            raise SystemExit(1)
        print(f"  tar_parse {parse:.0f} ms ≤ 10 ms: OK")

        # The injection bound: the composite's cached metadata pass —
        # never the block copy, never the uncached three-walk design.
        inject = fields.get("ext2_inject", 0.0)
        if inject > 30.0:
            print(f"  ext2_inject {inject:.0f} ms > 30 ms: WRONG (the copy or the uncached walks?)")
            raise SystemExit(1)
        print(f"  ext2_inject {inject:.0f} ms ≤ 30 ms: OK")

        # The data-disk bound: the serial-read design ran the whole
        # phase at 97-111 ms (vim) / 310 ms (big) — see the docstring
        # for the floor's core-count caveat.
        disk = fields.get("data_disk", 0.0)
        if disk > disk_bound:
            print(f"  data_disk {disk:.0f} ms > {disk_bound:.0f} ms: WRONG (the serial read?)")
            raise SystemExit(1)
        print(f"  data_disk {disk:.0f} ms ≤ {disk_bound:.0f} ms: OK")

        # The wall tripwire: gross regressions only (a new full pass).
        if wall >= base_wall * 3.0:
            print(f"  wall {wall:.2f}s ≥ base {base_wall:.2f}s × 3: WRONG")
            raise SystemExit(1)
        print(f"  wall {wall:.2f}s < base {base_wall:.2f}s × 3: OK")


if __name__ == "__main__":
    sys.exit(test_main("boot-time", main))
