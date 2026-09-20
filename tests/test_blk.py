#!/usr/bin/env python3
"""Large multi-segment block I/O integrity test.

Regression test for the virtio-blk `seg_max` queue stall: with SEG_MAX
negotiated the guest builds multi-segment (multi-descriptor) requests.  This
writes a 12 MiB random file through the overlay disk (`/dev/vdb`), drops the
page cache and re-reads it, then reads the root disk (`/dev/vda`) directly.
Both directions use the multi-descriptor device code path that previously
deadlocked the guest's block queue.

Usage (from the repo root, after `make`):
    uv run python tests/test_blk.py
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402


def main() -> None:
    vm = Vm(["--disk-size", "64"])
    try:
        vm.boot("blk")
        out = vm.run(
            "dd if=/dev/urandom of=/root/blk.bin bs=1M count=12 2>/dev/null; "
            "sync; "
            "A=$(md5sum /root/blk.bin | cut -d' ' -f1); "
            "echo 3 > /proc/sys/vm/drop_caches; "
            "B=$(md5sum /root/blk.bin | cut -d' ' -f1); "
            'echo "BLK_MD5 $A $B"; '
            "dd if=/dev/vda of=/dev/null bs=1M count=9 2>/dev/null; "
            "echo BLK\"\"_DONE",
            "BLK_DONE",
        )
    finally:
        vm.close()

    md5 = re.search(r"BLK_MD5 ([0-9a-f]{32}) ([0-9a-f]{32})", out)
    if not md5:
        raise AssertionError("md5sum of the 12 MiB file did not run")
    if md5.group(1) != md5.group(2):
        raise AssertionError(
            f"multi-segment write/read corrupted data: {md5.group(1)} != {md5.group(2)}"
        )


if __name__ == "__main__":
    sys.exit(test_main("blk", main))
