#!/usr/bin/env python3
"""Feature test: every virtio device is wired and usable.

Boots with the full device set (console, two virtio-blk, net, rng, virtiofs)
and checks:

  * virtio device IDs visible in `/sys/bus/virtio/devices` (1 = net,
    2 = blk x2, 3 = console, 4 = rng, 26 = fs),
  * `/dev/vda`, `/dev/vdb`, `/dev/hwrng` exist,
  * virtio-blk queue geometry: `max_segments == 126` and
    `max_segment_size == 32768`.  `seg_max` must leave room for the request
    header and status descriptors; advertising 128 on a 128-descriptor ring
    let the guest build an impossible 130-descriptor request, so the Linux
    driver stopped the block queue forever on `-ENOSPC` (regression test),
  * virtio-rng returns fresh entropy.

Usage (from the repo root, after `make`):
    uv run python tests/test_devices.py
"""

import pathlib
import re
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# virtio device IDs (include/uapi/linux/virtio_ids.h)
VIRTIO_IDS = {
    "0x0001": "net",
    "0x0002": "blk",
    "0x0003": "console",
    "0x0004": "rng",
    "0x001a": "fs",
}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sandal-devices-test-") as tmp_dir:
        vm = Vm(["--disk-size", "64", "--share", f"{tmp_dir}:/mnt/share"])
        try:
            vm.boot("devices")
            out = vm.run(
                "for d in /sys/bus/virtio/devices/*; do cat $d/device; done; "
                "echo \"NODES $(ls /dev/vda /dev/vdb /dev/hwrng 2>&1 | tr '\\n' ' ')\"; "
                "echo \"MAXSEG $(cat /sys/block/vda/queue/max_segments)\"; "
                "echo \"MAXSZ $(cat /sys/block/vda/queue/max_segment_size)\"; "
                "echo \"RNG1 $(dd if=/dev/hwrng bs=32 count=1 2>/dev/null | md5sum | cut -d' ' -f1)\"; "
                "echo \"RNG2 $(dd if=/dev/hwrng bs=32 count=1 2>/dev/null | md5sum | cut -d' ' -f1)\"; "
                "echo DEVICES_DONE",
                "DEVICES_DONE",
            )
        finally:
            vm.close()

    # The pty echoes CR/LF line endings; normalize before line-anchored parses.
    out = out.replace("\r", "")
    counts: dict[str, int] = {}
    for dev_id in re.findall(r"^0x[0-9a-f]{4}$", out, re.M):
        counts[dev_id] = counts.get(dev_id, 0) + 1
    for dev_id, name in VIRTIO_IDS.items():
        expected = 2 if name == "blk" else 1
        if counts.get(dev_id, 0) != expected:
            raise AssertionError(
                f"expected {expected} virtio-{name} ({dev_id}), saw "
                f"{counts.get(dev_id, 0)} (all: {counts})"
            )

    node_lines = re.findall(r"NODES ([^\n]*)", out)
    if not any(
        all(n in line for n in ("/dev/vda", "/dev/vdb", "/dev/hwrng")) for line in node_lines
    ):
        raise AssertionError(f"missing device nodes (vda/vdb/hwrng); saw {node_lines!r}")

    maxseg = re.search(r"MAXSEG (\d+)", out)
    if not maxseg or int(maxseg.group(1)) != 126:
        raise AssertionError(
            "max_segments must be 126 (seg_max = queue_size - 2), got "
            f"{maxseg and maxseg.group(1)}"
        )
    maxsz = re.search(r"MAXSZ (\d+)", out)
    if not maxsz or int(maxsz.group(1)) != 32768:
        raise AssertionError(f"max_segment_size must be 32768, got {maxsz and maxsz.group(1)}")

    rng = re.findall(r"RNG[12] ([0-9a-f]{32})", out)
    if len(rng) != 2:
        raise AssertionError(f"virtio-rng did not produce entropy ({rng})")
    if rng[0] == rng[1]:
        raise AssertionError("virtio-rng returned identical 32-byte reads")


if __name__ == "__main__":
    sys.exit(test_main("devices", main))
