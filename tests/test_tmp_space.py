#!/usr/bin/env python3
"""/tmp space-sharing + export-exclusion test.

/tmp rides the overlay root — in disk mode it shares the data disk
(--disk-size) instead of a fixed half-RAM tmpfs. Two contracts:

  1. SPACE: with --disk-size, /tmp holds more than the old tmpfs cap
     (~120 MB) and the bytes really land on the data disk (written,
     checksummed, read back).

  2. EXPORT EXCLUSION: /tmp is workspace scratch — sandal-export must
     NEVER deliver it. A file planted in /tmp must not appear in the
     exported layer, while a file in /root must (the control).

Usage (from the repo root, after `make`):
    uv run python tests/test_tmp_space.py
"""

import pathlib
import re
import sys
import tarfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import layer_ref  # noqa: E402
from vm_harness import Vm, test_main  # noqa: E402

MARKER = b"TMP_SPACE_MAGIC_7"
BIG_MB = 300


def phase_space(tmp: pathlib.Path) -> None:
    """Contract 1: /tmp shares the data disk's capacity."""
    vm = Vm(["--disk-size", "1024"])
    try:
        vm.boot("disk boot")
        out = vm.run(
            "df -k /tmp | tail -1; echo DF\"\"_DONE", "DF_DONE"
        )
        # df's line: "<fs> <1K-blocks> ..."; the overlay reports the data
        # disk's size. The old dedicated tmpfs capped at ~124000 KB.
        line = next(
            (l for l in out.splitlines() if l.startswith(("overlay", "tmpfs", "/dev/"))),
            None,
        )
        if line is None:
            raise AssertionError(f"df produced no output line: {out!r}")
        blocks = int(line.split()[1])
        if blocks < 900_000:
            raise AssertionError(
                f"/tmp does not share the data disk: df shows {blocks} KB "
                f"(expected ≥ 900000 for --disk-size 1024)"
            )

        # The bytes really land: write 300 MB into /tmp, checksum, read
        # back, checksum again.
        vm.run(
            f"dd if=/dev/zero of=/tmp/big bs=1M count={BIG_MB} 2>/dev/null; "
            f"echo WRITE\"\"_DONE",
            "WRITE_DONE",
        )
        def md5_of(label, marker):
            out = vm.run(f"md5sum /tmp/big; echo {label}\"\"_DONE", marker)
            line = next(
                (l for l in out.splitlines() if "  /tmp/big" in l), None
            )
            if line is None:
                raise AssertionError(f"md5sum produced no hash line: {out!r}")
            return line.split()[0]

        written = md5_of("SUM", "SUM_DONE")
        vm.run("sync; echo SYNC\"\"_DONE", "SYNC_DONE")
        readback = md5_of("VERIFY", "VERIFY_DONE")
        if written != readback:
            raise AssertionError(
                f"/tmp write did not round-trip: {written} != {readback}"
            )
    finally:
        vm.close()


def phase_export_exclusion(tmp: pathlib.Path) -> pathlib.Path:
    """Contract 2: sandal-export never delivers /tmp content."""
    vm = Vm(["--disk-size", "1024"])
    try:
        vm.boot("export boot")
        # The control: workspace data in /root must export.
        vm.run(
            f"echo {MARKER.decode()} > /root/keep.txt; "
            f"echo scratch > /tmp/leak.txt; "
            f"dd if=/dev/zero of=/tmp/big bs=1M count=64 2>/dev/null; "
            f"echo PLANT\"\"_DONE",
            "PLANT_DONE",
        )
        vm.run("sandal-export /tmp/x.layer", "Layer exported", count=1)
    finally:
        saved = re.findall(rb"Layer saved to: ([^\s\r]+)", vm.buf)
        vm.close()

    if not saved:
        raise AssertionError(
            "export: the VMM never named a saved layer: " f"{vm.buf[-300:]!r}"
        )
    layer = pathlib.Path.cwd() / saved[-1].decode()

    raw = layer.with_suffix(".tar")
    raw.write_bytes(layer_ref.decompress_layer(layer))
    names = []
    with tarfile.open(raw, "r:") as tf:
        for m in tf.getmembers():
            names.append(m.name.lstrip("./"))
        keep = next(
            (m for m in tf.getmembers() if m.name.lstrip("./") == "root/keep.txt"),
            None,
        )
        content = tf.extractfile(keep).read().strip() if keep else None
    leaked = [n for n in names if n == "tmp" or n.startswith("tmp/")]

    if keep is None or content != MARKER:
        raise AssertionError(
            f"export: the /root control did not survive "
            f"(keep={keep is not None}, content={content!r})"
        )
    if leaked:
        raise AssertionError(
            f"export: /tmp content leaked into the layer: {leaked[:5]} "
            f"(all entries: {names[:10]}...)"
        )
    return layer


def main() -> bool:
    tmp = pathlib.Path(__file__).parent / "tmp_space_work"
    tmp.mkdir(exist_ok=True)

    print("/tmp shares --disk-size: writing and verifying 300 MB ...")
    phase_space(tmp)
    print("/tmp shares --disk-size: OK")

    print("sandal-export excludes /tmp: exporting with /tmp planted ...")
    phase_export_exclusion(tmp)
    print("sandal-export excludes /tmp: OK")
    return True


if __name__ == "__main__":
    sys.exit(test_main("tmp-space", main))
