#!/usr/bin/env python3
"""End-to-end test for the layer export/load round-trip.

Boots the sandal VM twice with a pty:

  1. Cold boot with a writable overlay disk, create a file in the guest,
     run the guest `sandal-export <path>` command, and verify the host
     receives a valid gzip-compressed `.layer` archive containing the file.
  2. Fresh boot with `--layer <that file>` and verify the file is back in
     the guest filesystem.

Requires the codesigned release binary (`make`) and macOS/HVF.

Usage (from the repo root, after `make`):
    uv run python tests/test_export.py
"""

import pathlib
import sys
import tarfile
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

MARKER = b"ROUNDTRIP_MAGIC_42"


def phase_export(tmp: pathlib.Path) -> pathlib.Path:
    layer = tmp / "roundtrip.layer"
    vm = Vm(["--disk-size", "64"])
    try:
        vm.boot("export boot")
        vm.run(
            f"echo {MARKER.decode()} > /root/roundtrip.txt; echo WRITE_DONE",
            "WRITE_DONE",
        )
        vm.run(f"sandal-export {layer}", "Layer exported", count=1)
    finally:
        vm.close()

    if not layer.is_file():
        raise AssertionError(f"export: {layer} was not created on the host")
    return layer


def phase_load(layer: pathlib.Path) -> None:
    vm = Vm(["--disk-size", "64", "--layer", str(layer)])
    try:
        vm.boot("load boot")
        out = vm.run("cat /root/roundtrip.txt; echo LOAD_DONE", "LOAD_DONE")
        if MARKER.decode() not in out:
            raise AssertionError("load: round-trip file content missing in guest")
    finally:
        vm.close()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sandal-export-test-") as tmp_dir:
        tmp = pathlib.Path(tmp_dir)
        print("export: creating file in guest and exporting a layer...")
        layer = phase_export(tmp)

        print(f"export: validating {layer} ...")
        with tarfile.open(layer, "r:gz") as tf:
            try:
                member = tf.getmember("root/roundtrip.txt")
            except KeyError:
                raise AssertionError(
                    "export: root/roundtrip.txt missing from layer "
                    f"(entries: {[m.name for m in tf.getmembers()[:10]]})"
                )
            content = tf.extractfile(member).read().strip()
        if content != MARKER:
            raise AssertionError(f"export: unexpected layer content {content!r}")

        print("load: booting with --layer and reading the file back...")
        phase_load(layer)


if __name__ == "__main__":
    sys.exit(test_main("export", main))
