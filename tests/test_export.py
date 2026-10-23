#!/usr/bin/env python3
"""End-to-end test for the layer export/load round-trip.

Boots the sandal VM four times with a pty:

  1. Cold boot with a writable overlay disk (`--disk-size`), create a file in
     the guest, run `sandal-export <path>`, and verify the host receives a
     valid zstd-compressed `.layer` archive containing the file (disk-mode
     export).
  2. Cold boot with the default tmpfs overlay upper (no `--disk-size`), create
     a file, export it, and verify the layer again.  The data disk is still
     attached; the guest uses it as the raw scratch device the tar is written
     onto (tmpfs-mode export).
  3. Fresh boot with `--layer <disk layer>` and verify the file is back in the
     guest filesystem.
  4. Fresh boot with `--layer <tmpfs layer>` and verify that file is back too.

Requires the codesigned release binary (`make`) and macOS/HVF.

Usage (from the repo root, after `make`):
    uv run python tests/test_export.py
"""

import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

MARKER = b"ROUNDTRIP_MAGIC_42"
TMPFS_MARKER = b"TMPFS_MAGIC_43"


def phase_export(
    tmp: pathlib.Path,
    extra_args: list[str],
    layer_name: str,
    guest_path: str,
    marker: bytes,
) -> pathlib.Path:
    """Export a layer and return the path the VMM actually saved it to.

    The output path is NEVER sent from the guest (the dedicated console
    port whose whole stream was the path is gone): the VMM names the
    layer content-addressed, in its own working directory, and logs the
    path ("Layer saved to: ...") — the operator renames from the log
    line. This test IS the operator: parse the log line and use the
    named path.
    """
    vm = Vm(extra_args)
    try:
        vm.boot("export boot")
        vm.run(
            f"echo {marker.decode()} > {guest_path}; echo WRITE\"\"_DONE",
            "WRITE_DONE",
        )
        vm.run(f"sandal-export {tmp / layer_name}", "Layer exported", count=1)
    finally:
        # The VMM's own log line names the saved layer; it rides the same
        # pty as everything else, and vm.buf retains the whole transcript.
        # (console_eprintln terminates the line with \r — strip it.)
        saved = re.findall(rb"Layer saved to: ([^\s\r]+)", vm.buf)
        vm.close()

    if not saved:
        raise AssertionError(
            "export: the VMM never named a saved layer (no \"Layer saved "
            f"to\" line): {vm.buf[-300:]!r}"
        )
    layer = pathlib.Path.cwd() / saved[-1].decode()
    if not layer.is_file():
        raise AssertionError(f"export: {layer} was not created on the host")
    return layer


def validate_layer(layer: pathlib.Path, guest_path: str, marker: bytes) -> None:
    # The layer is compressed (the chunked zstd container or a legacy
    # single frame); decompress either for tarfile (tests/layer_ref.py).
    import layer_ref

    raw = layer.with_suffix(".tar")
    raw.write_bytes(layer_ref.decompress_layer(layer))
    # tmpfs mode tars with a `./` prefix; normalize before lookup.
    member_name = guest_path.lstrip("/")
    with tarfile.open(raw, "r:") as tf:
        history = [m.name for m in tf.getmembers() if m.name.endswith(".ash_history")]
        if history:
            raise AssertionError(f"export: shell history leaked into layer: {history}")
        member = next(
            (m for m in tf.getmembers() if m.name.lstrip("./") == member_name), None
        )
        if member is None:
            raise AssertionError(
                f"export: {member_name} missing from layer "
                f"(entries: {[m.name for m in tf.getmembers()[:10]]})"
            )
        content = tf.extractfile(member).read().strip()
    if content != marker:
        raise AssertionError(f"export: unexpected layer content {content!r}")


def phase_load(layer: pathlib.Path, guest_path: str, marker: bytes) -> None:
    vm = Vm(["--disk-size", "64", "--layer", str(layer)])
    try:
        vm.boot("load boot")
        out = vm.run(f"cat {guest_path}; echo LOAD\"\"_DONE", "LOAD_DONE")
        if marker.decode() not in out:
            raise AssertionError("load: round-trip file content missing in guest")
    finally:
        vm.close()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sandal-export-test-") as tmp_dir:
        tmp = pathlib.Path(tmp_dir)
        guest_path = "/root/roundtrip.txt"

        print("export (disk mode): creating file in guest and exporting a layer...")
        disk_layer = phase_export(
            tmp, ["--disk-size", "64"], "disk.layer", guest_path, MARKER
        )
        print(f"export: validating {disk_layer} ...")
        validate_layer(disk_layer, guest_path, MARKER)

        print("export (tmpfs mode): creating file in guest and exporting a layer...")
        tmpfs_layer = phase_export(tmp, [], "tmpfs.layer", guest_path, TMPFS_MARKER)
        print(f"export: validating {tmpfs_layer} ...")
        validate_layer(tmpfs_layer, guest_path, TMPFS_MARKER)

        print("load: booting with --layer and reading the file back...")
        phase_load(disk_layer, guest_path, MARKER)
        print("load: booting with the tmpfs-mode layer...")
        phase_load(tmpfs_layer, guest_path, TMPFS_MARKER)


if __name__ == "__main__":
    sys.exit(test_main("export", main))
