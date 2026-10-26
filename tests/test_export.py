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

    The requested name travels as a marker file in the overlay upper
    (.sandal-layer-name) and is honored when it survives the VMM's
    sanitization (a single path component, a strict charset); this test
    passes full host paths (with '/'), which are deliberately unusable —
    the layer falls back to the content-addressed name. Either way the
    VMM logs the saved path ("Layer saved to: ...") and this test IS
    the operator: parse the log line and use the named path.
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


def phase_named_export(extra_args: list[str], requested: str, expected: str) -> None:
    """A usable requested name lands as <name>.layer in the VMM's cwd."""
    # The test owns its names: a stale target (an earlier aborted run)
    # would trip the never-overwrite rule and fall back.
    target = pathlib.Path.cwd() / expected
    target.unlink(missing_ok=True)
    vm = Vm(extra_args)
    try:
        vm.boot("named export boot")
        vm.run("echo NAMED_MAGIC > /root/named.txt; echo WRITE\"\"_DONE", "WRITE_DONE")
        vm.run(f"sandal-export {requested}", "Layer exported", count=1)
        saved = re.findall(rb"Layer saved to: ([^\s\r]+)", vm.buf)
    finally:
        vm.close()
    if not saved or saved[-1].decode() != expected:
        raise AssertionError(
            f"export: requested {requested!r}, saved {saved[-1:]!r}, want {expected!r}"
        )
    layer = pathlib.Path.cwd() / expected
    if not layer.is_file():
        raise AssertionError(f"export: {layer} was not created on the host")
    validate_layer(layer, "/root/named.txt", b"NAMED_MAGIC")
    layer.unlink()


def phase_fallback_export(extra_args: list[str], requested: str) -> None:
    """An unusable requested name (traversal, bad charset) falls back to
    the content-addressed name and nothing named like the request lands
    in the VMM's cwd."""
    vm = Vm(extra_args)
    try:
        vm.boot("fallback export boot")
        vm.run("echo FALLBACK_MAGIC > /root/fallback.txt; echo WRITE\"\"_DONE", "WRITE_DONE")
        vm.run(f"sandal-export {requested}", "Layer exported", count=1)
        saved = re.findall(rb"Layer saved to: ([^\s\r]+)", vm.buf)
    finally:
        vm.close()
    if not saved:
        raise AssertionError("export: the VMM never named a saved layer")
    saved_name = saved[-1].decode()
    if not re.fullmatch(r"layer-[0-9a-f]{16}\.layer", saved_name):
        raise AssertionError(
            f"export: requested {requested!r} saved as {saved_name!r} — "
            "the content-addressed fallback did not fire"
        )
    if (pathlib.Path.cwd() / saved_name).is_file():
        (pathlib.Path.cwd() / saved_name).unlink()
    for p in pathlib.Path.cwd().glob("evil*"):
        raise AssertionError(f"export: a traversal name escaped: {p}")


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

        print("export (named): honoring a sanitized requested name...")
        phase_named_export(["--disk-size", "64"], "foo.layer", "foo.layer")
        print("export (named): .layer appended when missing...")
        phase_named_export([], "mylayer", "mylayer.layer")
        print("export (named): a traversal attempt falls back, nothing escapes...")
        phase_fallback_export(["--disk-size", "64"], "../evil")

        print("export (full): the specified layers + the upper, no base rootfs...")
        vm = Vm(["--disk-size", "64", "--layer", str(disk_layer)])
        try:
            vm.boot("full boot")
            vm.run(
                'echo FULL_MAGIC > /root/full.txt; echo WRITE""_DONE',
                "WRITE_DONE",
            )
            vm.run("sandal-export --full consolidated.layer", "Layer exported", count=1)
            saved = re.findall(rb"Layer saved to: ([^\s\r]+)", vm.buf)
        finally:
            vm.close()
        if not saved or saved[-1].decode() != "consolidated.layer":
            raise AssertionError(
                f"export full: saved {saved[-1:]!r}, want consolidated.layer"
            )
        layer = pathlib.Path.cwd() / "consolidated.layer"
        import layer_ref

        raw = layer.with_suffix(".tar")
        raw.write_bytes(layer_ref.decompress_layer(layer))
        with tarfile.open(raw, "r:") as tf:
            names = [m.name.lstrip("./") for m in tf.getmembers()]
        raw.unlink()
        layer.unlink()
        if "root/full.txt" not in names:
            raise AssertionError(f"export full: the runtime file missing: {names}")
        if "root/roundtrip.txt" not in names:
            raise AssertionError(
                f"export full: the specified layer's file missing: {names}"
            )
        if any(n == "bin" or n.startswith("bin/") or n == "usr" for n in names):
            raise AssertionError("export full: the base rootfs leaked into the layer")
        print("export (full): the layers + the upper, the base ignored: OK", flush=True)


if __name__ == "__main__":
    sys.exit(test_main("export", main))
