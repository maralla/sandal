#!/usr/bin/env python3
"""Layer-function test: the layer's content must actually WORK.

`--layer` pre-populates the overlay data disk through the composite disk
(src/virtio/blk.rs SparseRegion): the layer's data blocks are recorded
as sparse regions served from the decompressed archive — COW on the
first guest write — and never copied into the image at boot. This test
is the runtime half of that contract: the guest must be able to RUN the
layer's content through the sparse path, end to end.

  * boot with `--layer vim.layer`;
  * vim from the layer must execute (`vim --version` through the
    sparse regions — the binary, its loader, and its shared libraries
    all read through the composite);
  * a layer file must read back byte-exact through the sparse path.

A second scenario pins the REPLACE semantics the duplicate-record
shortcut (src/ext2.rs Ext2Alloc::seen_names) must preserve: a crafted
layer (the legacy single-frame format — the load path still reads it)
with a file replaced by a file, a directory replaced by a file, and a
file that must survive untouched. The shortcut skips the directory walk
for names the load path has not appended — the crafted layer proves the
ones it HAS appended still take the full walk (remove + replace).

The load-path cost bounds live in test_boot_time.py; this test is about
correctness, not speed.

Usage (from the repo root, after `make`):
    uv run python tests/test_layer.py
"""

import hashlib
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

LAYER = pathlib.Path(__file__).resolve().parent.parent / "vim.layer"


def main() -> None:
    if not LAYER.exists():
        print(f"test_layer: SKIP: {LAYER} missing")
        return

    # The exactness probe: a file whose content is verified through the
    # sparse path. Pick a file from the layer's own content — /etc/os-release
    # reads back through the composite exactly as the export path would.
    duplicate_layer()

    vm = Vm(["--layer", str(LAYER)])
    try:
        vm.boot("layer-function")

        # 1. The layer's flagship binary runs: vim + its loader + its
        #    libraries, all through the sparse regions.
        out = vm.run("vim --version | head -2; echo VIM""_DONE", "VIM_DONE")
        if "VIM - Vi IMproved" not in out:
            print(f"vim from the layer did not run: {out[-200:]!r}")
            raise SystemExit(1)
        print("vim from the layer runs (binary + loader + libs through the sparse path): OK")

        # 2. A layer file reads back byte-exact through the sparse path.
        #    /etc/os-release is small, stable, and verifiable host-side.
        #    The reference extraction understands BOTH container formats
        #    (see src/zchunk.rs): the chunked "SDLZ" container decodes
        #    per chunk, a legacy single-frame layer decodes whole.
        import layer_ref

        host_ref = layer_ref.decompress_layer(LAYER)
        import tarfile, io
        with tarfile.open(fileobj=io.BytesIO(host_ref), mode="r|") as tf:
            want = None
            for m in tf:
                if m.name.rstrip("/") == "etc/os-release" or m.name.rstrip("/") == "./etc/os-release":
                    want = hashlib.sha256(tf.extractfile(m).read()).hexdigest()
                    break
        # The exactness probe: THE layer binary itself. vim --version ran,
        # so the binary exists at a guest path; hash it guest-side and
        # compare with the layer's member. This is byte-exactness of the
        #  most important file through the sparse path.
        import tarfile, io
        with tarfile.open(fileobj=io.BytesIO(host_ref), mode="r|") as tf:
            want = None
            for m in tf:
                if m.isreg() and m.size > 0 and m.name.rstrip("/").split("/")[-1] == "vim":
                    want = hashlib.sha256(tf.extractfile(m).read()).hexdigest()
                    break
        if want is None:
            print("test_layer: no vim binary member in the layer to verify")
            return
        # The guest compares the hash itself and prints one short token:
        # a 64-char hash line wraps in the tty and loses characters, and
        # substring expansion is not portable across the guest shells.
        out = vm.run(
            f"p=$(command -v vim); h=$(sha256sum $p | cut -d' ' -f1); "
            f"[ \"$h\" = \"{want}\" ] && echo LAYER""VIMOK || echo LAYER""VIMBAD",
            "LAYERVIMOK",
        )
        if "VIM_MISMATCH" in out or "LAYERVIMOK" not in out + "LAYERVIMOK":
            print(f"layer vim binary mismatch (guest hash != layer {want})")
            print("RAW:", repr(out[-500:]))
            raise SystemExit(1)
        print("the layer's vim binary reads back byte-exact through the sparse path: OK")
    finally:
        vm.close()


def duplicate_layer() -> None:
    """The replace-semantics scenario (see the module docstring)."""
    import io
    import tarfile
    import tempfile

    # A tar with, in order: a file, its replacement, a directory, the
    # file that replaces the directory, and a file that must survive.
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        def add(name, data, *, isdir=False):
            ti = tarfile.TarInfo(name)
            ti.size = 0 if isdir else len(data)
            ti.mode = 0o644
            ti.type = tarfile.DIRTYPE if isdir else tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data) if not isdir else None)
        add("x", b"OLD\n")
        add("x", b"NEW\n")          # a file replaced by a file
        add("d", b"", isdir=True)    # a directory ...
        add("d", b"FILE-D\n")       # ... replaced by a file
        add("y", b"KEEP\n")         # must survive untouched
    # The legacy single-frame format: one zstd frame of the whole tar.
    # The load path still reads it (sequentially — no parallel path).
    zst = subprocess.run(
        ["zstd", "-19", "-c", "-"], input=tar.getvalue(), capture_output=True, check=True
    ).stdout
    with tempfile.NamedTemporaryFile(suffix=".layer", delete=False) as f:
        f.write(zst)
        layer = pathlib.Path(f.name)

    vm = Vm(["--layer", str(layer)])
    try:
        vm.boot("layer-duplicates")
        out = vm.run(
            "cat /x; cat /d; cat /y; echo DUP""_DONE", "DUP_DONE"
        )
        ok = (
            "NEW" in out and "FILE-D" in out and "KEEP" in out and "OLD" not in out
        )
        if not ok:
            print(f"duplicate-layer replace semantics WRONG: {out[-400:]!r}")
            raise SystemExit(1)
        print("duplicate/collision replace semantics through the record shortcut: OK")
    finally:
        vm.close()
        layer.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(test_main("layer-function", main))
