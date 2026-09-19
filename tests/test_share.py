#!/usr/bin/env python3
"""End-to-end test for shared host directories (`--share host:guest`).

Boots the sandal VM with a virtiofs share and verifies both directions:

  * host -> guest: the guest reads a file created on the host,
  * guest -> host: the guest creates files (incl. a nested directory) and the
    host sees them with the expected content.

Requires the codesigned release binary (`make`) and macOS/HVF.

Usage (from the repo root, after `make`):
    uv run python tests/test_share.py
"""

import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

HOST_MARKER = "SHARE_HOST_MARKER_7f3a"
GUEST_MARKER = "SHARE_GUEST_MARKER_9c1e"
GUEST_PATH = "/mnt/share"


def wait_host_file(path: pathlib.Path, content: str, timeout: float = 10.0) -> str:
    """Poll `path` until it contains `content` (virtiofs writes are async)."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        if path.is_file():
            last = path.read_text(errors="replace")
            if last == content:
                return last
        time.sleep(0.2)
    return last


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sandal-share-test-") as tmp_dir:
        tmp = pathlib.Path(tmp_dir)
        (tmp / "host_to_guest.txt").write_text(HOST_MARKER + "\n")

        print("share: booting with --share ...")
        vm = Vm(["--disk-size", "64", "--share", f"{tmp}:{GUEST_PATH}"])
        try:
            vm.boot("share")

            print("share: host -> guest read...")
            out = vm.run(
                f"cat {GUEST_PATH}/host_to_guest.txt; echo READ_DONE",
                "READ_DONE",
            )
            if HOST_MARKER not in out:
                raise AssertionError("share: host file content missing in guest")

            print("share: guest -> host write (file + nested dir)...")
            vm.run(
                f"echo {GUEST_MARKER} > {GUEST_PATH}/from_guest.txt; "
                f"mkdir -p {GUEST_PATH}/sub; "
                f"echo {GUEST_MARKER}_nested > {GUEST_PATH}/sub/nested.txt; "
                "sync; echo WRITE_DONE",
                "WRITE_DONE",
            )
        finally:
            vm.close()

        content = wait_host_file(tmp / "from_guest.txt", GUEST_MARKER + "\n")
        if content != GUEST_MARKER + "\n":
            raise AssertionError(
                f"share: from_guest.txt content {content!r} != {GUEST_MARKER!r}"
            )
        nested = wait_host_file(tmp / "sub" / "nested.txt", GUEST_MARKER + "_nested\n")
        if nested != GUEST_MARKER + "_nested\n":
            raise AssertionError(f"share: nested.txt content {nested!r}")


if __name__ == "__main__":
    sys.exit(test_main("share", main))
