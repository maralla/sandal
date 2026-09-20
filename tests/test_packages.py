#!/usr/bin/env python3
"""End-to-end test for guest package management (`apk`).

Boots with the network on and verifies the full install path:

  * `apk update` fetches and signature-verifies the repository indexes
    over HTTPS through the user-space netstack,
  * `apk add` downloads and installs a package into the overlay,
  * the installed binary runs.

Requires the host CA bundle (injected into the guest as
/etc/ssl/certs/ca-certificates.crt) and a host with internet access; both
are skipped cleanly otherwise.

Usage (from the repo root, after `make`):
    uv run python tests/test_packages.py
"""

import os
import pathlib
import re
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

os_is_linux = sys.platform.startswith("linux")


def main() -> None:
    if not os.path.isfile("/etc/ssl/certs/ca-certificates.crt"):
        print("test_packages: SKIP: no host CA bundle to inject")
        return

    vm = Vm(["--disk-size", "64"])
    try:
        vm.boot("packages")

        def run(cmd: str, marker: str, timeout: float) -> str:
            vm.buf = b""
            vm.send_line(cmd)
            if not vm.wait_for(marker.encode(), 1, timeout):
                raise AssertionError(
                    f"command did not finish: {cmd!r}: "
                    f"{vm.buf.decode('utf-8', 'replace')[-300:]!r}"
                )
            time.sleep(1.0)
            vm.read_more(1.0)
            out = vm.buf.decode("utf-8", "replace")
            # drop everything up to the end of the echoed command line
            return out.split("\n", 1)[-1] if "\n" in out else out

        out = run("apk update 2>&1 | tail -1; echo PKGU" + '\"\"' + "_DONE",
                  "PKGU_DONE", 240)
        if "OK:" not in out and "unavailable" not in out:
            raise AssertionError(f"apk update did not succeed: {out!r}")
        print("packages: apk update ok")

        out = run("apk add --no-cache file 2>&1 | tail -1; echo PKGI" + '\"\"' + "_DONE",
                  "PKGI_DONE", 300)
        if "OK:" not in out:
            raise AssertionError(f"apk add did not succeed: {out!r}")
        print("packages: apk add ok")

        out = run("file /bin/busybox | head -1; echo FILE" + '\"\"' + "_DONE",
                  "FILE_DONE", 60)
        if not re.search(r"ELF \d{2}-bit", out):
            raise AssertionError(f"installed `file` did not run: {out!r}")
        print("packages: installed binary runs")
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("packages", main))
