#!/usr/bin/env python3
"""Regression test: the session's default directory is the HOME directory.

The command execution line's sessions inherit the init's cwd: the init
`cd /root`s into the home directory, and the line starts after — every
session it forks lands in the home, and the shell's own prompt renders
the HOME-abbreviated form (`~ # `).

The regression this test pins: the line's start moved BEFORE the cd (the
daemon start block sits early in the init), so every session
inherited the pre-cd cwd — which, after the pivot_root, resolved to the
pivoted root's `/` — and the shell's own prompt rendered it (MEASURED:
`pwd` printed `/`, the prompt `/ # `). The cd now comes first; this test
asserts the restored contract end to end:

  1. the session's prompt is the HOME-abbreviated form (`~ # `);
  2. `pwd` inside the session prints `/root` — never `/`.

Usage (from the repo root, after `make`):
    uv run python tests/test_default_cwd.py
"""

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402


def main() -> None:
    vm = Vm(command=("sh",))
    try:
        vm.boot("default-cwd")

        # 1. The prompt form: the HOME-abbreviated one. The harness's
        #    PROMPTS tuple accepts both forms (a session may legitimately
        #    cd away), but the DEFAULT is the home — the boot prompt is
        #    the session's first rendering of its own cwd.
        if b"~ #" not in vm.buf:
            raise AssertionError(
                "the boot prompt is not the HOME form (`~ # `): "
                f"{vm.buf[-120:]!r}"
            )

        # 2. The cwd itself, from the session's own mouth.
        vm.buf = b""
        vm.send_line("pwd; echo PWD\"\"_DONE")
        if not vm.wait_for(b"PWD_DONE", 1, 30):
            raise AssertionError("pwd did not run")
        lines = [
            line.strip()
            for line in vm.buf.decode("utf-8", "replace").splitlines()
        ]
        if "/root" not in lines:
            raise AssertionError(f"pwd did not print /root: {lines[-8:]!r}")
        if "/" in lines:
            raise AssertionError(f"pwd printed the pivoted root's `/`: {lines[-8:]!r}")
        print("default-cwd: the home directory is the default (`~`, /root): OK")
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("default-cwd", main))
