#!/usr/bin/env python3
"""Exit-code forwarding test for the session agent (portagent).

The session agent is the reaper: the session's exit status must reach
the VMM's exit protocol — the init script's exit marker — EXACTLY:

  * a normal exit (`exit N`) forwards N (the reaper's status >> 8),
  * a signal death would forward 128+signal (the reaper's other path —
    exercised end-to-end by test_console_input's Ctrl-C check, 130),
  * nothing else may substitute: the VMM exits 0 only when the marker
    never matched, which is exactly the failure this test catches.

The agent is pure machine code drafted with the x86_64 DSL
(src/initramfs/tools/x86_64/portagent.rs — its program documentation is
the reference). This test is what caught the draft's first bug: the
reaper's `and 0xff` destroyed the status before the normal path's
`shr 8` re-read it — every code forwarded as 0.

Usage (from the repo root, after `make`):
    uv run python tests/test_exit_codes.py
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# Normal exits across the range: small, mid, the shell-convention signal
# slot (128+2 — the same value test_console_input's Ctrl-C path produces,
# here through the NORMAL path), and the 8-bit maximum.
CODES = [42, 7, 130, 255]


def main() -> None:
    for code in CODES:
        vm = Vm()
        try:
            vm.boot()
            vm.send_line(f"exit {code}")
            deadline = __import__("time").time() + 60
            rc = None
            while __import__("time").time() < deadline:
                vm.read_more(0.2)
                if vm.proc.poll() is not None:
                    rc = vm.proc.returncode
                    break
        finally:
            vm.close()
        if rc != code:
            print(f"exit {code}: forwarded {rc} (want {code}): WRONG")
            raise SystemExit(1)
        print(f"exit {code}: forwarded {rc}: OK")


if __name__ == "__main__":
    sys.exit(test_main("exit-codes", main))
