#!/usr/bin/env python3
"""Exit-code forwarding test for the session agent (portagent).

The session agent is the reaper: the session's exit status must reach
the VMM's exit protocol — the init script's exit marker — EXACTLY:

  * a normal exit (`exit N`) forwards N (the reaper's status >> 8),
  * a signal death would forward 128+signal (the reaper's other path —
    exercised end-to-end by test_console_input's Ctrl-C check, 130),
  * nothing else may substitute: the VMM exits 0 only when the marker
    never matched, which is exactly the failure this test catches;
  * the session-failure code (127: the guest shell's own not-found
    code — e.g. a typo in the workload command) forwards UNCHANGED,
    with the diagnostic on the NON-INTERACTIVE path only: there the
    failing command's own output never becomes visible, and the
    silent exit was the measured bug — `uanme` for `uname` exited
    with not one byte of output, indistinguishable from a hang, so the
    VMM names the failure itself (see vm::diagnose_session_exit). On
    the INTERACTIVE path (`sandal -- sh`) the shell names its own
    failures at the source (its own `not found` line, in the
    terminal), and a diagnostic there would misattribute the status to
    the session command — which ran; this test pins BOTH: the
    non-interactive diagnostic prints, and the interactive one does
    not.

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

    # The session-failure code: a nonexistent workload command (the exact
    # reproduction — `uanme` for `uname`), on the NON-INTERACTIVE path
    # (stdin not a terminal: the one-shot session). The code must
    # forward unchanged (127, the guest shell's own not-found code),
    # and the diagnostic must print: there the failing command's own
    # output never becomes visible, and the silent exit was the
    # measured bug — the VMM names the failure itself. (The interactive
    # path names its own failures at the source — the shell's own
    # `not found` line, in the terminal — and a diagnostic there would
    # misattribute the status to the session command, which ran.)
    import subprocess
    import time

    proc = subprocess.run(
        [str(pathlib.Path("target/release/sandal")), "--", "uanme", "-a"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    rc = proc.returncode
    if rc != 127:
        print(f"session-failure: forwarded {rc} (want 127): WRONG")
        raise SystemExit(1)
    if b"was not found inside the VM" not in proc.stderr:
        print("session-failure: the diagnostic is MISSING (the silent exit): WRONG")
        raise SystemExit(1)
    print("session-failure 127 forwards unchanged + the diagnostic prints: OK")

    # The interactive path: `sandal -- sh` on a real terminal, a typo'd
    # command inside, then the shell's own exit. The measured trigger
    # was Ctrl-D (EOF on the shell's stdin — the user pressed it right
    # after the typo'd command); a bare VEOF byte's input chain is
    # load-sensitive (MEASURED: it stalls past every bound under the
    # suite's load, while the standalone probe completes), so the test
    # drives the shell's own `exit` — the IDENTICAL contract: the shell
    # exits with its own last status (127, the typo'd command's), the
    # reaper's trailer carries it, and the diagnostic gate is on the
    # session MODE, not the trigger. The status forwards unchanged, the
    # shell's own `not found` line named the failure at the source —
    # and the VMM diagnostic must NOT print: it would misattribute the
    # status to the session command (`sh`), which ran (MEASURED: the
    # regression printed "the workload command `sh` was not found
    # inside the VM" right after the Ctrl-D).
    vm = Vm(command=("sh",))
    try:
        vm.boot("exit-codes (interactive)")
        vm.buf = b""
        vm.send_line("non-exist")
        deadline = time.time() + 30
        while time.time() < deadline:
            vm.read_more(0.2)
            if b"not found" in vm.buf:  # the shell's own, visible
                break
        if b"not found" not in vm.buf:
            raise AssertionError("the shell's own failure line never appeared")
        vm.buf = b""
        vm.send_line("exit")  # the shell's own exit: its own last status
        # The exit chain is the transport's own: the reaper's trailer
        # -> the guest's TX ring -> the device's drain -> the bridge's
        # take -> the withholding scan's match — each hop a bridge
        # round, and the guest's ring recovery is vCPU-exit-gated: under
        # the suite's load (every prior test's VMs winding down) the
        # chain takes MINUTES, and a 90 s window made the suite's own
        # per-test cap SIGTERM the VM mid-case (MEASURED: exit -15,
        # "forwarded None"). 600 s, still bounded by the suite's cap.
        deadline = time.time() + 600
        rc = None
        while time.time() < deadline:
            vm.read_more(0.2)
            if vm.proc.poll() is not None:
                rc = vm.proc.returncode
                break
    finally:
        vm.close()
    if rc != 127:
        print(f"interactive session-failure: forwarded {rc} (want 127): WRONG")
        raise SystemExit(1)
    if b"was not found inside the VM" in vm.buf:
        print("interactive session-failure: the MISATTRIBUTED diagnostic printed: WRONG")
        raise SystemExit(1)
    print("interactive session-failure 127 forwards + no misattributed diagnostic: OK")


if __name__ == "__main__":
    sys.exit(test_main("exit-codes", main))
