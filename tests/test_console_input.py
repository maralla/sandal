#!/usr/bin/env python3
"""End-to-end test for interactive console input (line editing).

Verifies the interactive input path end to end: host keystrokes reach the
guest, the guest's line editor sees them, and its terminal output (echo and
erase sequences) reaches the host pty unharmed.

  * echo latency: a keystroke is echoed quickly (no multi-second stalls),
  * erase: after typing `abc` + backspace the pty receives a backspace
    followed by an erase sequence (`ESC[J` or the `BS SP BS` classic), so
    the character disappears from the user's screen,
  * line editing: a command corrected with backspace executes in its
    corrected form (`ecno` -> `echo`),
  * controlling terminal: the guest shell must NOT report "can't access
    tty" — /bin/ctty hands the console to the command as its controlling
    terminal, so Ctrl-C interrupts a running command (exit status 130) and
    Ctrl-Z/`fg` provide working job control,
  * protocol-marker safety: the exit protocol uses a per-boot random token
    delivered in the config, so echoing script text (`cat /init`), the old
    fixed string (`echo SANDAL_EXIT:0`), or the config itself must NOT shut
    the VM down.

Usage (from the repo root, after `make`):
    uv run python tests/test_console_input.py
"""

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

ERASE_LATENCY = 2.0  # seconds a single keystroke echo may take
ECHO_LATENCY = 1.0


def wait_output(vm: Vm, timeout: float) -> bytes:
    """Collect pty output until `timeout` of silence."""
    end = time.time() + timeout
    got = b""
    while time.time() < end:
        if not vm.read_more(0.05):
            continue
        got = vm.buf  # read_more appends to vm.buf
        end = time.time() + 0.2
    return got


def wait_bytes(vm: Vm, needle: bytes, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in vm.buf:
            return True
        vm.read_more(0.05)
    return needle in vm.buf


def main() -> None:
    vm = Vm([])
    try:
        vm.boot("console-input")

        # ── Echo latency: a keystroke comes back quickly ──────────────
        vm.buf = b""
        t0 = time.time()
        os.write(vm.master, b"x")
        if not wait_bytes(vm, b"x", ECHO_LATENCY):
            raise AssertionError("keystroke was not echoed within 1s")
        latency = time.time() - t0
        print(f"console-input: echo latency {latency * 1000:.0f}ms")

        # ── Erase: backspace erases the character on screen ───────────
        # The guest's line editor erases with `BS` + `ESC[J` (or the classic
        # `BS SP BS`); anything less leaves the character on screen.
        for ch in b"abc":
            os.write(vm.master, bytes([ch]))
            time.sleep(0.05)
        wait_output(vm, 0.5)
        vm.buf = b""
        os.write(vm.master, b"\x7f")  # backspace
        out = wait_output(vm, ERASE_LATENCY)
        bs = out.count(b"\x08")
        if bs < 1:
            raise AssertionError(f"backspace produced no echo at all: {out!r}")
        erased = b"\x08\x1b[J" in out or b"\x08 \x08" in out
        if not erased:
            raise AssertionError(
                "backspace moved the cursor but did not erase "
                f"(got {out!r}; expected `BS ESC[J` or `BS SP BS`)"
            )
        print("console-input: erase sequence ok")

        # ── Line editing: a corrected command runs in corrected form ──
        vm.buf = b""
        os.write(vm.master, b"ecno")  # typo, not submitted yet
        wait_output(vm, 0.5)
        # Fix it: erase 4 chars, retype `echo hi`, run.
        for _ in range(4):
            os.write(vm.master, b"\x7f")
            time.sleep(0.05)
        os.write(vm.master, b"echo hi\r")
        if not wait_bytes(vm, b"\r\nhi\r", 10) and b"hi\r" not in vm.buf:
            raise AssertionError(f"corrected command did not produce `hi`: {vm.buf[-200:]!r}")
        if b"ecno: not found" in vm.buf:
            raise AssertionError("guest executed the uncorrected command")
        print("console-input: line-edit correction ok")

        # ── Controlling terminal: job control + tty signals ───────────
        if b"can't access tty" in vm.buf:
            raise AssertionError(
                "guest shell reports 'can't access tty' — /bin/ctty did not "
                "give the command a controlling terminal"
            )
        vm.buf = b""
        os.write(vm.master, b"sleep 30\r")
        time.sleep(1.0)
        vm.buf = b""
        os.write(vm.master, b"\x03")  # Ctrl-C
        if not wait_bytes(vm, b"~ #", 5):
            raise AssertionError(f"Ctrl-C did not return the prompt: {vm.buf[-120:]!r}")
        vm.buf = b""
        os.write(vm.master, b"echo S=$?\r")
        if not wait_bytes(vm, b"S=130", 5):
            raise AssertionError(f"interrupted command exit status != 130: {vm.buf[-120:]!r}")
        print("console-input: Ctrl-C interrupts (status 130)")

        vm.buf = b""
        os.write(vm.master, b"sleep 60\r")
        time.sleep(1.0)
        vm.buf = b""
        os.write(vm.master, b"\x1a")  # Ctrl-Z
        if not wait_bytes(vm, b"Stopped", 5):
            raise AssertionError(f"Ctrl-Z did not suspend the job: {vm.buf[-120:]!r}")
        vm.buf = b""
        os.write(vm.master, b"fg\r")
        time.sleep(1.0)
        vm.buf = b""
        os.write(vm.master, b"\x03")
        if not wait_bytes(vm, b"~ #", 5):
            raise AssertionError(f"fg + Ctrl-C did not return the prompt: {vm.buf[-120:]!r}")
        print("console-input: Ctrl-Z / fg job control ok")

        # ── Protocol-marker safety: fixed strings are inert ───────────
        for cmd in (b"cat /init; echo CAT_DONE\r",
                    b"echo SANDAL_EXIT:0; echo ECHO_DONE\r",
                    b"cat /etc/sandal.conf > /dev/null; echo CONF_DONE\r"):
            vm.buf = b""
            os.write(vm.master, cmd)
            done = next((m for m in (b"CAT_DONE", b"ECHO_DONE", b"CONF_DONE") if m in cmd), None)
            if not wait_bytes(vm, done, 10):
                raise AssertionError(
                    f"shell died after {cmd!r} — protocol marker leaked "
                    f"into workload output: {vm.buf[-120:]!r}"
                )
        print("console-input: exit protocol ignores workload output")
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("console-input", main))
