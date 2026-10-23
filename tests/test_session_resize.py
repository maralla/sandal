#!/usr/bin/env python3
"""The session line's resize regression: vi under a live pty resize.

The reported freeze: `sandal -- sh`, `vi /init`, then the terminal
zooms (a SIGWINCH on the host pty) — and the pane hung for good: no
redraw, no cursor motion, no input effect. The mechanism (measured on
the broken build):

  * the device's inject retry pulse returned `true` — progress — and
    reset its own pacing, so every bridge round pulsed the guest IRQ;
    the guest spun through interrupt-ack MMIO exits at ~215 Hz while
    its deferred transport workers starved;
  * the bridge's poll asked POLLOUT on the session's stdin (always
    ready) and never actually parked, so the spin ran at full speed;
  * a graceful close was missing (a fast one-shot's output and its
    SHUTDOWN landed inside one bridge round; the connection vanished
    out from under the parked socket and the client read EOF with
    zero bytes);
  * the guest's vsockd answered the stalls with fork/exit "storms" —
    a child torn down per write, per timer tick — which made every
    byte pay a fork and papered over the livelock instead of fixing
    it.

This test walks the exact scenario against the REAL session line (the
host pty as the terminal) and asserts the contract that froze: the
resize redrew the editor, and the session still answered input after
it. It then hammers the chain — a paste burst behind the resize, an
output burst through it — because the short paths passed all session
while the real one froze.

Key sequences follow a real terminal: Escape, then the ex command, as
SEPARATE writes (batching ESC with a command changes what busybox vi
parses — its escape-sequence handling eats the next byte, which is the
editor's semantics, not the transport's).

Usage (from the repo root, after `make`):
    uv run python tests/test_session_resize.py
"""

import fcntl
import pathlib
import struct
import sys
import termios
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The session must answer input within this bound after a resize: the
# chain is SIGWINCH → the RSZ1 record → TIOCSWINSZ → vi's redraw — and
# then the NEXT keystroke must still land. The frozen build never
# answered at all.
ANSWER_DEADLINE = 30.0

# The zoomed geometry (the harness pty starts at 120x40).
SMALL_ROWS, SMALL_COLS = 24, 80
BIG_ROWS, BIG_COLS = 40, 120


def resize_pty(vm, rows: int, cols: int) -> None:
    fcntl.ioctl(vm.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def wait_for(vm, needle: bytes, timeout: float) -> bool:
    deadline = time.time() + timeout
    vm.buf = b""
    while time.time() < deadline:
        vm.read_more(0.2)
        if needle in vm.buf:
            return True
    return False


def main() -> None:
    vm = Vm(command=("sh",))
    try:
        vm.boot("session-resize")

        # vi on a file with more lines than the window: the redraw is
        # real output, and the resize must reach it (the editor's
        # status line carries the file name — a live redraw's proof).
        vm.send_line("vi /init")
        if not wait_for(vm, b"- /init", 30):
            raise AssertionError("vi never started")

        # ── The zoom: the reported freeze ───────────────────────────
        # Shrink the pty: SIGWINCH → the RSZ1 record → the guest's
        # session re-sizes itself → vi redraws at the new geometry.
        resize_pty(vm, SMALL_ROWS, SMALL_COLS)
        if not wait_for(vm, b"24;1H", ANSWER_DEADLINE):
            raise AssertionError(
                "the resize never redrew the editor (the reported freeze)"
            )

        # ── Input after the resize: the other half of the freeze ────
        # Cursor motion: three downs, the status line's row follows
        # (the row prefix only — the file's line count is not the
        # test's business).
        vm.send_raw(b"j")
        vm.send_raw(b"j")
        vm.send_raw(b"j")
        if not wait_for(vm, b"/init 4/", ANSWER_DEADLINE):
            raise AssertionError(
                "the session stopped answering input after the resize"
            )

        # Quit vi exactly as a terminal would: Escape, then the ex
        # command, as separate writes.
        vm.send_raw(b"\x1b")
        time.sleep(0.3)
        vm.send_raw(b":q!\r")
        if not wait_for(vm, b"~ #", ANSWER_DEADLINE):
            raise AssertionError("vi never quit after the resize")

        # ── The chain under load ────────────────────────────────────
        # A resize while a paste burst is in flight, then the resize
        # back — the session must still answer through both.
        resize_pty(vm, BIG_ROWS, BIG_COLS)
        vm.send_raw(b"true\n" * 200)
        if not wait_for(vm, b"~ #", ANSWER_DEADLINE):
            raise AssertionError("the paste burst behind the resize stalled")
        vm.send_line("echo PASTE_DRAINED")
        if not wait_for(vm, b"PASTE_DRAINED", ANSWER_DEADLINE):
            raise AssertionError("the shell never answered after the paste")

        resize_pty(vm, SMALL_ROWS, SMALL_COLS)
        vm.send_line("echo RESIZE_OK1")
        if not wait_for(vm, b"RESIZE_OK1", ANSWER_DEADLINE):
            raise AssertionError("the session stalled after the second resize")

        # ── Output through the resize ───────────────────────────────
        # A burst of output spanning the resize (a redraw-sized stream
        # against a moving window), then one more input answer.
        resize_pty(vm, BIG_ROWS, BIG_COLS)
        vm.send_line("head -c 200000 /dev/zero | tr '\\0' 'x'; echo; "
                     "echo OUT_BURST_OK")
        if not wait_for(vm, b"OUT_BURST_OK", ANSWER_DEADLINE):
            raise AssertionError("the output burst through the resize stalled")
    finally:
        vm.close()


main_ok = test_main("session-resize", main)
sys.exit(main_ok)
