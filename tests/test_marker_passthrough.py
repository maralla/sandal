#!/usr/bin/env python3
"""Legacy marker strings are inert — the console protocol is GONE.

The VMM once scanned the guest's output stream for protocol markers
(`<token><status>`, `SESSION:port`, `SANDAL_EXPORT_PATH:`). A marker
matched ANYWHERE turned into the vim screen-desync bug (a marker
drawn mid-redraw swallowed the rest of a newline-less TUI burst), and
even the token-authenticated, line-anchored redesign was still a
STRING PROTOCOL — user output could imitate it by design.

The protocol is marker-free now: the exit code rides the hypercall page
(`sandal-exit`), the session routing rides the virtio-console control
queue (the driver's own PORT_OPEN(1)), the export path rides a
dedicated port. Nothing scans user-visible streams — there is no
string to match. This test guards the whole boundary:

  * the vim shape — legacy marker text mid-line, then a no-newline
    burst: every byte must still arrive;
  * a line-initial legacy marker (the old protocol shape) is just
    output: it streams through verbatim and captures nothing;
  * the real protocols still work — the exit code forwards (the
    hypercall), and no layer is written from user content.

Usage (from the repo root, after `make`):
    uv run python tests/test_marker_passthrough.py
"""

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The no-newline burst after the mid-line marker text: big enough that
# the old anywhere-match (which ate it whole) cannot pass by accident.
BURST_BYTES = 2000

# The fixed export marker text: a line starting with it is user content
# now (the protocol echoes `<token>SANDAL_EXPORT_PATH:`), and must both
# stream through and not be captured as an export path.
FIXED_MARKER = "SANDAL_EXPORT_PATH:"


def main() -> None:
    vm = Vm()
    try:
        vm.boot("marker passthrough boot")

        # ── Mid-line marker text: the vim shape ──────────────────────
        # Marker text inside a drawn row, then a burst with NO newline
        # (a TUI redraw positions with escape sequences, never `\n`).
        # The old filter swallowed everything from the marker to the
        # next `\n` — the whole burst here, and on a real TUI stream
        # every burst after it too.
        vm.run(
            "printf 'row text SANDAL_EXPORT_PATH: more row text; '"
            " && head -c {n} /dev/zero | tr '\\0' T"
            " && printf '\\r\\nTAIL%s_OK\\r\\n' \"\"".format(n=BURST_BYTES),
            "TAIL_OK",
        )
        arrived = vm.buf.count(b"T")
        if arrived < BURST_BYTES:
            print(
                f"mid-line marker: only {arrived} of {BURST_BYTES} "
                "no-newline burst bytes arrived: WRONG"
            )
            raise SystemExit(1)
        print(f"mid-line marker: {arrived} burst bytes streamed through: OK")

        # ── The next command's output still arrives ──────────────────
        # The vicious tail of the old bug: with no `\n` anywhere, the
        # suppression ran on — the NEXT command's output vanished too.
        vm.run("echo AFTER""_MARKER", "AFTER_MARKER")
        print("post-burst output: the next command streamed through: OK")

        # ── A line-initial FIXED marker is user content now ──────────
        # The export protocol echoes `<token>SANDAL_EXPORT_PATH:`; a
        # line starting with the fixed marker text alone is just output.
        # It must stream through verbatim — the old fixed-marker match
        # swallowed it — and must not be captured: a capture would write
        # a layer to that path at shutdown.
        false_layer = f"/tmp/sandal-marker-false-positive-{os.getpid()}.layer"
        vm.run(
            f"printf '\\r\\n{FIXED_MARKER}{false_layer}\\r\\n'"
            " && printf 'STREAMED%s_OK\\r\\n' ''",
            "STREAMED_OK",
        )
        if (FIXED_MARKER + false_layer).encode() not in vm.buf:
            print("fixed marker line: swallowed instead of streamed: WRONG")
            raise SystemExit(1)
        print("fixed marker line: streamed through verbatim: OK")

        # ── The line-initial protocol still works ────────────────────
        # The exit code rides a whole line; line-anchored matching must
        # still catch it (the port copy may land mid-line after a
        # newline-less session tail — the console echo is the backup).
        vm.send_line("exit 42")
        rc = None
        deadline = time.time() + 60
        while time.time() < deadline:
            vm.read_more(0.2)
            if vm.proc.poll() is not None:
                rc = vm.proc.returncode
                break
    finally:
        vm.close()

    if rc != 42:
        print(f"exit protocol: forwarded {rc} (want 42): WRONG")
        raise SystemExit(1)
    print("exit protocol: forwarded 42: OK")

    # ── No layer from the false-positive capture ────────────────────
    # The line-initial fixed marker streamed through (checked above);
    # a capture would have written a layer to that path at shutdown.
    if os.path.exists(false_layer):
        os.unlink(false_layer)
        print("false-positive capture: a layer was written: WRONG")
        raise SystemExit(1)
    print("false-positive capture: no layer written: OK")


if __name__ == "__main__":
    sys.exit(test_main(__name__, main))
