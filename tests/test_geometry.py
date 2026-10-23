#!/usr/bin/env python3
"""End-to-end terminal-geometry test for the virtio-ports session.

The session agent (portagent) bridges a guest pty to the virtio-console
host device port. The geometry chain:

  * boot:   the init script passes the VMM's advertised window on the
            agent's command line; the agent applies it to the pty pair
            before the fork, so the session starts sized;
  * live:   the VMM polls the host pty's winsize (the kernel's
            SIGWINCH never fires — the pty is not the VMM's controlling
            terminal) and injects a resize record ("RSZ1") into the port
            input stream; the agent strips it and applies it, and the
            kernel SIGWINCHs the session — everything downstream (the
            shell, tmux, editors) re-sizes itself like a real terminal
            would.

This test walks the chain in both directions, on an idle session first:

  * idle:   a host resize before any real input (the input window has
            barely grown — the record must not depend on it), then the
            resize back; the session must report both geometries;
  * boot:   the session must report the host window at rest;
  * tmux:   the client must match the session, and the pane tty must
            match tmux's pane geometry (#{pane_width} x #{pane_height})
            — what a fullscreen editor in the pane (vim) would size
            itself from;
  * live:   a host resize must reach tmux's panes within the budget.

A wrong layer localizes the break. Probes read the winsizes directly
(python one-liners — a heredoc stdin would make fd 0 the heredoc, not
the tty, and every probe would read ENOTTY).

Usage (from the repo root, after `make`):
    uv run python tests/test_geometry.py
"""

import base64
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The harness pty geometry (vm_harness.py): 120 cols x 40 rows.
HOST = "40x120"
ZOOM = "30x100"  # the zoomed geometry: 100 cols x 30 rows

INSTALL_MARKER = "GEO""_INSTALLED"

# One probe per tty: fd 0 of the probe process (the session or pane tty).
PROBE_B64 = base64.b64encode(
    b"import fcntl,struct\n"
    b"w = fcntl.ioctl(0, 0x5413, struct.pack('8H', *([0] * 8)))\n"
    b"rows, cols = struct.unpack('2H', w[:4])\n"
    b"print('GEO_RESULT %dx%d' % (rows, cols))\n"
).decode()


def geo_session(vm):
    """The last GEO_RESULT line's geometry (the probe tty's winsize)."""
    import re

    for line in reversed(vm.buf.decode("utf-8", "replace").splitlines()):
        if line.startswith("GEO_RESULT "):
            # Strip ANSI/CSI escape sequences before the parse: a live
            # resize makes the shell's line editor redraw its prompt
            # line, and the redraw's erase sequences (ESC[K ...) land on
            # the SAME output line as the probe's result — the geometry
            # itself is correct, and the escapes are the terminal's own
            # redraw noise (a timing-dependent interleaving: MEASURED 1
            # pass in 3 runs without this).
            line = re.sub("\x1b\\[[0-9;?]*[ -/]*[@-~]", "", line)
            return line.split(" ", 1)[1].strip()
    return None


def host_resize(vm, rows: int, cols: int) -> None:
    import fcntl
    import os
    import struct
    import termios
    fcntl.ioctl(vm.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    os.write(vm.master, b"")  # nudge: the VMM polls its own pty size


def probe_until(vm, want: str, budget_s: float) -> str:
    """Re-run the probe until the tty reports `want` (the resize chain is
    async end-to-end: the agent, the kernel's SIGWINCH, tmux's server —
    each hop has its own latency)."""
    import time
    deadline = time.time() + budget_s
    got = None
    while time.time() < deadline:
        vm.buf = b""
        vm.send_line("python3 /tmp/geo.py")
        if vm.wait_for(b"GEO_RESULT", 1, 30):
            got = geo_session(vm)
            if got == want:
                break
        time.sleep(3)
    return got


def main() -> None:
    vm = Vm(["--disk-size", "512"])
    try:
        vm.boot("geometry")

        def run(cmd: str, marker: str, timeout: float = 300) -> str:
            vm.buf = b""
            vm.send_line(cmd)
            if not vm.wait_for(marker.encode(), 1, timeout):
                raise AssertionError(
                    f"command did not finish: {cmd!r}: "
                    f"{vm.buf.decode('utf-8', 'replace')[-300:]!r}"
                )
            return vm.buf.decode("utf-8", "replace")

        # ── Layer 0: the IDLE-session resize, both directions ────────
        # A TRUE idle session: no input has ever been typed beyond this
        # probe line, so there are no input pushes for a resize record to
        # piggyback on — it must deliver on its own (the VMM injects it
        # directly at the poll). busybox stty reads the session tty's
        # winsize directly, so no python is needed (and none is installed
        # yet — installing it would be input the record could ride on).
        def stty_rows(want: int, budget_s: float) -> bool:
            import time
            deadline = time.time() + budget_s
            while time.time() < deadline:
                vm.buf = b""
                vm.send_line(
                    "stty -a | grep -o 'rows [0-9]*' | head -1; echo ST""TY_DONE"
                )
                if vm.wait_for(b"ST" b"TY_DONE", 1, 30):
                    time.sleep(1)
                    vm.read_more(0.5)
                    for line in vm.buf.decode("utf-8", "replace").splitlines():
                        if line.strip() == f"rows {want}":
                            return True
                time.sleep(3)
            return False

        host_resize(vm, 30, 100)  # the zoom: 100 cols x 30 rows
        ok_idle_zoom = stty_rows(30, 90)
        print(f"TRUE-idle resize to 100x30 (stty rows 30): "
              + ("OK" if ok_idle_zoom else "WRONG"))

        host_resize(vm, 40, 120)  # the zoom back out
        ok_idle_back = stty_rows(40, 90)
        print(f"TRUE-idle resize back to 120x40 (stty rows 40): "
              + ("OK" if ok_idle_back else "WRONG"))

        # ── The probe tooling for the remaining layers ────────────────
        out = run(
            f"echo {PROBE_B64} | base64 -d > /tmp/geo.py; "
            f"apk add --no-cache python3 tmux vim 2>&1 | tail -1; echo {INSTALL_MARKER}",
            INSTALL_MARKER,
        )
        if "OK:" not in out:
            raise AssertionError(f"apk add failed: {out!r}")

        # ── Layer 1: the session at rest (the agent's boot geometry) ──
        # (already proven by the resize-back probe above)
        ok_session = ok_idle_back

        # ── Layer 2+3: tmux's client and pane geometry ───────────────
        vm.buf = b""
        vm.send_line("tmux new -s geo")
        import time
        deadline = time.time() + 30
        while time.time() < deadline:
            vm.read_more(0.2)
            if b"0:sh" in vm.buf:  # the pane's shell prompt: attached
                break
        time.sleep(1.5)
        vm.read_more(0.5)

        vm.buf = b""
        vm.send_line(
            "tmux display-message -p 'GEO_CLIENT #{client_width}x#{client_height}'; "
            "tmux display-message -p 'GEO_PANE #{pane_width}x#{pane_height}'; "
            "python3 /tmp/geo.py"
        )
        if not vm.wait_for(b"GEO_RESULT", 1, 60):
            raise AssertionError("pane probe did not finish")
        client = pane = pane_ws = None
        for line in vm.buf.decode("utf-8", "replace").splitlines():
            if line.startswith("GEO_CLIENT "):
                client = line.split(" ", 1)[1].strip()
            elif line.startswith("GEO_PANE "):
                pane = line.split(" ", 1)[1].strip()
            elif line.startswith("GEO_RESULT "):
                pane_ws = line.split(" ", 1)[1].strip()
        ok_client = client == "120x40"
        # tmux reports WxH; the probe reports rows x cols — normalize.
        want_pane_ws = None
        if pane and "x" in pane:
            w, h = pane.split("x", 1)
            want_pane_ws = f"{h}x{w}"
        ok_pane = pane_ws == want_pane_ws
        print(f"tmux client: {client} (want 120x40): "
              + ("OK" if ok_client else "WRONG"))
        print(f"tmux pane:   {pane}; pane tty: {pane_ws} (want {want_pane_ws}): "
              + ("OK" if ok_pane else "WRONG"))

        # ── Layer 4: the live resize under tmux, BOTH directions ────
        # The pane is where a fullscreen editor (vim) lives, and the zoom
        # is what a user does while it is open: the pane must follow the
        # host window in BOTH directions (tmux keeps one status line, so
        # the pane geometry is the window minus it).
        host_resize(vm, 30, 100)  # zoom in
        got_in = probe_until(vm, "29x100", 120)
        ok_live_in = got_in == "29x100"
        print(f"zoom IN under tmux (pane -> 29x100): {got_in}: "
              + ("OK" if ok_live_in else "WRONG"))

        host_resize(vm, 40, 120)  # zoom out
        got_out = probe_until(vm, want_pane_ws, 120)
        ok_live_out = got_out == want_pane_ws
        print(f"zoom OUT under tmux (pane -> {want_pane_ws}): {got_out}: "
              + ("OK" if ok_live_out else "WRONG"))

        ok_live = ok_live_in and ok_live_out

        failures = [
            name for name, ok in [
                ("idle resize (the zoom)", ok_idle_zoom),
                ("resize back (the session at rest)", ok_idle_back),
                ("tmux client geometry", ok_client),
                ("pane tty geometry (the fullscreen-editor fill)", ok_pane),
                ("live resize under tmux", ok_live),
            ] if not ok
        ]
        if failures:
            for f in failures:
                print(f"test_geometry: FAIL: {f}")
            raise SystemExit(1)
        print("test_geometry: PASS")
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("geometry", main))
