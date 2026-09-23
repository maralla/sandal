#!/usr/bin/env python3
"""Diagnostic test: the ATTACHED tmux client on the guest console hangs.

Known issue (x86_64, kernel 6.12.70, tmux 3.5a). The detached-server path
works (see test_tmux.py); the attached client (`tmux new -s x` in the
foreground of the console) hangs forever with no output:

  * tmux sends its terminal capability queries (DA1/DA2/XTVERSION/OSC10/11)
    and queues the first draw (~155 bytes) in its evbuffer, then waits for
    the libevent EV_WRITE event on the console fd.
  * The event never fires: `n_tty_poll()` only reports EPOLLOUT when
    `!tty_is_writelocked() && chars_in_buffer() < 256 && write_room() > 0`.
  * Guest-kernel instrumentation (pr_err in hvc_write/put_chars) shows the
    console TX path is healthy in isolation: `virtqueue_add_outbuf` never
    fails (`num_free` stays 128), and every `put_chars` round-trips —
    except two that never return (start count > done count in dmesg),
    i.e. a `put_chars` spin (`while (!virtqueue_get_buf()) cpu_relax()`)
    wedges waiting for a used-ring completion, holding the tty writer lock
    and gating EPOLLOUT off for the attached client.
  * Meanwhile the VMM trace (`SANDAL_TRACE_CONSOLE_IO=1`) shows the TX
    queue frozen: `TX_SKIP reason=no_new_heads last_avail=N avail_idx=N`
    repeating — the driver never submits the next head.

This test reproduces the hang and dumps the evidence (tmux server log via
`tmux -v`, /proc interrupt counts, dmesg) so the failure is observable:

    SANDAL_TRACE_CONSOLE_IO=1 SANDAL_TRACE_FILE=/tmp/trace.log \
        uv run python tests/test_tmux_attached.py

Next steps for a fix: the wedge is in the interlock between the VMM's
used-ring completion (`VirtioConsoleDevice::process_tx`) and the guest's
`virtqueue_get_buf` consumption inside `__send_to_port`'s spin. Compare
`write_used_idx`'s value against the guest's `vq->last_used_idx` at the
wedge (add a guest kernel print of both in `virtqueue_get_buf`) — the
completion for the wedged head is either never written or already
consumed by a concurrent `get_buf` (net-kicker drain racing the main
loop's drain).

Usage (from the repo root, after `make`):
    uv run python tests/test_tmux_attached.py
"""

import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# Background probe: while the attached client is wedged, dump the guest
# state that characterizes the failure (IRQ delivery, the tmux server's
# own debug log, kernel-side write-path prints).
WATCHDOG = r"""
sleep 8
echo REP1
dmesg | grep "VADD vq=output" | tail -8
echo REP2
dmesg | grep "VGET vq=output" | tail -8
echo REP3
dmesg | grep -E "SNDP|GETBUF BAD|not a head" | tail -4
echo REPEND
echo "=== TASKS ==="
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  C=$(cat /proc/$p/comm 2>/dev/null)
  case "$C" in *tmux*|*sh*|*base64*)
    echo "pid=$p comm=$C wchan=$(cat /proc/$p/wchan 2>/dev/null) stat=$(awk '{print $3}' /proc/$p/stat 2>/dev/null)"
    ;;
  esac
done
echo "=== CLIENT STACK ==="
CP=$(pgrep -f 'tmux new' | head -1)
echo "client pid=$CP"
cat /proc/$CP/stack 2>/dev/null | head -12
echo "=== SERVER STACK ==="
SP=$(ls /tmp/tmux-*/$(id -u) 2>/dev/null | head -1)
for p in $(ls /proc | grep -E '^[0-9]+$'); do
  grep -q tmux /proc/$p/cmdline 2>/dev/null && grep -q server /proc/$p/cmdline 2>/dev/null && SP=$p
  grep -aq tmux /proc/$p/comm 2>/dev/null && ! grep -qa 'tmux new' /proc/$p/cmdline 2>/dev/null && SP=$p
done
echo "server pid=$SP"
cat /proc/$SP/stack 2>/dev/null | head -12
echo "=== IRQ SAMPLE 1 ==="
grep -iE "virtio|console" /proc/interrupts
sleep 3
echo "=== IRQ SAMPLE 2 ==="
grep -iE "virtio|console" /proc/interrupts
L=$(ls /root/tmux-server-*.log 2>/dev/null | head -1)
echo "=== SERVER LOG: write path ==="
echo -n "redraw deferred count: "; grep -c "redraw deferred" $L 2>/dev/null
grep -nE "wrote [0-9]+ bytes|waiting for redraw|can't keep up" $L 2>/dev/null | head -5
echo "=== SERVER LOG: first 25 ==="
head -25 $L 2>/dev/null | cut -c1-110
echo "=== SERVER LOG: tty lines ==="
grep -E "tty|EAGAIN|write" $L 2>/dev/null | head -15
echo "=== CLIENT FDS ==="
ls -l /proc/90/fd 2>/dev/null
echo "=== SERVER FDS ==="
ls -l /proc/83/fd 2>/dev/null | head -12
echo M3
"""


def main() -> None:
    # Mirror the guest's serial-port writes to stderr: the report channel
    # that bypasses the (possibly wedged) guest tty stack. Trace the console
    # virtqueue traffic to a file (TX_SKIP/RAMLOG diagnostics).
    os.environ["SANDAL_VERBOSE_UART"] = "1"
    os.environ["SANDAL_TRACE_CONSOLE_IO"] = "1"
    os.environ["SANDAL_TRACE_FILE"] = "/tmp/sandal-tmux-trace.log"
    if os.path.exists("/tmp/sandal-tmux-trace.log"):
        os.unlink("/tmp/sandal-tmux-trace.log")
    vm = Vm(["--disk-size", "512"])
    try:
        vm.boot("tmux-attached")

        def run(cmd: str, marker: str, timeout: float = 240) -> str:
            vm.buf = b""
            vm.send_line(cmd)
            if not vm.wait_for(marker.encode(), 1, timeout):
                raise AssertionError(
                    f"command did not finish: {cmd!r}: "
                    f"{vm.buf.decode('utf-8', 'replace')[-400:]!r}"
                )
            time.sleep(0.8)
            vm.read_more(0.8)
            return vm.buf.decode("utf-8", "replace").split("\n", 1)[-1]

        out = run("apk add --no-cache tmux 2>&1 | tail -1; echo M0", "M0")
        if "OK:" not in out:
            raise AssertionError(f"apk add tmux failed: {out!r}")

        # Control: the detached-server path (the test_tmux.py coverage).
        out = run(
            "cd /root; tmux -v new-session -d -s reg 'sleep 300' 2>&1 | tail -2; "
            "tmux ls; echo M1",
            "M1",
        )
        if "reg:" not in out:
            raise AssertionError(f"detached tmux session did not start: {out!r}")
        print("detached server path: OK")

        # The failing case: the attached client. Arm the watchdog probe in
        # the background, then start the attached client in the foreground.
        import base64

        wd_b64 = base64.b64encode(WATCHDOG.encode()).decode()
        vm.send_line(f"echo {wd_b64} | base64 -d > /tmp/wd.sh; sh /tmp/wd.sh &")
        time.sleep(1.5)
        vm.read_more(1.0)

        vm.buf = b""
        vm.send_line("cd /root; tmux new -s atest")
        saw_ui = None
        deadline = time.time() + 30
        while time.time() < deadline:
            vm.read_more(0.2)
            if b"M3" in vm.buf:  # watchdog finished; client never drew
                break
            # Only output rendered AFTER the attach counts: the outer
            # shell's own prompt (~ #) appears in the echo of the command,
            # so it must not match. The tmux UI draws the window list and
            # then the pane's fresh prompt below the status line.
            if b"[atest]" in vm.buf and b"0:sh" in vm.buf:
                saw_ui = "status line + window list"
                break

        out = vm.buf.decode("utf-8", "replace")
        print("--- serial report (vring/hvc state) ---")
        for line in out.splitlines():
            if (
                "VADD" in line
                or "VGET" in line
                or "SNDP" in line
                or "vring: add" in line
                or "hvc: write" in line
                or "put_chars" in line
                or "not a head" in line
            ):
                print(line)
        print("--- markers ---")
        print("REP markers:", [m for m in ("REP1", "REP2", "REPEND") if m in out])
        j = out.find("REPEND")
        k = out.find("M3", j + 1)
        print("--- watchdog console report ---")
        print(out[j:k + 2] if j >= 0 else "(console output blocked)")
        if saw_ui:
            print("ATTACHED CLIENT PROCEEDED — the hang is fixed!")
        else:
            raise AssertionError(
                "attached tmux client hung (known issue, see module docstring); "
                "evidence above"
            )
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("tmux_attached", main))
