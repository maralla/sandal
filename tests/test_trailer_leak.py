#!/usr/bin/env python3
"""Regression test: the exit-status trailer NEVER leaks to the terminal.

The command execution line carries the command's exit status back to the
VMM as a 17-byte trailer appended to the command's own output stream
(16 magic bytes + the status byte). The guest sends the magic and the
status byte as TWO SEPARATE packets, and the VMM's exchange rounds split
at the guest's own packet boundaries — so the trailer arrives across
rounds, in parts.

A per-round "deliver everything that does not match" scan LEAKED the
parts (the regression this test pins): `sandal -- uname -a` printed the
whole 16-byte magic — `VSOCKD:EXIT:01` — to the terminal, and the
leftover `\\n\\0` left the terminal mangled (a bogus indented last line),
before the status round finally exited the process. The scan is now a
WITHHOLDING scan: every round withholds the longest suffix that could be
the trailer's start (a prefix of the magic) and delivers the rest, so a
real trailer never leaks one byte — the command's own output flows
verbatim, and the exit fires on the completed trailer with the command's
own status.

This test drives the SESSION line (front end 1: `sandal -- <command>`),
not the --port endpoint: the leak was measured on the session's own pty
path. For each command it asserts, end to end:

  1. the terminal received EXACTLY the command's own output — not one
     byte more (no magic, no partial magic, no mangled trailing bytes);
  2. the process exited with the command's own status (0 and 7).

Usage (from the repo root, after `make`):
    uv run python tests/test_trailer_leak.py
"""

import os
import pathlib
import select
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The 16-byte trailer magic (src/vm/session.rs: TRAILER_MAGIC). The test
# checks the magic never appears in the terminal output — in whole OR in
# any part that the withholding should have suppressed.
MAGIC = b"VSOCKD:EXIT:01"

# One command's round-trip deadline: boot + the command + the exit.
DEADLINE = 120.0


def run_session(command: list[str]) -> tuple[bytes, int | None]:
    """Boot `sandal -- <command>` on a pty; return (output, exit code).

    Captures EVERY byte the terminal received, up to and past the
    process exit — the leak was measured as trailing garbage after the
    command's own output, so the capture must not stop at the exit.
    """
    vm = Vm(command=command)
    try:
        deadline = time.time() + DEADLINE
        while time.time() < deadline:
            vm.read_more(0.2)
            if vm.proc.poll() is not None:
                # Drain the tail: the last round may still be in flight.
                while True:
                    ready, _, _ = select.select([vm.master], [], [], 1.0)
                    if not ready:
                        break
                    if not vm.read_more(0.2):
                        break
                break
        return vm.buf, vm.proc.poll()
    finally:
        vm.close()


def check(command: list[str], want_output: bytes, want_status: int) -> None:
    out, status = run_session(command)
    # 1. The output: EXACTLY the command's own bytes. Not one byte more
    #    — a leaked magic (whole or partial) or any mangled trailing
    #    byte shows up here (the regression printed the whole magic).
    if out != want_output:
        extra = out[len(want_output):] if out.startswith(want_output) else out
        raise AssertionError(
            f"{command!r}: the terminal received {len(out)} bytes "
            f"(want {len(want_output)}); the command's own output "
            f"{'prefixes it; extra tail: ' if out.startswith(want_output) else ''}"
            f"{extra[:120]!r}"
        )
    # Belt and suspenders: the magic never appears anywhere — whole or in
    # any fragment the withholding should have suppressed.
    for fragment in (MAGIC, MAGIC[:8], MAGIC[:4], MAGIC[-4:]):
        if fragment in out:
            raise AssertionError(
                f"{command!r}: the trailer magic leaked: {fragment!r} in the output"
            )
    # 2. The exit: the command's own status, forwarded unchanged.
    if status != want_status:
        raise AssertionError(
            f"{command!r}: exit {status} (want {want_status})"
        )
    print(f"trailer-leak: {command!r}: exact output + exit {want_status}: OK")


def check_terminal_restore() -> None:
    """The host terminal's termios must survive the session's exit path.

    The session runs on the host tty with OPOST disabled (the guest pty
    already formed the output) and the input side in raw mode (every
    keystroke must reach the guest verbatim) — and its exit path is
    `process::exit`, which never runs the Drop that restored the
    originals. The user's own shell then inherited the mangled terminal
    (MEASURED: fish's own `time` report printed as a staircase — each
    line shifted right by the previous one, ending in a bare CR — and
    the input side was echo-less). The exit-path restore must return
    the terminal to EXACTLY its pre-session state.
    """
    import fcntl
    import struct
    import termios

    vm = Vm(command=["echo", "TERM_RESTORE_PROBE"])
    try:
        # The pair's shared termios, BEFORE: the pre-mangling state the
        # exit-path handler must restore to.
        before = termios.tcgetattr(vm.master)
        deadline = time.time() + DEADLINE
        while time.time() < deadline:
            vm.read_more(0.2)
            if vm.proc.poll() is not None:
                while True:
                    ready, _, _ = select.select([vm.master], [], [], 1.0)
                    if not ready:
                        break
                    if not vm.read_more(0.2):
                        break
                break
        if vm.proc.poll() != 0:
            raise AssertionError(
                f"the session did not exit with its own status: {vm.proc.poll()}"
            )
        after = termios.tcgetattr(vm.master)
    finally:
        vm.close()
    if after != before:
        raise AssertionError(
            "the host terminal's termios did not survive the exit path: "
            f"before {before!r}, after {after!r}"
        )
    # Belt and suspenders: the two manglings this regression measured —
    # OPOST off (the staircase) and ECHO off (the dead input side).
    if not (after[1] & termios.OPOST):
        raise AssertionError("OPOST off after the exit: the staircase")
    if not (after[3] & termios.ECHO):
        raise AssertionError("ECHO off after the exit: the dead input side")
    print("trailer-leak: the host terminal survives the exit path: OK")


def check_no_output_exit() -> None:
    """A NO-OUTPUT command must still exit — with its own status.

    The trailer is the command's exit-status carrier, and a no-output
    command (`ls` of an empty home — the default directory) leaves it
    the ONLY traffic on the line. The reaper used to exit(0) the moment
    it had written the trailer — leaving the guest idle: the vCPU
    stopped exiting, the kernel's send worker never ran, the trailer
    never posted, and the VMM hung forever (MEASURED: unloaded the race
    was won in ~0.25 s and the process exited; under load — or with -v,
    the deterministic slowdown — it hung past every bound). The reaper
    now naps forever, keeping the vCPU's timer wakeups (and the kernel
    workqueues) flowing until the host's own exit kills the VM — so the
    chain completes and the command's own status forwards. The -v flag
    is the load-independent repro: pre-fix it hung permanently.
    """
    import fcntl
    import struct
    import subprocess
    import termios

    # The PARALLEL load: the race's reliable repro. A single run wins or
    # loses the race on its own timing (MEASURED: a single -v run hung
    # pre-fix one session and exited the next); CONCURRENT runs stack the
    # machine's load until the loser hangs past every bound (MEASURED:
    # pre-fix, the accumulated load of repeated runs hung the VMM
    # forever; post-fix, 8 concurrent runs all complete in under half a
    # second).
    sandal = str(pathlib.Path("target/release/sandal"))
    procs = []
    masters = []
    try:
        for _ in range(8):
            master, slave = os.openpty()
            fcntl.ioctl(
                slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0)
            )
            proc = subprocess.Popen(
                [sandal, "-v", "--", "ls"],
                stdin=slave, stdout=slave, stderr=slave, close_fds=True,
            )
            os.close(slave)
            masters.append(master)
            procs.append(proc)
        t0 = time.time()
        deadline = t0 + 90
        pending = set(range(len(procs)))
        codes: dict[int, int | None] = {}
        while pending and time.time() < deadline:
            for i in sorted(pending):
                if i not in pending:
                    continue
                ready, _, _ = select.select([masters[i]], [], [], 0.05)
                if ready:
                    try:
                        if not os.read(masters[i], 65536):
                            continue
                    except OSError:
                        pass
                if procs[i].poll() is not None:
                    codes[i] = procs[i].poll()
                    pending.discard(i)
        for i in pending:
            codes[i] = None
    finally:
        for m in masters:
            try:
                os.close(m)
            except OSError:
                pass
        for p in procs:
            if p.poll() is None:
                p.terminate()
                p.wait()
    hung = [i for i, c in codes.items() if c is None]
    if hung:
        raise AssertionError(
            f"the no-output command hung under the parallel load: runs {hung}"
        )
    bad = {i: c for i, c in codes.items() if c != 0}
    if bad:
        raise AssertionError(f"the no-output command exited wrong: {bad}")
    print("trailer-leak: 8 concurrent no-output runs all exit (status 0): OK")


def main() -> None:
    # The original reproduction was `sandal -- uname -a` (a real
    # system command, exit 0): the whole 16-byte magic printed to the
    # terminal before the status round exited the process. The command
    # is arbitrary on this path — the contract is the same for any
    # command — so the cases here use outputs that are exactly
    # deterministic (a real uname string embeds the kernel build date
    # and changes with every kernel re-fetch).

    # Exit 0: the command's own output verbatim, nothing else, exit 0.
    check(["echo", "LEAK_PROBE_OK"], b"LEAK_PROBE_OK\r\n", 0)

    # A failing command (exit 7): the same contract on the failure path —
    # the magic withheld, the status forwarded. (The quotes ride inside
    # the argument: the command line is joined with spaces on its way to
    # the guest, and a bare `sh -c '...'` loses them at the join — the
    # guest's shell would fragment the line and run nothing.)
    check(
        ["sh", "-c", "'echo MARKER_OK; exit 7'"],
        b"MARKER_OK\r\n",
        7,
    )

    # The exit path's own terminal state: the atexit restore.
    check_terminal_restore()

    # The no-output command: the trailer-only chain must complete.
    check_no_output_exit()

    print("trailer-leak: the trailer never leaks, the status forwards: OK")


if __name__ == "__main__":
    sys.exit(test_main("trailer-leak", main))
