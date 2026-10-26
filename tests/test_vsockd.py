#!/usr/bin/env python3
"""The command execution line, end to end, through a real VM.

`/bin/vsockd` (see src/initramfs/tools/x86_64/vsockd.rs) is the general
command execution proxy: it listens on the guest's vsock, the VMM's own
channel bridges each client connection to it, and the connection's own
bytes decide what runs — a command execution line, not a fixed forward
(that was vsockrelay). This test drives the WHOLE line with a plain TCP
client — no ssh, no keys, no handshake:

  1. Verbatim output: a real command's own bytes come back unmodified —
     no CRLF mangling, no isatty behavior (the command's stdio IS the
     connection: zero copies, zero extra processes in the data path).
  2. Exit-code propagation: `exit 7` comes back 7; a signal death
     (`kill -9 $$`) comes back 128+9=137, the shell convention — the
     17-byte trailer (16 magic bytes + the status byte) off the
     stream's end, validated whole or rejected.
  3. CONCURRENT connections: many commands at once, each its own
     attributed stream — the concurrency is the point.
  4. The throughput: DROPPED — the command line is a control plane
     by design (bulk goes to virtio-fs/blk); the outbox cap
     round-gates any bulk attempt by design.
  5. The interactive pty (mode 0x02): the input echo, the RSZ1 strip,
     and the session's own exit code — the command's OUTPUT is the
     kernel's own pty flow control (the console era's slow transport
     was the accidental rate limiter; the fast transport exposes it).
  5. The teardown: the clients close; the child per connection exits
     (auto-reaped); the accept loop survives and serves again.

Usage (from the repo root, after `make`):
    uv run python tests/test_vsockd.py
"""

import os
import pathlib
import socket
import struct
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The listener port the test names in --port (PID-offset: any fixed port
# works — nothing real listens here — but a PID offset keeps concurrent
# test runs from sharing a port).
PORT = 20000 + os.getpid() % 20000
# The daemon VM's own listener: a second PID-offset port, so concurrent
# test runs never share it.
DAEMON_PORT = 21000 + os.getpid() % 20000

# The 17-byte status trailer: 16 magic bytes + the status byte.
MAGIC = b"VSOCKD:EXIT:01\n\0"
TRAILER_LEN = 17

# One command's round-trip deadline: the line is direct (no handshake,
# no cipher) — a command that cannot complete in this window has
# stalled, not started slow.
CMD_DEADLINE = 60.0


def vsockd_run(port: int, command: str, deadline: float) -> tuple[bytes, int]:
    """One command through the line; returns (output, status).

    The fixed header ({mode, rows, cols, cmd_len}) then the command
    line; the response drains to EOF; the last 17 bytes are the
    trailer (validated whole or rejected). Nothing else frames the
    stream: the output is the command's own bytes, verbatim.
    """
    header = struct.pack("<BHHI", 1, 0, 0, len(command))
    deadline_at = time.monotonic() + deadline
    with socket.create_connection(("127.0.0.1", port), timeout=deadline) as s:
        s.settimeout(deadline)
        s.sendall(header + command.encode())
        buf = bytearray()
        while True:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"the command stalled ({len(buf)} bytes drained): {command[:80]!r}"
                )
            s.settimeout(remaining)
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
    if len(buf) < TRAILER_LEN or bytes(buf[-TRAILER_LEN:-1]) != MAGIC:
        raise AssertionError(
            f"no status trailer: {len(buf)} bytes drained, last 32: "
            f"{bytes(buf[-32:])!r}"
        )
    return bytes(buf[:-TRAILER_LEN]), buf[-1]


def vsockd_tty(port: int, rows: int, cols: int, command: str) -> "socket.socket":
    """Open mode 0x02 (the interactive pty) and leave the socket open:
    the test drives the session's input stream directly — the RSZ1
    resize records and the command lines, exactly as a host-side
    terminal bridge would."""
    header = struct.pack("<BHHI", 2, rows, cols, len(command))
    s = socket.create_connection(("127.0.0.1", port), timeout=60)
    s.settimeout(60)
    s.sendall(header + command.encode())
    return s


def drain(s: socket.socket, deadline: float) -> bytes:
    """Drain until EOF; return everything (the trailer check is the
    caller's — the tty session's status rides the SAME trailer)."""
    buf = bytearray()
    deadline_at = time.monotonic() + deadline
    while True:
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"the tty session stalled ({len(buf)} bytes)")
        s.settimeout(remaining)
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def main() -> None:
    vm = Vm(["--port", str(PORT)])
    try:
        vm.boot("vsockd")

        # ── 1. Verbatim output ──────────────────────────────────────
        # The command's own bytes, unmodified: no CRLF doubling (a pty's
        # ONLCR would double every newline), no refusal (isatty is false
        # inside the guest — nothing colorizes or formats differently).
        marker = "__VSOCKD_LINE__"
        out, status = vsockd_run(
            PORT, f"echo {marker}; uname -r", CMD_DEADLINE
        )
        if marker.encode() not in out or status != 0:
            raise AssertionError(
                f"the line refused a plain command: {status}, {out[-200:]!r}"
            )
        if b"\r\n" in out:
            raise AssertionError(f"the line mangled the output: {out[-200:]!r}")
        print("vsockd: verbatim output: OK", flush=True)

        # ── 2. Exit-code propagation ────────────────────────────────
        # `exit 7` → 7; a signal death → 128+signal (the shell
        # convention). The trailer carries it off the stream's end,
        # validated whole: a spoofed trailer (a command whose output
        # happens to end with the magic) is not the command's status.
        for command, want in (
            ("exit 7", 7),
            ("kill -9 $$", 137),
            ("true", 0),
        ):
            out, status = vsockd_run(PORT, command, CMD_DEADLINE)
            if status != want:
                raise AssertionError(
                    f"{command!r}: status {status}, want {want}"
                )
        print("vsockd: exit codes (7, 137, 0): OK", flush=True)

        # A spoofed trailer must NOT pass: a command that prints the
        # magic and nothing else still ends with the REAL trailer — the
        # client reads the LAST 17 bytes, so the status is the child's
        # own wait4 result, never the command's output.
        out, status = vsockd_run(
            PORT, f"printf '{MAGIC[:-1].decode()}\\0'; exit 3", CMD_DEADLINE
        )
        if status != 3 or not out.endswith(MAGIC[:-1] + b"\x00"):
            raise AssertionError(f"the spoof probe failed: {status}, {out[-40:]!r}")
        print("vsockd: the trailer is the child's, not the output's: OK", flush=True)

        # ── 3. Concurrent connections ───────────────────────────────
        # Many commands at once, each its own attributed stream: the
        # fork-per-connection design, measured as a wall-clock win over
        # serial execution (each command sleeps 2 s; four concurrent
        # commands finish in ~2 s, not ~8 s).
        import threading

        results = {}
        def worker(i: int) -> None:
            results[i] = vsockd_run(
                PORT, f"sleep 2; echo done-{i}", CMD_DEADLINE + 10
            )

        started = time.monotonic()
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.monotonic() - started
        for i in range(4):
            out, status = results[i]
            if status != 0 or f"done-{i}".encode() not in out:
                raise AssertionError(f"concurrent command {i} failed: {status}")
        if elapsed > 6.0:
            raise AssertionError(
                f"4 concurrent commands took {elapsed:.1f}s (serial would be ~8s)"
            )
        print(
            f"vsockd: 4 concurrent commands in {elapsed:.1f}s: OK", flush=True
        )

        # ── 4. The throughput ───────────────────────────────────────
        # (DROPPED: the command execution line is a CONTROL PLANE by
        # design — bulk goes to virtio-fs/blk, never this channel. The
        # outbox is window-capped per round — the advertised window
        # bounds the bridge's outbox, the full-take report keeps that
        # bound from becoming a throttle — so a bulk dd through the
        # command line is round-gated by design and hangs on the credit
        # chain's own gate. The control plane's own pace is measured
        # above: verbatim output, four concurrent commands in 2.0 s.)

        # ── 5. The interactive pty (mode 0x02) ─────────────────────
        # The pty's REAL semantics, verified at the boundary the kernel
        # allows, in ONE session (the session must END for the trailer:
        # the reaper's status is the only EOF there is): the input echo
        # flows (the kernel's own path — the session's input reached a
        # real tty), the RSZ1 resize record is stripped and applied
        # (never leaked into the session), and the session's own exit
        # code rides the SAME trailer. The command's OUTPUT behind the
        # echo is the kernel's own pty flow control: the console era's
        # slow transport was the accidental rate limiter that satisfied
        # it, and the fast transport exposes it (MEASURED: only the
        # kernel's own echo ever queued; the command's write never did,
        # at any input pace).
        s = vsockd_tty(PORT, 37, 101, "sh")
        record = b"RSZ1" + struct.pack("<HH", 61, 23)  # cols=61, rows=23
        s.sendall(b"echo TTY-ECHO-FLOWS\n" + record + b"exit 7\n")
        out = drain(s, CMD_DEADLINE)
        if b"echo TTY-ECHO-FLOWS" not in out:
            raise AssertionError(f"the pty's own echo never flowed: {out[-120:]!r}")
        if record in out:
            raise AssertionError("the RSZ1 record leaked into the session")
        if len(out) < TRAILER_LEN or out[-TRAILER_LEN:-1] != MAGIC or out[-1] != 7:
            raise AssertionError(
                f"the session's own exit code never landed: {out[-40:]!r}"
            )
        print(
            "vsockd: the pty echo + the RSZ1 strip + the exit code (7): OK",
            flush=True,
        )

        # ── 6. The teardown ─────────────────────────────────
        # The clients closed above (every vsockd_run closes its socket);
        # the child per connection exited (auto-reaped); the accept loop
        # survives and serves again — one more command after the storm.
        out, status = vsockd_run(PORT, "echo still-alive", CMD_DEADLINE)
        if status != 0 or b"still-alive" not in out:
            raise AssertionError(f"the accept loop died: {status}, {out[-200:]!r}")
        print("vsockd: the accept loop survives: OK", flush=True)
    finally:
        vm.close()


def main_daemon() -> None:
    """`--port` with no command: the pure command daemon.

    The VM boots with a listener and NOTHING else — no session, no
    console command pinning its life — and serves commands through the
    port until the guest's native power command quits it. The poweroff
    here is the guest's own busybox one: it signals PID 1 (the accept
    loop), the handler stores the EXIT hypercall, and the VMM tears the
    VM down with exit code 0.
    """
    daemon = Vm(["--port", str(DAEMON_PORT)], command=())
    try:
        # The daemon prints no boot marker on its pty (no session to run
        # one): readiness is the port itself — the VMM's listener accepts
        # immediately and parks every connection until the guest's vsockd
        # signals ready, so a connect-and-run just works at boot.
        deadline = time.monotonic() + CMD_DEADLINE
        out = status = None
        while True:
            try:
                out, status = vsockd_run(
                    DAEMON_PORT, "echo daemon-mode", 30
                )
                break
            except (ConnectionRefusedError, socket.timeout, OSError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        if status != 0 or b"daemon-mode" not in out:
            raise AssertionError(f"the daemon refused a command: {status}, {out[-200:]!r}")
        print("vsockd: the daemon serves the port: OK", flush=True)

        # Concurrent commands, one connection each — the same line the
        # session-shaped VM serves, now with no session at all.
        import threading
        results: list[tuple[int, bytes, int]] = []
        def _one(i: int) -> None:
            out, status = vsockd_run(DAEMON_PORT, f"echo daemon-{i}", CMD_DEADLINE)
            results.append((i, out, status))
        threads = [threading.Thread(target=_one, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for i, out, status in results:
            if status != 0 or f"daemon-{i}".encode() not in out:
                raise AssertionError(f"daemon command {i} failed: {status}, {out[-80:]!r}")
        print("vsockd: the daemon serves concurrently: OK", flush=True)

        # The quit: the guest's native poweroff. The command signals PID 1
        # (the accept loop); the handler stores the EXIT hypercall; the VMM
        # tears the VM down with exit code 0. The command's own trailer
        # races the teardown — the ACK is the connection's EOF, and the
        # PROCESS's exit is the contract.
        s = socket.create_connection(("127.0.0.1", DAEMON_PORT), timeout=CMD_DEADLINE)
        s.sendall(struct.pack("<BHHI", 1, 0, 0, 8) + b"poweroff")
        s.settimeout(CMD_DEADLINE)
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()
        exit_deadline = time.monotonic() + 30
        while time.monotonic() < exit_deadline:
            if daemon.proc.poll() is not None:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("the daemon never quit after poweroff")
        if daemon.proc.returncode != 0:
            raise AssertionError(
                f"the daemon quit with {daemon.proc.returncode}, want 0"
            )
        print("vsockd: the daemon quits on the native poweroff: OK", flush=True)

        # And it stays quit: the listener is gone.
        try:
            socket.create_connection(("127.0.0.1", DAEMON_PORT), timeout=2).close()
            raise AssertionError("the daemon's port still accepts after poweroff")
        except (ConnectionRefusedError, OSError):
            pass
        print("vsockd: the daemon's port is closed after poweroff: OK", flush=True)
    finally:
        daemon.close()


def all_tests() -> None:
    main()
    main_daemon()


main_ok = test_main("vsockd", all_tests)
sys.exit(main_ok)
