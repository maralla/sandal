#!/usr/bin/env python3
"""The vsock relay channel, end to end, through a real VM.

The relay mode (--vsock-relay-sock): every connection the VMM bridges
lands on the guest's own TCP loopback — the guest's /bin/vsockrelay (a
crafted x86_64 guest helper, pure machine code — see
src/initramfs/tools/x86_64/vsockrelay.rs) forwards it, and sshd would
answer there. The guest carries no openssh, and a python stand-in's
startup pegs the single emulated vCPU for minutes and blocks the whole
guest — so the endpoint is a crafted helper too: /bin/vsockecho
(src/initramfs/tools/x86_64/vsockecho.rs), a pure echo, up in
milliseconds. No layer, no python3, nothing to install: the whole test
is the channel.

  1. The refusal (no endpoint running): the connection is accepted
     (the vsockrelay's listener works), its connect to :22 fails, and it
     closes the guest side — into the strand: the guest kernel's
     close-time SHUTDOWN/RST packets land in the guest's send queue and
     never propagate (the documented limitation, see src/vm/linux.rs) —
     so the client NEVER sees an EOF and the test never waits for one.
     What the test does instead — and verifies — is the working
     direction: the client closes, the bridge reads the EOF, the VMM
     RSTs the guest socket, the RST is DELIVERED, and the guest side of
     the connection is dead — while the vsockrelay's own accept loop
     (a persistent daemon, by design) survives for the next connection.
  2. The measurement, in two phases of ONE WINDOW EACH — the relay
     channel's honest shape (see the bounds block): window-paced (the
     guest's 256 KiB per-socket budget per credit round-trip) over a
     multi-hop event chain whose every round-trip costs tens of
     seconds. The sizes are the channel's own envelope, not a wish:
       - phase A: ONE 256 KiB echo round-trip — the honest
         per-round-trip yield (the echo forces both directions per
         byte; nothing generates);
       - phase B: 16 × 1 KiB exchanges — the per-exchange latency of
         the completion-driven chain — and a 64-byte quick echo that
         must complete with them.
     Every phase must COME BACK with the right bytes inside its
     deadline: completion is the assertion. A wedge reads as a
     timeout, and the measured per-round-trip yield and per-exchange
     latency are the report.
  3. The teardown: the legs' connections closed, their pump children
     auto-reaped — and the machinery must have survived: only the two
     accept loops remain, and a fresh connection still gets its echo.

Usage (from the repo root, after `make`):
    uv run python tests/test_vsockrelay.py
"""

import os
import pathlib
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The listener port the test names in --ssh-port: PID-offset to dodge
# collisions between concurrent suite runs (a fixed port would serialize
# them, and a collision fails the bind loudly, not silently).
PORT = 20000 + os.getpid() % 20000

# The endpoint's port: /bin/vsockecho's own (the vsockrelay forwards to
# it; the device's REQUESTs carry the vsock side — see
# src/virtio/vsock.rs's RELAY_VSOCK_PORT).
ENDPOINT_PORT = 22

# The measurement bounds — completion-based, not rate floors: the relay
# channel's honest shape is WINDOW-PACED (the guest's per-socket budget,
# 256 KiB per credit round-trip) over a multi-hop event chain (VMM
# bridge round → guest send worker → echo child → back), and each
# round-trip costs tens of seconds end to end (measured: the probe's
# full round-trip landed inside its 30 s window; a 2 MiB leg — eight
# round-trips — never finished inside 300 s). So each phase measures
# ONE window's worth, and the assertion is that it COMPLETES with the
# right bytes inside the deadline — the measured per-round-trip yield
# and per-exchange latency are the report, not a rate floor.
THROUGHPUT_BYTES = 256 * 1024          # ONE window round-trip: 4 skbs
RT_BYTES = 1024                        # 1 KiB per exchange
RT_COUNT = 16                          # 16 exchanges: 16 skbs
QUICK_BYTES = 64                       # the not-starved probe: 1 skb
MEASURE_DEADLINE = 600.0               # one window per phase, tens of s
PROBE_DEADLINE = 60.0                  # the endpoint's startup


def connect(timeout: float = 60.0) -> socket.socket:
    """Connect to the VMM's SSH-mode listener (the port the test named
    in --ssh-port — no port file, nothing to discover)."""
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
        except OSError as error:  # the listener is not up yet
            last = error
            time.sleep(0.2)
    raise AssertionError(f"the SSH listener never came up: {last}")


def probe_refusal_accepted(timeout: float) -> bool:
    """A fresh connection is ACCEPTED by the vsockrelay's loop (its
    connect then fails and it closes the guest side — the strand). The
    connect succeeding IS the acceptance: the loop answered. Never wait
    for an echo or an EOF — both are the stranded direction."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            client = connect(timeout=10.0)
            client.close()  # accepted: the loop answered
            return True
        except (OSError, AssertionError):
            time.sleep(0.5)
    return False


def probe_endpoint(timeout: float = PROBE_DEADLINE) -> bool:
    """Probe until /bin/vsockecho answers: one byte in, the same byte
    back. A probe before it is up gets the refusal's fast close — the
    vsockrelay's paced retry — so the probe just retries; the endpoint
    is up in milliseconds, not minutes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        client = connect()
        try:
            client.sendall(b"P")
            client.settimeout(2.0)
            echo = b""
            while len(echo) < 1:
                chunk = client.recv(1 - len(echo))
                if not chunk:
                    break
                echo += chunk
            if echo == b"P":
                client.close()
                return True
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
        time.sleep(0.5)
    return False


def main() -> None:
    vm = Vm(["--ssh-port", str(PORT)])
    try:
        vm.boot("vsockrelay")

        # ── Part 1: the refusal (no endpoint running) ───────────────
        # /bin/vsockecho is not started yet: the vsockrelay's connect to
        # 127.0.0.1:22 fails ECONNREFUSED and it closes the guest side —
        # into the strand (the guest's close packets never propagate;
        # see the module docstring). NEVER wait for the client's EOF: it
        # is the stranded direction. Close the client, and verify the
        # working direction instead: the RST lands, the guest side of
        # THIS connection is dead, and the vsockrelay's accept loop
        # survives for the next connection.
        client = connect(60.0)
        client.sendall(b"refused-probe")  # into the dead socket's queue
        client.close()  # the EOF: the bridge's mark_host_closed → RST

        # The guest side of the refused connection: dead (the RST
        # delivered), the accept loop alive — a fresh connection gets
        # accepted again (the refusal, not a wedge).
        if not probe_refusal_accepted(30.0):
            raise AssertionError("the vsockrelay's accept loop died")
        print(
            "vsockrelay refusal (no endpoint): the guest side dead, "
            "the accept loop alive: OK"
        )

        # ── The endpoint: /bin/vsockecho, up in milliseconds ─────────
        vm.run(
            f"/bin/vsockecho {ENDPOINT_PORT} & echo START""_DONE",
            "START_DONE",
        )
        if not probe_endpoint():
            raise AssertionError("the echo endpoint never answered")
        print("vsockrelay endpoint: /bin/vsockecho answering", flush=True)

        # ── Part 2: the concurrent measurement legs ──────────────────
        # Four connections at once — the many-clients shape. Every byte
        # goes through the full chain and comes back: the round-trip rate
        # IS the channel's bidirectional throughput, and the quick leg
        # must not starve behind the bulk legs.
        import threading

        results = {}
        failures = []

        def leg(name, fn):
            t = time.monotonic()
            try:
                results[name] = (time.monotonic() - t, fn())
            except BaseException as error:  # noqa: BLE001
                failures.append(f"{name}: {error!r}")

        def throughput_leg(tag: str):
            """One 4 MiB echo leg: the ramp through the chain and back,
            every byte verified."""
            client = connect()
            client.settimeout(MEASURE_DEADLINE)
            ramp = bytes(range(256))
            sent = 0
            echoed = 0
            verified = True
            try:
                while sent < THROUGHPUT_PER_LEG:
                    block = (ramp * 4096)[: min(
                        256 * 1024, THROUGHPUT_PER_LEG - sent
                    )]
                    client.sendall(block)
                    sent += len(block)
                    # Drain the echo: verify it against what was sent.
                    while echoed < sent:
                        want = min(256 * 1024, sent - echoed)
                        chunk = client.recv(want)
                        if not chunk:
                            raise AssertionError("throughput leg: EOF mid-echo")
                        expect = (ramp * 4096)[: len(chunk)]
                        if chunk != expect:
                            verified = False
                        echoed += len(chunk)
            finally:
                client.close()
            if not verified:
                raise AssertionError(f"throughput leg {tag}: wrong bytes")
            return echoed

        def roundtrip_leg():
            """64 × 1 KiB exchanges: the per-round-trip latency."""
            client = connect()
            client.settimeout(MEASURE_DEADLINE)
            payload = bytes(range(256)) * 4
            for i in range(RT_COUNT):
                client.sendall(payload)
                echo = b""
                while len(echo) < RT_BYTES:
                    chunk = client.recv(RT_BYTES - len(echo))
                    if not chunk:
                        raise AssertionError(f"round-trip {i}: EOF")
                    echo += chunk
                if echo != payload:
                    raise AssertionError(f"round-trip {i}: wrong bytes")
            client.close()
            return RT_COUNT

        def quick_leg():
            """A 64-byte echo in the concurrent mix — not starved."""
            client = connect()
            client.settimeout(60.0)
            payload = b"Q" * QUICK_BYTES
            client.sendall(payload)
            echo = b""
            while len(echo) < QUICK_BYTES:
                chunk = client.recv(QUICK_BYTES - len(echo))
                if not chunk:
                    raise AssertionError("quick leg: EOF")
                echo += chunk
            client.close()
            if echo != payload:
                raise AssertionError("quick leg: wrong bytes")
            return QUICK_BYTES

        # ── Phase A: ONE 256 KiB echo round-trip ────────────────────
        # The window's worth: the honest per-round-trip yield. The echo
        # forces both directions per byte (nothing generates); the
        # verification is byte-for-byte against the ramp.
        t_phase_a = time.monotonic()

        def throughput_leg():
            """ONE 256 KiB echo round-trip: the ramp through the chain
            and back, every byte verified."""
            client = connect()
            client.settimeout(MEASURE_DEADLINE)
            ramp = bytes(range(256))
            sent = 0
            echoed = 0
            verified = True
            try:
                while sent < THROUGHPUT_BYTES:
                    block = (ramp * 4096)[: min(
                        256 * 1024, THROUGHPUT_BYTES - sent
                    )]
                    client.sendall(block)
                    sent += len(block)
                    while echoed < sent:
                        want = min(256 * 1024, sent - echoed)
                        chunk = client.recv(want)
                        if not chunk:
                            raise AssertionError("phase A: EOF mid-echo")
                        # The CUMULATIVE stream: the expected bytes are
                        # the ramp's slice at [echoed..echoed+len) —
                        # comparing every chunk against the ramp's head
                        # fails the second chunk (the first verifier
                        # bug: phase A completed and the verifier
                        # rejected its own echo).
                        start = echoed % 256
                        block = ramp[start:] + ramp[:start]
                        expect = (block * ((len(chunk) + 255) // 256))[
                            : len(chunk)
                        ]
                        if chunk != expect:
                            verified = False
                        echoed += len(chunk)
            finally:
                client.close()
            if not verified:
                raise AssertionError("phase A: wrong bytes")
            return echoed

        leg("throughput", throughput_leg)
        if failures:
            raise AssertionError(f"phase A failed: {failures}")
        if "throughput" not in results:
            raise AssertionError("phase A incomplete: no result")
        tp_elapsed, tp_bytes = results["throughput"]
        phase_a_total = time.monotonic() - t_phase_a
        print(
            f"vsockrelay phase A (one {THROUGHPUT_BYTES} B round-trip): "
            f"{tp_bytes} B verified in {phase_a_total:.1f}s "
            f"({tp_bytes / phase_a_total / 1e3:.1f} KB/s): OK"
        )

        # ── Phase B: the latency legs (concurrent) ──────────────────
        # 16 × 1 KiB exchanges + a 64-byte quick echo: the
        # per-exchange latency of the completion-driven chain, and the
        # quick echo must complete with them (not starve).
        t_phase_b = time.monotonic()
        threads = [
            threading.Thread(target=leg, args=("roundtrip", roundtrip_leg)),
            threading.Thread(target=leg, args=("quick", quick_leg)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=MEASURE_DEADLINE)
        if failures:
            raise AssertionError(f"phase B failed: {failures}")
        if set(results) != {"throughput", "roundtrip", "quick"}:
            raise AssertionError(
                f"phase B incomplete: {sorted(results)}"
            )
        rt_elapsed, rt_count = results["roundtrip"]
        quick_elapsed, _ = results["quick"]
        phase_b_total = time.monotonic() - t_phase_b
        if rt_count != RT_COUNT:
            raise AssertionError(
                f"phase B: {rt_count}/{RT_COUNT} exchanges completed"
            )
        print(
            f"vsockrelay phase B (2 concurrent legs): "
            f"{rt_count} × {RT_BYTES} B exchanges in {rt_elapsed:.1f}s "
            f"({rt_elapsed / rt_count * 1000:.0f} ms each), "
            f"quick {QUICK_BYTES} B in {quick_elapsed:.1f}s, "
            f"total {phase_b_total:.1f}s: OK"
        )

        # ── Part 3: the teardown ────────────────────────────────────
        # The legs' clients closed (the RST path: the guest side of
        # every leg died); their pump children must be auto-reaped —
        # only the two accept loops remain — and the machinery must
        # have survived: a fresh connection still gets its echo.
        # The teardown: the children's exit is event-driven (the RST's
        # delivery → the guest's chain → the child's poll → the close
        # exit), so they leave over seconds, not instantly — a bounded
        # wait, then the counting. The counting itself: only lines that
        # ARE process lines (a leading PID) — the echoed command line
        # contains the names and is not a process.
        import re as _re

        def ps_processes() -> list[str]:
            ps = vm.run(
                "ps aux | grep -a -e vsockrelay -e vsockecho"
                " | grep -v grep; echo PS""_DONE",
                "PS_DONE",
                timeout=30.0,
            )
            return [
                line for line in ps.splitlines()
                if _re.match(r"\s*\d+\s+root\s", line)
            ]

        deadline = time.monotonic() + 60.0
        lines = ps_processes()
        while time.monotonic() < deadline:
            parents = sum(
                1 for line in lines if " 22 " in line or line.rstrip().endswith("22")
            )
            # The accept loops: "vsockrelay 22 22" / "vsockecho 22"
            # (two argv words vs one); anything else is a child.
            relay_loop = sum(1 for line in lines if "vsockrelay 22 22" in line)
            echo_loop = sum(1 for line in lines if "vsockecho 22" in line
                            and "vsockrelay" not in line)
            children = len(lines) - relay_loop - echo_loop
            if children == 0 and relay_loop >= 1 and echo_loop >= 1:
                break
            time.sleep(5.0)
            lines = ps_processes()
        relay_loop = sum(1 for line in lines if "vsockrelay 22 22" in line)
        echo_loop = sum(1 for line in lines if "vsockecho 22" in line
                        and "vsockrelay" not in line)
        children = len(lines) - relay_loop - echo_loop
        if children != 0 or relay_loop < 1 or echo_loop < 1:
            raise AssertionError(
                f"the teardown failed: {children} children left, "
                f"{relay_loop}/{echo_loop} accept loops: {lines!r}"
            )
        if not probe_endpoint(timeout=30.0):
            raise AssertionError("the machinery died with the legs")
        print(
            "vsockrelay teardown: the children exited (event-driven, "
            "auto-reaped), the accept loops alive, "
            "a fresh connection still echoes: OK"
        )
    except BaseException:
        # The diagnostic tail: without it every failure is a blind guess.
        try:
            vm.run(
                "ps aux | grep -a -e vsockrelay -e vsockecho"
                " | grep -v grep; echo POST""_MORTEM_DONE",
                "POST_MORTEM_DONE",
                timeout=15.0,
            )
        except Exception:
            pass
        raise
    finally:
        vm.close()



if __name__ == "__main__":
    sys.exit(test_main("vsockrelay", main))
