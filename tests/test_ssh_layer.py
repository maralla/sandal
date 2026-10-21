#!/usr/bin/env python3
"""The ssh server layer, end to end, through a real VM.

The layer (ssh-server.layer — built once through sandal's own export
path: a build VM installs openssh from the guest's own repositories,
generates the one ed25519 host key, and `sandal-export` writes the
overlay upper as the layer) carries the MACHINERY: openssh's binaries,
ONE ed25519 host key, /var/empty, and sshd-setup — the ONE per-boot
line, which takes the authorized key as its argument. The identity is
deliberately not baked: every boot names its own key.

  1. The machinery check: everything the layer should carry is there —
     sshd, sshd-session, ssh-keygen, the host key, /var/empty,
     sshd-setup — with NO apk anywhere (the install is in the layer,
     not the network).
  2. The STABLE HOST KEY — the layer's whole point: the guest's host
     key is byte-identical to the one shipped in the layer file (the
     host-side fingerprint of the layer's own key member, via
     tests/layer_ref.py). A per-boot keygen would diverge; a stable
     key means known_hosts stops churning.
  3. The ONE line: /usr/sbin/sshd-setup '<the test's public key>' —
     then a real ssh client through the VMM's --ssh-port listener:
     the handshake + identity + guest file access, exit-code
     propagation, CONCURRENT sessions, a 32 MiB bulk transfer, and
     the teardown (the children exit; the accept loops survive).

Usage (from the repo root, after `make`, with ssh-server.layer in
the repo root):
    uv run python tests/test_ssh_layer.py
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from layer_ref import decompress_layer  # noqa: E402
from vm_harness import Vm, test_main  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
LAYER = REPO / "ssh-server.layer"

# The listener port the test names in --ssh-port (PID-offset; see
# test_vsockrelay.py for the reasoning).
PORT = 20000 + os.getpid() % 20000

BULK_BYTES = 32 * 1024 * 1024
BULK_DEADLINE = 600.0
HANDSHAKE_DEADLINE = 300.0


def ssh_base(port: int, key: str) -> list:
    return [
        "ssh",
        "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentityFile=" + key,
        "-o", "IdentitiesOnly=yes",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=60",
        "root@127.0.0.1",
    ]


def ssh_run(port: int, key: str, command: str, timeout: float) -> tuple[bytes, int]:
    proc = subprocess.run(
        ssh_base(port, key) + [command],
        capture_output=True,
        timeout=timeout,
    )
    return proc.stdout, proc.returncode


def layer_hostkey_fingerprint() -> str:
    """The fingerprint of the host key shipped IN the layer file —
    computed host-side from the layer's own tar member. The guest's key
    must be byte-identical to this one: that is the layer's whole point
    (a stable host key), and a per-boot keygen would diverge."""
    import tarfile
    import io

    tar = decompress_layer(LAYER)
    with tarfile.open(fileobj=io.BytesIO(tar)) as tf:
        member = tf.extractfile("etc/ssh/ssh_host_ed25519_key.pub")
        if member is None:
            raise AssertionError("the layer ships no host key")
        pub = tempfile.NamedTemporaryFile(
            suffix=".pub", delete=False
        )
        pub.write(member.read())
        pub.close()
    try:
        out = subprocess.run(
            ["ssh-keygen", "-lf", pub.name],
            capture_output=True, check=True,
        ).stdout.decode()
        # "<bits> SHA256:<base64> ... (ED25519)" — the fingerprint line.
        return out.strip()
    finally:
        os.unlink(pub.name)


def main() -> None:
    if not LAYER.is_file():
        print(
            f"test_ssh_layer: SKIP: no {LAYER} "
            "(build it: a build VM, apk add openssh, one ed25519"
            " host key, sshd-setup, then sandal-export)"
        )
        return
    key = tempfile.mkdtemp(prefix="sandal-sshlayer-") + "/id_ed25519"
    vm = Vm([
        "--layer", str(LAYER),
        "--ssh-port", str(PORT),
        "--disk-size", "64",  # room for the 32 MiB bulk leg
    ])
    try:
        vm.boot("ssh-layer")
        print("ssh-layer: booted on the layer + --ssh-port", flush=True)

        # ── Part 1: the machinery, no apk anywhere ───────────────────
        out = vm.run(
            "ls -l /usr/sbin/sshd /usr/lib/ssh/sshd-session"
            " /usr/bin/ssh-keygen /usr/sbin/sshd-setup"
            " /etc/ssh/ssh_host_ed25519_key /var/empty /run"
            " 2>&1; echo MACH""_DONE",
            "MACH_DONE", timeout=30.0,
        )
        for piece in (
            "/usr/sbin/sshd",
            "sshd-session",
            "/usr/bin/ssh-keygen",
            "/usr/sbin/sshd-setup",
            "ssh_host_ed25519_key",
            "/var/empty",
            "/run",
        ):
            if piece not in out:
                raise AssertionError(
                    f"the layer is missing {piece}: {out[-500:]!r}"
                )
        print(
            "ssh-layer machinery: sshd + sshd-session + ssh-keygen"
            " + the host key + /var/empty + sshd-setup: OK",
            flush=True,
        )

        # ── Part 2: the STABLE host key ──────────────────────────────
        # The guest's key must be byte-identical to the layer's own key
        # member — the layer's whole point. A per-boot keygen diverges;
        # this key never changes under known_hosts.
        want = layer_hostkey_fingerprint()
        out = vm.run(
            "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
            "; echo FP""_DONE",
            "FP_DONE", timeout=30.0,
        )
        guest_fp = next(
            (line for line in out.splitlines() if "SHA256:" in line), ""
        )
        if guest_fp != want:
            raise AssertionError(
                f"the host key diverged from the layer's:"
                f"\\n  layer: {want!r}\\n  guest: {guest_fp!r}"
            )
        print(
            "ssh-layer host key: stable — the guest's key is the"
            " layer's own (known_hosts stops churning): OK",
            flush=True,
        )

        # ── Part 3: the ONE line, then the full ssh suite ────────────
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-q"],
            check=True, capture_output=True,
        )
        pub = pathlib.Path(key + ".pub").read_text().strip()
        out = vm.run(
            f"/usr/sbin/sshd-setup '{pub}' 2>&1; echo SETUP""_DONE",
            "SETUP_DONE", timeout=60.0,
        )
        if "SETUP_DONE" not in out or "error" in out.lower():
            raise AssertionError(f"sshd-setup failed: {out[-500:]!r}")
        print("ssh-layer: the ONE line ran; sshd is up", flush=True)

        # ── Part 2b: sshd's pid file — the fix for the boot log's
        # `Couldn't create pid file "/run/sshd.pid"`. The layer ships
        # /run (the same place /var/empty ships); the pid file then
        # exists, matches the live listener, the complaint is gone from
        # sshd's own log, and the STANDARD restart path —
        # kill $(cat /run/sshd.pid) — round-trips (the path that was
        # dead, leaving only pkill -f, whose -x form loses to comm
        # truncation).
        pid_file = vm.run(
            "cat /run/sshd.pid; echo PID""_DONE", "PID_DONE", timeout=15.0
        )
        pid = next(
            (line.strip() for line in pid_file.splitlines()
             if line.strip().isdigit()),
            "",
        )
        listener = vm.run(
            "pgrep -f 'sshd.*listener' | head -1; echo LIST""_DONE",
            "LIST_DONE", timeout=15.0,
        )
        listener_pid = next(
            (line.strip() for line in listener.splitlines()
             if line.strip().isdigit()),
            "",
        )
        if not pid or pid != listener_pid:
            raise AssertionError(
                f"the pid file is wrong: file={pid!r} listener={listener_pid!r}"
            )
        log = vm.run(
            "cat /var/log/sshd.log; echo LOG""_DONE", "LOG_DONE", timeout=15.0
        )
        if "Couldn't create pid file" in log:
            raise AssertionError(
                f"the pid file complaint is still in sshd's log: {log[-400:]!r}"
            )
        print(
            "ssh-layer pid file: /run/sshd.pid matches the listener,"
            " the complaint gone: OK",
            flush=True,
        )
        # The STANDARD restart round-trip: kill by the pid file, the
        # listener dies, sshd restarts and BINDS (no "Address in use"),
        # and the pid file carries the new listener.
        vm.run(
            "kill $(cat /run/sshd.pid); sleep 1;"
            " /usr/sbin/sshd -E /var/log/sshd.log;"
            " echo RESTART""_DONE",
            "RESTART_DONE", timeout=30.0,
        )
        listener2 = vm.run(
            "pgrep -f 'sshd.*listener' | head -1; echo LIST2""_DONE",
            "LIST2_DONE", timeout=15.0,
        )
        listener2_pid = next(
            (line.strip() for line in listener2.splitlines()
             if line.strip().isdigit()),
            "",
        )
        pid2_file = vm.run(
            "cat /run/sshd.pid; echo PID2""_DONE", "PID2_DONE", timeout=15.0
        )
        pid2 = next(
            (line.strip() for line in pid2_file.splitlines()
             if line.strip().isdigit()),
            "",
        )
        log2 = vm.run(
            "cat /var/log/sshd.log; echo LOG2""_DONE", "LOG2_DONE", timeout=15.0
        )
        if (
            not listener2_pid
            or listener2_pid == listener_pid
            or pid2 != listener2_pid
            or "Couldn't create pid file" in log2
            or "Address in use" in log2
        ):
            raise AssertionError(
                f"the standard restart round-trip failed: "
                f"old={listener_pid!r} new={listener2_pid!r} "
                f"pidfile={pid2!r}: {log2[-400:]!r}"
            )
        print(
            "ssh-layer restart: kill $(cat /run/sshd.pid) → the fresh"
            " listener binds, the pid file tracks it: OK",
            flush=True,
        )


        # The handshake + identity + guest file access.
        t0 = time.monotonic()
        out, code = ssh_run(
            PORT, key, "id -u; uname -m; head -1 /etc/passwd",
            HANDSHAKE_DEADLINE,
        )
        handshake = time.monotonic() - t0
        if code != 0:
            raise AssertionError(
                f"the ssh session failed ({code}): {out[-400:]!r}"
            )
        if b"0" not in out.split() or b"root:" not in out:
            raise AssertionError(f"wrong session output: {out[-400:]!r}")
        print(
            f"ssh-layer session: the handshake + identity + guest file"
            f" access in {handshake:.1f}s: OK",
            flush=True,
        )
        out, code = ssh_run(PORT, key, "sh -c 'exit 7'",
                           HANDSHAKE_DEADLINE)
        if code != 7:
            raise AssertionError(f"wrong exit code: {code}")
        print("ssh-layer exit codes: 7 in, 7 out: OK", flush=True)

        # Concurrent sessions.
        import threading

        results = {}

        def concurrent(i):
            t = time.monotonic()
            out, code = ssh_run(
                PORT, key, f"echo concurrent-{i}-ok", HANDSHAKE_DEADLINE,
            )
            results[i] = (time.monotonic() - t, out, code)

        threads = [
            threading.Thread(target=concurrent, args=(i,)) for i in (1, 2)
        ]
        t0 = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=HANDSHAKE_DEADLINE + 60.0)
        if set(results) != {1, 2}:
            raise AssertionError(
                f"concurrent sessions incomplete: {sorted(results)}"
            )
        for i, (elapsed, out, code) in results.items():
            if code != 0 or f"concurrent-{i}-ok".encode() not in out:
                raise AssertionError(
                    f"concurrent session {i}: {code}, {out[-200:]!r}"
                )
        print(
            f"ssh-layer concurrent: 2 sessions in "
            f"{time.monotonic() - t0:.1f}s: OK",
            flush=True,
        )

        # The bulk transfer: 32 MiB host → guest (a byte-granular
        # reader on the guest side — a block-reader stalls the chain;
        # see test_ssh_relay.py for the measured both-ways).
        mb = BULK_BYTES // (1024 * 1024)
        remote = (
            f"sh -c 'cat > /tmp/bulk.bin; wc -c < /tmp/bulk.bin'"
        )
        t0 = time.monotonic()
        ssh_proc = subprocess.Popen(
            ssh_base(PORT, key) + [remote],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        dd = subprocess.Popen(
            ["dd", "if=/dev/zero", "bs=1M", f"count={mb}"],
            stdout=ssh_proc.stdin,
            stderr=subprocess.DEVNULL,
        )
        dd.wait(timeout=BULK_DEADLINE)
        ssh_proc.stdin.close()
        out = ssh_proc.stdout.read()
        ssh_proc.wait(timeout=BULK_DEADLINE)
        bulk_elapsed = time.monotonic() - t0
        count = int(out.strip() or b"0")
        if count != BULK_BYTES:
            raise AssertionError(
                f"the bulk transfer delivered {count}/{BULK_BYTES} bytes"
            )
        print(
            f"ssh-layer bulk: {count} B host → guest in "
            f"{bulk_elapsed:.1f}s ({count / bulk_elapsed / 1e6:.2f} MB/s)"
            ": OK",
            flush=True,
        )

        # The teardown: the clients closed; the per-connection sshd and
        # pump children exit; the accept loops survive.
        time.sleep(5.0)
        out = vm.run(
            "ps aux | grep -a -e vsockrelay -e sshd"
            " | grep -v grep; echo PS""_DONE",
            "PS_DONE", timeout=30.0,
        )
        import re as _re

        procs = [
            line for line in out.splitlines()
            if _re.match(r"\s*\d+\s+root\s", line)
        ]
        relay_loop = sum(
            1 for line in procs if "vsockrelay 22 22" in line
        )
        sshd_loop = sum(
            1 for line in procs if "sshd: /" in line
        )
        children = len(procs) - relay_loop - sshd_loop
        if children != 0 or relay_loop < 1 or sshd_loop < 1:
            raise AssertionError(
                f"the teardown failed: {children} children, "
                f"{relay_loop}/{sshd_loop} accept loops: {procs!r}"
            )
        print(
            "ssh-layer teardown: the children exited, the accept loops"
            " alive: OK",
            flush=True,
        )
    finally:
        vm.close()
        import shutil

        shutil.rmtree(pathlib.Path(key).parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(test_main("ssh_layer", main))
