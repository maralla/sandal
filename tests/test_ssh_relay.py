#!/usr/bin/env python3
"""Real ssh through the vsock relay channel, end to end, through a real VM.

The relay mode's whole point (see tests/test_vsockrelay.py for the
channel's own measurement): ssh clients connect to the VMM's listener,
the channel bridges them to the guest's vsock, /bin/vsockrelay forwards
to the guest's TCP loopback — and here a REAL sshd answers. The guest
carries no openssh, but it is an Alpine minirootfs with apk behind the
NAT netstack (the package suites prove that path), so the test installs
openssh in the guest, wires key-only root auth, and drives a real
openssh client on the host through the full chain:

  1. The install: apk update + apk add openssh (the guest's own
     repositories, over the netstack); one ed25519 host key (fast to
     generate on the emulated vCPU); the privilege-separation user and
     directory the package's openrc post-install would have made.
  2. The session: a real ssh client (StrictHostKeyChecking off, the
     test's own ed25519 identity) through the VMM's listener port:
       - the handshake + an identity command — the measured latency;
       - exit-code propagation: sh -c 'exit 7' comes back 7;
       - guest file access: head /etc/passwd through the channel;
       - CONCURRENT sessions: two shells at once, each its own
         attributed stream.
  3. The bulk transfer: 32 MiB host → guest over the ssh channel
     (dd | ssh 'cat > /dev/null') — measured against the channel's
     known window-paced envelope (~2.4 MB/s; the transport, not the
     cipher, is the ceiling). Completion-based: it must finish with the
     right byte count inside the deadline.
  4. The teardown: the clients close; the per-connection sshd and pump
     children exit; the two accept loops (vsockrelay's, sshd's) survive.

Usage (from the repo root, after `make`):
    uv run python tests/test_ssh_relay.py
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402

# The listener port the test names in --ssh-port (PID-offset; see
# test_vsockrelay.py for the reasoning).
PORT = 20000 + os.getpid() % 20000

# The bulk transfer: 32 MiB over the ssh channel. The channel's honest
# ceiling is the window pace (~2.4 MB/s measured in test_vsockrelay);
# 32 MiB ≈ 15 s at that rate, and the deadline bounds a stall.
BULK_BYTES = 32 * 1024 * 1024
BULK_DEADLINE = 600.0
HANDSHAKE_DEADLINE = 300.0
INSTALL_DEADLINE = 900.0


def listener_port() -> int:
    """The port the test named in --ssh-port — it IS the port."""
    return PORT


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


def ssh_run(port: int, key: str, command: str, timeout: float,
            stdin: bytes | None = None) -> tuple[bytes, int]:
    """One ssh command; returns (stdout, exit). The exit code is ssh's
    own protocol: the remote command's status, propagated honestly."""
    proc = subprocess.run(
        ssh_base(port, key) + [command],
        input=stdin,
        capture_output=True,
        timeout=timeout,
    )
    return proc.stdout, proc.returncode


def main() -> None:
    vm = Vm(["--ssh-port", str(PORT), "--disk-size", "64"])
    key = tempfile.mkdtemp(prefix="sandal-ssh-") + "/id_ed25519"
    try:
        vm.boot("ssh-relay")
        port = listener_port()

        # ── Part 1: the install ─────────────────────────────────────
        # The guest's own repositories over the netstack; then the host
        # key (ed25519 only — fast to generate on the emulated vCPU),
        # the privilege-separation user + directory the package's openrc
        # post-install would have made, and the test's public key.
        out = vm.run(
            "apk update 2>&1 | tail -1; echo APKU""_DONE",
            "APKU_DONE", timeout=INSTALL_DEADLINE,
        )
        if "OK:" not in out:
            raise AssertionError(f"apk update failed: {out[-400:]!r}")
        out = vm.run(
            "apk add --no-cache openssh-server openssh-keygen"
            " 2>&1 | tail -2; echo APKI""_DONE",
            "APKI_DONE", timeout=INSTALL_DEADLINE,
        )
        if not any(
            mark in out for mark in ("OK:", "installed", "share")
        ) or "ERROR" in out or "error" in out:
            raise AssertionError(f"apk add failed: {out[-600:]!r}")
        print("ssh-relay install: openssh in the guest: OK", flush=True)

        out = vm.run(
            "ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key"
            " -N '' -q && echo HOSTKEY""_DONE",
            "HOSTKEY_DONE", timeout=300.0,
        )
        if "HOSTKEY_DONE" not in out:
            raise AssertionError(f"the host key failed: {out[-400:]!r}")
        # The privilege-separation user + directory (openssh >= 9.8's
        # sshd-session needs both; the package's openrc post-install
        # would have made them).
        vm.run(
            "mkdir -p /var/empty /var/log /root/.ssh && chmod 700 /root/.ssh;"
            " echo 'sshd:x:74:74:sshd:/var/empty:/sbin/nologin'"
            " >> /etc/passwd;"
            " echo 'sshd:x:74:' >> /etc/group;"
            " echo PRIVSEP""_DONE",
            "PRIVSEP_DONE", timeout=30.0,
        )
        # The test's own keypair: generate FIRST, then inject the
        # public key. Key-only root auth (openssh's own defaults:
        # PermitRootLogin prohibit-password — passwords refused for
        # root either way).
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-q"],
            check=True, capture_output=True,
        )
        pub = pathlib.Path(key + ".pub").read_text().strip()
        vm.run(
            f"echo '{pub}' >> /root/.ssh/authorized_keys"
            " && chmod 600 /root/.ssh/authorized_keys"
            " && echo AUTH""_DONE",
            "AUTH_DONE", timeout=30.0,
        )
        # Start sshd (it daemonizes; the listener is the channel's
        # endpoint — vsockrelay forwards :22 to it).
        out = vm.run(
            "/usr/sbin/sshd -E /var/log/sshd.log 2>&1; echo SSHD""_DONE",
            "SSHD_DONE", timeout=60.0,
        )
        print("ssh-relay: sshd started", flush=True)

        # ── Part 2: the session ─────────────────────────────────────
        # A real ssh client through the full chain: the handshake, an
        # identity command, exit-code propagation, guest file access.
        t0 = time.monotonic()
        out, code = ssh_run(
            port, key, "id -u; uname -m; head -1 /etc/passwd",
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
            f"ssh-relay session: the handshake + identity + guest file"
            f" access in {handshake:.1f}s: OK",
            flush=True,
        )
        out, code = ssh_run(port, key, "sh -c 'exit 7'",
                            HANDSHAKE_DEADLINE)
        if code != 7:
            raise AssertionError(f"wrong exit code: {code}")
        print("ssh-relay exit codes: 7 in, 7 out: OK", flush=True)

        # ── Part 3: concurrent sessions ─────────────────────────────
        # Two shells at once, each its own attributed stream — the
        # many-clients shape the channel exists for.
        import threading

        results = {}

        def concurrent(i):
            t = time.monotonic()
            out, code = ssh_run(
                port, key, f"echo concurrent-{i}-ok", HANDSHAKE_DEADLINE,
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
            raise AssertionError(f"concurrent sessions incomplete: {sorted(results)}")
        for i, (elapsed, out, code) in results.items():
            if code != 0 or f"concurrent-{i}-ok".encode() not in out:
                raise AssertionError(
                    f"concurrent session {i}: {code}, {out[-200:]!r}"
                )
        print(
            f"ssh-relay concurrent: 2 sessions in "
            f"{time.monotonic() - t0:.1f}s "
            f"({results[1][0]:.1f}s / {results[2][0]:.1f}s): OK",
            flush=True,
        )

        # ── Part 4: the bulk transfer ───────────────────────────────
        # 32 MiB host → guest over the ssh channel: host dd pipes into
        # the ssh client's stdin, the guest dd writes it out and wc -c
        # counts what arrived. The transport's window pace (~2.4 MB/s)
        # is the ceiling; the cipher adds nothing. Completion-based.
        # The guest-side reader MUST be byte-granular (cat): a
        # block-reader (dd bs=1M) stalls the whole chain — it waits
        # for a full block before reading anything, so the consumption
        # reports that reopen the transport's window never fire, and
        # the transfer dies at the first window's worth (measured:
        # 2 MB of 32 MB, then a permanent stall).
        remote = (
            "sh -c 'cat > /tmp/bulk.bin;"
            " wc -c < /tmp/bulk.bin'"
        )
        t0 = time.monotonic()
        ssh_proc = subprocess.Popen(
            ssh_base(port, key) + [remote],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        mb = BULK_BYTES // (1024 * 1024)
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
            f"ssh-relay bulk: {count} B host → guest in "
            f"{bulk_elapsed:.1f}s ({count / bulk_elapsed / 1e6:.2f} MB/s)"
            ": OK",
            flush=True,
        )

        # ── Part 5: the teardown ────────────────────────────────────
        # The clients closed; the per-connection sshd and pump children
        # exit; the accept loops survive.
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
        relay_loop = sum(1 for line in procs if "vsockrelay 22 22" in line)
        sshd_loop = sum(
            1 for line in procs
            if "/usr/sbin/sshd" in line and "sshd:" not in line
        ) + sum(1 for line in procs if "sshd: /" in line)
        # sshd's listener shows as "sshd: /usr/sbin/sshd [listener]".
        children = len(procs) - relay_loop - sshd_loop
        if children != 0 or relay_loop < 1:
            raise AssertionError(
                f"the teardown failed: {children} children, "
                f"{relay_loop} relay loops: {procs!r}"
            )
        print(
            "ssh-relay teardown: the children exited, the accept loops"
            " alive: OK",
            flush=True,
        )
    finally:
        vm.close()

        import shutil
        shutil.rmtree(pathlib.Path(key).parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(test_main("ssh_relay", main))
