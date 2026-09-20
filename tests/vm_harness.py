#!/usr/bin/env python3
"""Shared pty harness for the sandal integration tests.

Boots `target/release/sandal` on a pty and provides helpers to send guest
shell commands and wait for their output.  Requires the codesigned release
binary (`make`) and macOS/HVF.
"""

import fcntl
import os
import pathlib
import select
import struct
import subprocess
import sys
import termios
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SANDAL = REPO_ROOT / "target" / "release" / "sandal"
PROMPTS = (b"~ #", b"/ #")
BOOT_TIMEOUT = 90.0
CMD_TIMEOUT = 30.0


class Vm:
    """A sandal VM spawned on its own pty."""

    def __init__(self, extra_args=(), verbose_env="SANDAL_TEST_VERBOSE"):
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        self.master = master
        self.verbose_env = verbose_env
        self.proc = subprocess.Popen(
            [str(SANDAL), *extra_args, "--", "sh"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)
        self.buf = b""

    def read_more(self, timeout: float) -> bool:
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            data = os.read(self.master, 65536)
        except OSError:
            return False
        if not data:
            return False
        self.buf += data
        if os.environ.get(self.verbose_env):
            sys.stderr.write(data.decode("utf-8", "replace"))
        return True

    def wait_for(self, needle: bytes, count: int, timeout: float) -> bool:
        """Wait until `needle` appeared at least `count` times.

        Commands are echoed by the guest, so requiring two occurrences
        (echo + output) distinguishes the command from its result.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.buf.count(needle) >= count:
                return True
            self.read_more(0.2)
        return self.buf.count(needle) >= count

    def wait_for_any(self, needles, timeout: float) -> bool:
        """Wait until any of `needles` has appeared at least once."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(n in self.buf for n in needles):
                return True
            self.read_more(0.2)
        return any(n in self.buf for n in needles)

    def send_line(self, line: str) -> None:
        os.write(self.master, line.encode() + b"\r")

    def run(
        self,
        command: str,
        marker: str,
        timeout: float = CMD_TIMEOUT,
        count: int = 2,
    ) -> str:
        """Send one shell command; return output up to `marker`.

        `count` is the number of marker occurrences to wait for: 2 for a
        marker printed by the command (echo + result), 1 for output-only
        markers that are not part of the echoed command line.
        """
        origin = len(self.buf)
        self.send_line(command)
        if not self.wait_for(marker.encode(), count, timeout):
            raise AssertionError(f"command did not finish: {command!r}")
        return self.buf[origin:].decode("utf-8", "replace")

    def boot(self, label: str = "boot") -> None:
        if not self.wait_for_any(PROMPTS, BOOT_TIMEOUT):
            raise AssertionError(f"{label}: shell prompt did not appear")
        # Give the shell a moment to settle at the prompt.
        time.sleep(0.5)

    def close(self) -> None:
        try:
            self.proc.terminate()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            os.close(self.master)
        except OSError:
            pass


def test_main(name: str, fn) -> int:
    """Run a test body, printing `test_<name>: PASS`/`FAIL`."""
    if not SANDAL.is_file():
        print(f"error: {SANDAL} not found; run `make` first", file=sys.stderr)
        return 2
    try:
        fn()
    except AssertionError as e:
        print(f"test_{name}: FAIL: {e}", file=sys.stderr)
        return 1
    print(f"test_{name}: PASS")
    return 0
